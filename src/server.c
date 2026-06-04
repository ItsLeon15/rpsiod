#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "server.h"
#include "compress.h"
#include "http.h"
#include "http2.h"
#include "rate_limit.h"
#include "security.h"
#include "route.h"
#include "tls.h"
#include "static.h"
#include "php.h"
#include "perf.h"
#include "proxy.h"
#include "signals.h"
#include "util.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/openat2.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <pwd.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define RPSIOD_MAX_EVENTS 256
#define RPSIOD_CLIENT_BUFFER 32768
#define RPSIOD_MAX_LISTENERS 128
#define RPSIOD_SMALL_FILE_WRITEV_MAX 16384

typedef enum {
    OBJ_LISTENER = 1,
    OBJ_CLIENT = 2
} object_kind;

typedef struct {
    object_kind kind;
    int fd;
    char ip[64];
    uint16_t port;
    bool tls;
    SSL_CTX *tls_ctx;
} listener_object;

typedef struct client_object {
    object_kind kind;
    int fd;
    uint16_t local_port;
    bool tls;
    SSL *ssl;
    struct timespec request_started_mono;
    struct timespec request_started_real;
    uint64_t request_id;
    unsigned keep_alive_requests;
    bool sendfile_enabled;
    bool idle_keep_alive;
    char client_ip[INET6_ADDRSTRLEN];
    char server_ip[INET6_ADDRSTRLEN];
    char buf[RPSIOD_CLIENT_BUFFER];
    size_t used;
    struct timespec last_active_mono;
    struct timespec accepted_real;
    struct client_object *prev;
    struct client_object *next;
} client_object;

typedef struct {
    const rpsiod_site_config *site;
    const char *content_encoding;
    const char *location;
    const char *content_range;
    const char *retry_after;
    const char *etag;
    const struct stat *file_stat;
    bool cache_control;
    bool accept_ranges;
    bool vary_accept_encoding;
    bool suppress_default_cache_control;
    bool chunked_response;
} response_options;

static rpsiod_static_meta_cache_entry *static_meta_lookup(rpsiod_site_config *site, const char *relative_path, const struct stat *st) {
    for (size_t i = 0; i < RPSIOD_STATIC_META_CACHE; i++) {
        rpsiod_static_meta_cache_entry *entry = &site->static_meta_cache[i];
        if (!entry->valid || strcmp(entry->relative_path, relative_path) != 0) {
            continue;
        }
        if (entry->size == st->st_size &&
            entry->mtime == st->st_mtime &&
            entry->inode == (unsigned long long)st->st_ino) {
            rpsiod_perf_inc(&rpsiod_perf.cache_hits);
            return entry;
        }
        entry->valid = false;
        break;
    }
    rpsiod_perf_inc(&rpsiod_perf.cache_misses);
    return NULL;
}

static void static_meta_store_variant(rpsiod_site_config *site, rpsiod_static_meta_cache_entry *entry, const char *relative_path, const char *suffix) {
    char variant[PATH_MAX];
    if (snprintf(variant, sizeof(variant), "%s%s", relative_path, suffix) >= (int)sizeof(variant)) {
        return;
    }
    int fd = rpsiod_static_open_site_path(site, variant);
    if (fd < 0) {
        return;
    }
    struct stat vst;
    rpsiod_perf_inc(&rpsiod_perf.file_stat_calls);
    if (fstat(fd, &vst) == 0 && S_ISREG(vst.st_mode)) {
        if (strcmp(suffix, ".br") == 0) {
            entry->has_br = true;
            entry->br_size = vst.st_size;
            entry->br_mtime = vst.st_mtime;
            entry->br_inode = (unsigned long long)vst.st_ino;
        } else if (strcmp(suffix, ".gz") == 0) {
            entry->has_gzip = true;
            entry->gzip_size = vst.st_size;
            entry->gzip_mtime = vst.st_mtime;
            entry->gzip_inode = (unsigned long long)vst.st_ino;
        }
    }
    close(fd);
}

static rpsiod_static_meta_cache_entry *static_meta_store(rpsiod_site_config *site, const char *relative_path, int file_fd, const struct stat *st) {
    size_t idx = site->static_meta_clock++ % RPSIOD_STATIC_META_CACHE;
    rpsiod_static_meta_cache_entry *entry = &site->static_meta_cache[idx];
    memset(entry, 0, sizeof(*entry));
    entry->valid = true;
    rpsiod_safe_copy(entry->relative_path, sizeof(entry->relative_path), relative_path);
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", file_fd);
    ssize_t resolved = readlink(proc_path, entry->absolute_path, sizeof(entry->absolute_path) - 1);
    if (resolved >= 0) {
        entry->absolute_path[resolved] = '\0';
    } else {
        if (snprintf(entry->absolute_path, sizeof(entry->absolute_path), "%s/%s", site->static_root_real, relative_path) >=
            (int)sizeof(entry->absolute_path)) {
            entry->absolute_path[0] = '\0';
        }
    }
    rpsiod_safe_copy(entry->mime, sizeof(entry->mime), rpsiod_mime_type(relative_path));
    entry->size = st->st_size;
    entry->mtime = st->st_mtime;
    entry->inode = (unsigned long long)st->st_ino;
    entry->directory = S_ISDIR(st->st_mode);
    char request_path[PATH_MAX];
    if (snprintf(request_path, sizeof(request_path), "/%s", relative_path) < (int)sizeof(request_path)) {
        entry->blocked = rpsiod_blocked_direct_access(site, request_path);
    }
    snprintf(entry->etag, sizeof(entry->etag), "W/\"%llx-%llx-%llx\"",
             (unsigned long long)st->st_ino,
             (unsigned long long)st->st_size,
             (unsigned long long)st->st_mtim.tv_sec);
    static_meta_store_variant(site, entry, relative_path, ".br");
    static_meta_store_variant(site, entry, relative_path, ".gz");
    return entry;
}

static rpsiod_static_meta_cache_entry *static_meta_get(rpsiod_site_config *site, const char *relative_path, int file_fd, const struct stat *st) {
    rpsiod_static_meta_cache_entry *entry = static_meta_lookup(site, relative_path, st);
    if (entry != NULL) {
        return entry;
    }
    return static_meta_store(site, relative_path, file_fd, st);
}

static uint64_t next_request_id(void) {
    static uint64_t counter = 0;
    return ((uint64_t)getpid() << 32) | (++counter);
}

static ssize_t client_read(client_object *client, void *buf, size_t len) {
    if (!client->tls) {
        return read(client->fd, buf, len);
    }
    int n = SSL_read(client->ssl, buf, (int)len);
    if (n <= 0) {
        int err = SSL_get_error(client->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            errno = EAGAIN;
        } else {
            errno = EIO;
        }
        return -1;
    }
    return n;
}

static int wait_for_fd(int fd, short events);

static int client_write_all(client_object *client, const void *buf, size_t len) {
    if (!client->tls) {
        int rc = rpsiod_write_all(client->fd, buf, len);
        if (rc < 0) {
            rpsiod_perf_inc(&rpsiod_perf.write_errors);
        }
        return rc;
    }
    const unsigned char *p = (const unsigned char *)buf;
    while (len > 0) {
        int chunk = len > INT_MAX ? INT_MAX : (int)len;
        int n = SSL_write(client->ssl, p, chunk);
        if (n <= 0) {
            int err = SSL_get_error(client->ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                short events = err == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
                if (wait_for_fd(client->fd, events) > 0) {
                    continue;
                }
            }
            rpsiod_perf_inc(&rpsiod_perf.write_errors);
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int wait_for_fd(int fd, short events) {
    struct pollfd pfd = {.fd = fd, .events = events};
    for (;;) {
        int rc = poll(&pfd, 1, 1000);
        if (rc < 0 && errno == EINTR) {
            continue;
        }
        return rc;
    }
}

static int client_writev_all(client_object *client, const struct iovec *iov, int iovcnt) {
    if (iovcnt <= 0) {
        return 0;
    }
    if (client->tls) {
        for (int i = 0; i < iovcnt; i++) {
            if (client_write_all(client, iov[i].iov_base, iov[i].iov_len) < 0) {
                return -1;
            }
        }
        return 0;
    }
    struct iovec local[8];
    if (iovcnt > (int)(sizeof(local) / sizeof(local[0]))) {
        return -1;
    }
    memcpy(local, iov, (size_t)iovcnt * sizeof(local[0]));
    int first = 0;
    while (first < iovcnt) {
        ssize_t n = writev(client->fd, &local[first], iovcnt - first);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (wait_for_fd(client->fd, POLLOUT) > 0) {
                    continue;
                }
            }
            rpsiod_perf_inc(&rpsiod_perf.write_errors);
            return -1;
        }
        if (n == 0) {
            rpsiod_perf_inc(&rpsiod_perf.write_errors);
            return -1;
        }
        while (first < iovcnt && n >= (ssize_t)local[first].iov_len) {
            n -= (ssize_t)local[first].iov_len;
            first++;
        }
        if (first < iovcnt && n > 0) {
            local[first].iov_base = (char *)local[first].iov_base + n;
            local[first].iov_len -= (size_t)n;
        }
    }
    return 0;
}

static int copy_file_read_write(client_object *client, int file_fd, off_t offset, off_t length) {
    if (lseek(file_fd, offset, SEEK_SET) < 0) {
        return -1;
    }
    char chunk[65536];
    off_t remaining = length;
    while (remaining > 0) {
        size_t want = remaining > (off_t)sizeof(chunk) ? sizeof(chunk) : (size_t)remaining;
        ssize_t rd = read(file_fd, chunk, want);
        if (rd < 0) {
            if (errno == EINTR) {
                continue;
            }
            rpsiod_perf_inc(&rpsiod_perf.read_errors);
            return -1;
        }
        if (rd == 0) {
            rpsiod_perf_inc(&rpsiod_perf.read_errors);
            return -1;
        }
        if (client_write_all(client, chunk, (size_t)rd) < 0) {
            return -1;
        }
        remaining -= rd;
    }
    rpsiod_perf_inc(&rpsiod_perf.fallback_read_write_count);
    return 0;
}

static int send_file_body(client_object *client, int file_fd, off_t offset, off_t length) {
    if (length <= 0) {
        return 0;
    }
    if (client->tls || !client->sendfile_enabled) {
        return copy_file_read_write(client, file_fd, offset, length);
    }
    off_t current = offset;
    off_t remaining = length;
    while (remaining > 0) {
        ssize_t sent = sendfile(client->fd, file_fd, &current, (size_t)remaining);
        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (wait_for_fd(client->fd, POLLOUT) > 0) {
                    continue;
                }
                rpsiod_perf_inc(&rpsiod_perf.write_errors);
                return -1;
            }
            return copy_file_read_write(client, file_fd, current, remaining);
        }
        if (sent == 0) {
            rpsiod_perf_inc(&rpsiod_perf.write_errors);
            return -1;
        }
        rpsiod_perf_inc(&rpsiod_perf.sendfile_calls);
        rpsiod_perf_add(&rpsiod_perf.sendfile_bytes, (unsigned long long)sent);
        remaining -= sent;
    }
    return 0;
}

static int drop_privileges_after_bind(const rpsiod_config *cfg, rpsiod_logger *logger) {
    if (!cfg->drop_privileges || geteuid() != 0) {
        return 0;
    }
    struct group *gr = getgrnam(cfg->linux_group);
    struct passwd *pw = getpwnam(cfg->linux_user);
    if (gr == NULL || pw == NULL) {
        rpsiod_log_error(logger, NULL, "configured user/group %s:%s not found", cfg->linux_user, cfg->linux_group);
        return -1;
    }
    if (setgid(gr->gr_gid) < 0 || initgroups(pw->pw_name, gr->gr_gid) < 0 || setuid(pw->pw_uid) < 0) {
        rpsiod_log_error(logger, NULL, "failed to drop privileges to %s:%s: %s", cfg->linux_user, cfg->linux_group, strerror(errno));
        return -1;
    }
    rpsiod_log_error(logger, NULL, "dropped privileges to %s:%s", cfg->linux_user, cfg->linux_group);
    return 0;
}

static int set_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

static bool header_name_matches(const char *a, const char *b) {
    return rpsiod_streq_ci(a, b);
}

static bool header_removed(const rpsiod_site_config *site, const char *name) {
    if (site == NULL) {
        return false;
    }
    for (size_t i = 0; i < site->headers_remove_count; i++) {
        if (header_name_matches(site->headers_remove[i], name)) {
            return true;
        }
    }
    return false;
}

static bool protected_response_header(const char *name) {
    return header_name_matches(name, "Content-Length") ||
           header_name_matches(name, "Connection") ||
           header_name_matches(name, "Transfer-Encoding") ||
           header_name_matches(name, "Content-Type") ||
           header_name_matches(name, "Content-Encoding") ||
           header_name_matches(name, "Location") ||
           header_name_matches(name, "Content-Range") ||
           header_name_matches(name, "Retry-After") ||
           header_name_matches(name, "Cache-Control") ||
           header_name_matches(name, "Date") ||
           header_name_matches(name, "ETag") ||
           header_name_matches(name, "Last-Modified") ||
           header_name_matches(name, "Strict-Transport-Security") ||
           header_name_matches(name, "Accept-Ranges") ||
           header_name_matches(name, "X-Served-By") ||
           header_name_matches(name, "X-Cache") ||
           header_name_matches(name, "X-Cache-Hits") ||
           header_name_matches(name, "X-Timer") ||
           header_name_matches(name, "X-Request-ID") ||
           header_name_matches(name, "Vary") ||
           header_name_matches(name, "Alt-Svc") ||
           header_name_matches(name, "Server");
}

static bool header_added(const rpsiod_site_config *site, const char *name) {
    if (site == NULL) {
        return false;
    }
    for (size_t i = 0; i < site->headers_add_count; i++) {
        if (header_name_matches(site->headers_add[i].name, name)) {
            return true;
        }
    }
    return false;
}

static int append_header(char *buf, size_t buf_len, size_t *used, const char *name, const char *value) {
    if (*used >= buf_len) {
        return -1;
    }
    int n = snprintf(buf + *used, buf_len - *used, "%s: %s\r\n", name, value);
    if (n < 0 || (size_t)n >= buf_len - *used) {
        return -1;
    }
    *used += (size_t)n;
    return 0;
}

static void mark_request_start(client_object *client) {
    client->request_id = next_request_id();
    (void)clock_gettime(CLOCK_MONOTONIC, &client->request_started_mono);
    (void)clock_gettime(CLOCK_REALTIME, &client->request_started_real);
    client->last_active_mono = client->request_started_mono;
    client->idle_keep_alive = false;
}

static void perf_note_active_connection(void) {
    unsigned long long active = rpsiod_perf_get(&rpsiod_perf.active_connections);
    unsigned long long peak = rpsiod_perf_get(&rpsiod_perf.peak_active_connections);
    while (active > peak &&
           !atomic_compare_exchange_weak_explicit(&rpsiod_perf.peak_active_connections,
                                                  &peak,
                                                  active,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed)) {
    }
}

static void client_list_add(client_object **head, client_object *client) {
    client->prev = NULL;
    client->next = *head;
    if (*head != NULL) {
        (*head)->prev = client;
    }
    *head = client;
}

static void client_list_remove(client_object **head, client_object *client) {
    if (client->prev != NULL) {
        client->prev->next = client->next;
    } else if (*head == client) {
        *head = client->next;
    }
    if (client->next != NULL) {
        client->next->prev = client->prev;
    }
    client->prev = NULL;
    client->next = NULL;
}

static void format_http_time(time_t t, char *out, size_t out_len) {
    struct tm tm;
    if (gmtime_r(&t, &tm) == NULL ||
        strftime(out, out_len, "%a, %d %b %Y %H:%M:%S GMT", &tm) == 0) {
        rpsiod_safe_copy(out, out_len, "Thu, 01 Jan 1970 00:00:00 GMT");
    }
}

static const char *cached_date_value(void) {
    static time_t cached_time = 0;
    static char cached_date[64];
    time_t now = time(NULL);
    if (now != cached_time || cached_date[0] == '\0') {
        cached_time = now;
        format_http_time(now, cached_date, sizeof(cached_date));
    }
    return cached_date;
}

static const char *served_by_value(void) {
    static char hostname[256];
    if (hostname[0] == '\0') {
        if (gethostname(hostname, sizeof(hostname)) < 0 || hostname[0] == '\0') {
            rpsiod_safe_copy(hostname, sizeof(hostname), "rpsiod");
        }
        hostname[sizeof(hostname) - 1] = '\0';
    }
    return hostname;
}

static unsigned long long elapsed_request_ms(const client_object *client) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0 || client->request_started_mono.tv_sec == 0) {
        return 0;
    }
    time_t sec = now.tv_sec - client->request_started_mono.tv_sec;
    long nsec = now.tv_nsec - client->request_started_mono.tv_nsec;
    if (nsec < 0) {
        sec--;
        nsec += 1000000000L;
    }
    if (sec < 0) {
        return 0;
    }
    return (unsigned long long)sec * 1000ULL + (unsigned long long)nsec / 1000000ULL;
}

static double elapsed_request_subms(const client_object *client) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0 || client->request_started_mono.tv_sec == 0) {
        return 0.0;
    }
    time_t sec = now.tv_sec - client->request_started_mono.tv_sec;
    long nsec = now.tv_nsec - client->request_started_mono.tv_nsec;
    if (nsec < 0) {
        sec--;
        nsec += 1000000000L;
    }
    if (sec < 0) {
        return 0.0;
    }
    return (double)sec * 1000.0 + (double)nsec / 1000000.0;
}

static void trace_stage(client_object *client, rpsiod_logger *logger, const rpsiod_site_config *site, const rpsiod_http_request *req, const char *stage, const char *fmt, ...) {
    if (req == NULL || !req->trace_request) {
        return;
    }
    struct timespec real_now;
    (void)clock_gettime(CLOCK_REALTIME, &real_now);
    char detail[1024] = "";
    if (fmt != NULL && fmt[0] != '\0') {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(detail, sizeof(detail), fmt, ap);
        va_end(ap);
    }
    rpsiod_log_error(logger, site,
                     "trace request=%llx stage=%s realtime=%lld.%09ld elapsed_ms=%.3f fd=%d reused=%s method=%s path=%s %s",
                     (unsigned long long)client->request_id,
                     stage,
                     (long long)real_now.tv_sec,
                     real_now.tv_nsec,
                     elapsed_request_subms(client),
                     client->fd,
                     client->keep_alive_requests > 0 ? "true" : "false",
                     req->method,
                     req->path,
                     detail);
}

static void trace_absolute_time(client_object *client, rpsiod_logger *logger, const rpsiod_site_config *site, const rpsiod_http_request *req, const char *stage, const struct timespec *ts) {
    if (req == NULL || !req->trace_request || ts == NULL || ts->tv_sec == 0) {
        return;
    }
    rpsiod_log_error(logger, site,
                     "trace request=%llx stage=%s realtime=%lld.%09ld fd=%d method=%s path=%s",
                     (unsigned long long)client->request_id,
                     stage,
                     (long long)ts->tv_sec,
                     ts->tv_nsec,
                     client->fd,
                     req->method,
                     req->path);
}

static bool etag_opaque_matches(const char *candidate, size_t candidate_len, const char *etag) {
    if (candidate_len >= 2 && candidate[0] == 'W' && candidate[1] == '/') {
        candidate += 2;
        candidate_len -= 2;
    }
    size_t etag_len = strlen(etag);
    if (etag_len >= 2 && etag[0] == 'W' && etag[1] == '/') {
        etag += 2;
        etag_len -= 2;
    }
    return candidate_len == etag_len && strncmp(candidate, etag, etag_len) == 0;
}

static bool if_none_match_matches(const char *value, const char *etag) {
    if (value == NULL || value[0] == '\0' || etag == NULL || etag[0] == '\0') {
        return false;
    }
    const char *p = value;
    while (*p != '\0') {
        while (*p == ' ' || *p == '\t' || *p == ',') {
            p++;
        }
        const char *start = p;
        while (*p != '\0' && *p != ',') {
            p++;
        }
        const char *end = p;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
            end--;
        }
        if (start < end && start[0] == '*' && start + 1 == end) {
            return true;
        }
        if (etag_opaque_matches(start, (size_t)(end - start), etag)) {
            return true;
        }
    }
    return false;
}

static bool parse_http_time(const char *value, time_t *out) {
    if (value == NULL || value[0] == '\0') {
        return false;
    }
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    char *end = strptime(value, "%a, %d %b %Y %H:%M:%S GMT", &tm);
    if (end == NULL) {
        memset(&tm, 0, sizeof(tm));
        end = strptime(value, "%A, %d-%b-%y %H:%M:%S GMT", &tm);
    }
    if (end == NULL) {
        memset(&tm, 0, sizeof(tm));
        end = strptime(value, "%a %b %e %H:%M:%S %Y", &tm);
    }
    if (end == NULL) {
        return false;
    }
    while (*end == ' ' || *end == '\t') {
        end++;
    }
    if (*end != '\0') {
        return false;
    }
    *out = timegm(&tm);
    return true;
}

static bool request_cache_validator_matches(const rpsiod_http_request *req, const struct stat *st, const char *etag) {
    if (!rpsiod_streq_ci(req->method, "GET") && !rpsiod_streq_ci(req->method, "HEAD")) {
        return false;
    }
    if (req->if_none_match[0] != '\0') {
        return if_none_match_matches(req->if_none_match, etag);
    }
    if (req->if_modified_since[0] != '\0') {
        time_t since = 0;
        if (parse_http_time(req->if_modified_since, &since)) {
            return st->st_mtime <= since;
        }
    }
    return false;
}

static int build_response_headers(client_object *client, int status, const char *content_type, off_t content_length, bool keep_alive, const response_options *opts, char *headers, size_t headers_len, size_t *used_out) {
    const rpsiod_site_config *site = opts != NULL ? opts->site : NULL;
    size_t used = 0;
    int n = snprintf(headers, headers_len, "HTTP/1.1 %d %s\r\n", status, rpsiod_http_status_text(status));
    if (n < 0 || (size_t)n >= headers_len) {
        return -1;
    }
    used = (size_t)n;

    if (!header_removed(site, "Date")) {
        if (append_header(headers, headers_len, &used, "Date", cached_date_value()) < 0) return -1;
    }
    if (!(site != NULL && site->hide_server_header) && !header_removed(site, "Server")) {
        if (append_header(headers, headers_len, &used, "Server", "rpsiod") < 0) return -1;
    }
    if (opts != NULL && opts->location != NULL && !header_removed(site, "Location")) {
        if (append_header(headers, headers_len, &used, "Location", opts->location) < 0) return -1;
    }
    if (opts != NULL && opts->content_range != NULL && !header_removed(site, "Content-Range")) {
        if (append_header(headers, headers_len, &used, "Content-Range", opts->content_range) < 0) return -1;
    }
    if (opts != NULL && opts->retry_after != NULL && !header_removed(site, "Retry-After")) {
        if (append_header(headers, headers_len, &used, "Retry-After", opts->retry_after) < 0) return -1;
    }
    if (!header_removed(site, "Content-Type")) {
        if (append_header(headers, headers_len, &used, "Content-Type", content_type != NULL ? content_type : "text/plain; charset=utf-8") < 0) return -1;
    }
    if (content_length >= 0) {
        char clen[64];
        snprintf(clen, sizeof(clen), "%lld", (long long)content_length);
        if (!header_removed(site, "Content-Length")) {
            if (append_header(headers, headers_len, &used, "Content-Length", clen) < 0) return -1;
        }
    } else if (opts != NULL && opts->chunked_response) {
        if (append_header(headers, headers_len, &used, "Transfer-Encoding", "chunked") < 0) return -1;
    }
    if (opts != NULL && opts->content_encoding != NULL && !header_removed(site, "Content-Encoding")) {
        if (append_header(headers, headers_len, &used, "Content-Encoding", opts->content_encoding) < 0) return -1;
    }
    if (!(opts != NULL && opts->suppress_default_cache_control) && !header_removed(site, "Cache-Control")) {
        const char *cache_value = "no-cache";
        if (site != NULL && opts != NULL && opts->cache_control && site->cache_enabled && site->cache_default[0] != '\0') {
            cache_value = site->cache_default;
        }
        if (append_header(headers, headers_len, &used, "Cache-Control", cache_value) < 0) return -1;
    }
    if (opts != NULL && opts->etag != NULL && !header_removed(site, "ETag")) {
        if (append_header(headers, headers_len, &used, "ETag", opts->etag) < 0) return -1;
    } else if (opts != NULL && opts->file_stat != NULL && !header_removed(site, "ETag")) {
        char etag[128];
        snprintf(etag, sizeof(etag), "W/\"%llx-%llx-%llx\"",
                 (unsigned long long)opts->file_stat->st_ino,
                 (unsigned long long)opts->file_stat->st_size,
                 (unsigned long long)opts->file_stat->st_mtim.tv_sec);
        if (append_header(headers, headers_len, &used, "ETag", etag) < 0) return -1;
    }
    if (opts != NULL && opts->file_stat != NULL && !header_removed(site, "Last-Modified")) {
        char modified[64];
        format_http_time(opts->file_stat->st_mtime, modified, sizeof(modified));
        if (append_header(headers, headers_len, &used, "Last-Modified", modified) < 0) return -1;
    }
    if (client->tls && !header_removed(site, "Strict-Transport-Security")) {
        if (append_header(headers, headers_len, &used, "Strict-Transport-Security", "max-age=31536000; includeSubDomains") < 0) return -1;
    }
    if (opts != NULL && opts->accept_ranges && !header_removed(site, "Accept-Ranges")) {
        if (append_header(headers, headers_len, &used, "Accept-Ranges", "bytes") < 0) return -1;
    }
    if (!header_removed(site, "Connection")) {
        if (append_header(headers, headers_len, &used, "Connection", keep_alive ? "keep-alive" : "close") < 0) return -1;
    }
    if (!header_removed(site, "X-Served-By")) {
        if (append_header(headers, headers_len, &used, "X-Served-By", served_by_value()) < 0) return -1;
    }
    if (!header_removed(site, "X-Cache")) {
        if (append_header(headers, headers_len, &used, "X-Cache", "MISS") < 0) return -1;
    }
    if (!header_removed(site, "X-Cache-Hits")) {
        if (append_header(headers, headers_len, &used, "X-Cache-Hits", "0") < 0) return -1;
    }
    if (!header_removed(site, "X-Timer")) {
        char timer[96];
        long ms = client->request_started_real.tv_nsec / 1000000L;
        if (client->request_started_real.tv_sec == 0) {
            struct timespec now;
            (void)clock_gettime(CLOCK_REALTIME, &now);
            client->request_started_real = now;
            ms = now.tv_nsec / 1000000L;
        }
        snprintf(timer, sizeof(timer), "S%lld%03ld,VS0,VE%llu",
                 (long long)client->request_started_real.tv_sec,
                 ms,
                 elapsed_request_ms(client));
        if (append_header(headers, headers_len, &used, "X-Timer", timer) < 0) return -1;
    }
    if (!header_removed(site, "X-Request-ID")) {
        char request_id[64];
        snprintf(request_id, sizeof(request_id), "%llx", (unsigned long long)client->request_id);
        if (append_header(headers, headers_len, &used, "X-Request-ID", request_id) < 0) return -1;
    }
    if (opts != NULL && opts->vary_accept_encoding && !header_removed(site, "Vary")) {
        if (append_header(headers, headers_len, &used, "Vary", "Accept-Encoding") < 0) return -1;
    }
    if (!header_removed(site, "Alt-Svc")) {
        if (append_header(headers, headers_len, &used, "Alt-Svc", "clear") < 0) return -1;
    }
    if (!header_removed(site, "X-Content-Type-Options") && !header_added(site, "X-Content-Type-Options")) {
        if (append_header(headers, headers_len, &used, "X-Content-Type-Options", "nosniff") < 0) return -1;
    }
    if (site != NULL) {
        for (size_t i = 0; i < site->headers_add_count; i++) {
            if (!protected_response_header(site->headers_add[i].name) && !header_removed(site, site->headers_add[i].name)) {
                if (append_header(headers, headers_len, &used, site->headers_add[i].name, site->headers_add[i].value) < 0) return -1;
            }
        }
    }
    if (used + 2 >= headers_len) {
        return -1;
    }
    headers[used++] = '\r';
    headers[used++] = '\n';
    *used_out = used;
    return 0;
}

static int write_response_headers(client_object *client, int status, const char *content_type, off_t content_length, bool keep_alive, const response_options *opts) {
    char headers[16384];
    size_t used = 0;
    if (build_response_headers(client, status, content_type, content_length, keep_alive, opts, headers, sizeof(headers), &used) < 0) {
        return -1;
    }
    return client_write_all(client, headers, used);
}

static bool response_header_token_valid(const char *name) {
    if (name == NULL || name[0] == '\0') {
        return false;
    }
    for (const unsigned char *cursor = (const unsigned char *)name; *cursor != '\0'; cursor++) {
        unsigned char ch = *cursor;
        bool valid = (ch >= '0' && ch <= '9') ||
                     (ch >= 'A' && ch <= 'Z') ||
                     (ch >= 'a' && ch <= 'z') ||
                     ch == '!' || ch == '#' || ch == '$' || ch == '%' ||
                     ch == '&' || ch == '\'' || ch == '*' || ch == '+' ||
                     ch == '-' || ch == '.' || ch == '^' || ch == '_' ||
                     ch == '`' || ch == '|' || ch == '~';
        if (!valid) {
            return false;
        }
    }
    return true;
}

static bool response_header_value_valid(const char *value) {
    if (value == NULL) {
        return false;
    }
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; cursor++) {
        if ((*cursor < 0x20 && *cursor != '\t') || *cursor == 0x7f) {
            return false;
        }
    }
    return true;
}

static bool php_response_header_allowed(const char *name) {
    return !header_name_matches(name, "Status") &&
           !header_name_matches(name, "Content-Type") &&
           !header_name_matches(name, "Content-Length") &&
           !header_name_matches(name, "Connection") &&
           !header_name_matches(name, "Keep-Alive") &&
           !header_name_matches(name, "Proxy-Authenticate") &&
           !header_name_matches(name, "Proxy-Authorization") &&
           !header_name_matches(name, "TE") &&
           !header_name_matches(name, "Trailer") &&
           !header_name_matches(name, "Transfer-Encoding") &&
           !header_name_matches(name, "Upgrade") &&
           !header_name_matches(name, "Server") &&
           !header_name_matches(name, "Date") &&
           !header_name_matches(name, "Strict-Transport-Security") &&
           !header_name_matches(name, "X-Served-By") &&
           !header_name_matches(name, "X-Cache") &&
           !header_name_matches(name, "X-Cache-Hits") &&
           !header_name_matches(name, "X-Timer") &&
           !header_name_matches(name, "X-Request-ID") &&
           !header_name_matches(name, "Alt-Svc");
}

static int append_php_response_headers(char *headers, size_t headers_len, size_t *used, char *cgi_headers, const rpsiod_site_config *site) {
    char *save = NULL;
    for (char *line = strtok_r(cgi_headers, "\r\n", &save); line != NULL; line = strtok_r(NULL, "\r\n", &save)) {
        char *colon = strchr(line, ':');
        if (colon == NULL) {
            continue;
        }
        *colon = '\0';
        char *name = line;
        char *value = colon + 1;
        rpsiod_trim(name);
        rpsiod_trim(value);
        if (response_header_token_valid(name) &&
            response_header_value_valid(value) &&
            php_response_header_allowed(name) &&
            !header_removed(site, name) &&
            append_header(headers, headers_len, used, name, value) < 0) {
            return -1;
        }
    }
    return 0;
}

static int write_php_response_headers(client_object *client, const rpsiod_site_config *site, int status,
                                      const char *content_type, off_t content_length, bool keep_alive,
                                      char *cgi_headers, bool chunked_response) {
    char headers[16384];
    size_t used = 0;
    response_options opts = {.site = site, .suppress_default_cache_control = true, .chunked_response = chunked_response};
    if (build_response_headers(client, status, content_type, content_length, keep_alive, &opts, headers, sizeof(headers), &used) < 0) {
        return -1;
    }
    if (used < 2 || headers[used - 2] != '\r' || headers[used - 1] != '\n') {
        return -1;
    }
    used -= 2;
    if (cgi_headers != NULL && append_php_response_headers(headers, sizeof(headers), &used, cgi_headers, site) < 0) {
        return -1;
    }
    if (used + 2 >= sizeof(headers)) {
        return -1;
    }
    headers[used++] = '\r';
    headers[used++] = '\n';
    return client_write_all(client, headers, used);
}

static int client_write_chunked_body(client_object *client, const unsigned char *body, size_t body_len) {
    if (body_len == 0) {
        return 0;
    }
    char prefix[32];
    int prefix_len = snprintf(prefix, sizeof(prefix), "%zx\r\n", body_len);
    if (prefix_len < 0 || (size_t)prefix_len >= sizeof(prefix)) {
        return -1;
    }
    struct iovec chunks[3] = {
        {.iov_base = prefix, .iov_len = (size_t)prefix_len},
        {.iov_base = (void *)body, .iov_len = body_len},
        {.iov_base = "\r\n", .iov_len = 2},
    };
    return client_writev_all(client, chunks, 3);
}

static int client_write_chunked_end(client_object *client) {
    return client_write_all(client, "0\r\n\r\n", 5);
}

static int write_small_file_response(client_object *client, int status, const char *content_type, int file_fd, off_t length, bool keep_alive, const response_options *opts) {
    if (length < 0 || length > RPSIOD_SMALL_FILE_WRITEV_MAX) {
        return -1;
    }
    char headers[16384];
    size_t header_len = 0;
    if (build_response_headers(client, status, content_type, length, keep_alive, opts, headers, sizeof(headers), &header_len) < 0) {
        return -1;
    }
    char body[RPSIOD_SMALL_FILE_WRITEV_MAX];
    size_t body_len = (size_t)length;
    size_t got = 0;
    while (got < body_len) {
        ssize_t rd = pread(file_fd, body + got, body_len - got, (off_t)got);
        if (rd < 0) {
            if (errno == EINTR) {
                continue;
            }
            rpsiod_perf_inc(&rpsiod_perf.read_errors);
            return -1;
        }
        if (rd == 0) {
            break;
        }
        got += (size_t)rd;
    }
    if (got != body_len) {
        return -1;
    }
    struct iovec iov[2] = {
        {.iov_base = headers, .iov_len = header_len},
        {.iov_base = body, .iov_len = body_len}
    };
    return client_writev_all(client, iov, 2);
}

static int send_text(client_object *client, const rpsiod_site_config *site, int status, const char *text, const rpsiod_http_request *req, rpsiod_logger *logger) {
    size_t len = strlen(text);
    response_options opts = {.site = site, .cache_control = false};
    if (write_response_headers(client, status, "text/plain; charset=utf-8", (off_t)len, req->keep_alive, &opts) < 0) {
        return -1;
    }
    struct iovec body_iov = {.iov_base = (void *)text, .iov_len = len};
    if (!req->head_only && client_writev_all(client, &body_iov, 1) < 0) {
        return -1;
    }
    rpsiod_log_access(logger, site, client->client_ip, req->method, req->path, status, (unsigned long long)len);
    return 0;
}

static int send_file_fd(client_object *client, rpsiod_site_config *site, int status, const char *path, int file_fd, const struct stat *st, const rpsiod_static_meta_cache_entry *meta, const rpsiod_http_request *req, rpsiod_logger *logger) {
    const char *mime = meta != NULL && meta->mime[0] != '\0' ? meta->mime : rpsiod_mime_type(path);
    const char *etag = meta != NULL && meta->etag[0] != '\0' ? meta->etag : NULL;
    const char *planned_send_method = (!req->head_only && st->st_size >= 0 && st->st_size <= RPSIOD_SMALL_FILE_WRITEV_MAX)
                                      ? "writev"
                                      : ((client->tls || !client->sendfile_enabled) ? "read-write" : "sendfile");
    trace_stage(client, logger, site, req, "file-ready", "file=%s size=%lld mime=%s cache=%s send_method=%s",
                path,
                (long long)st->st_size,
                mime,
                meta != NULL ? "meta-hit" : "meta-miss",
                planned_send_method);
    if (status == 200 && !req->range_present && request_cache_validator_matches(req, st, etag)) {
        response_options opts = {
            .site = site,
            .etag = etag,
            .file_stat = st,
            .cache_control = true,
            .accept_ranges = true,
            .vary_accept_encoding = site->compression_enabled
        };
        int rc = write_response_headers(client, 304, mime, 0, req->keep_alive, &opts);
        trace_stage(client, logger, site, req, "headers-sent", "status=304 bytes=0 cache=validator-hit");
        rpsiod_log_access(logger, site, client->client_ip, req->method, req->path, 304, 0);
        return rc;
    }
    if (status == 200 && req->range_present) {
        off_t total = st->st_size;
        off_t start = 0;
        off_t end = total > 0 ? total - 1 : 0;
        bool valid = total > 0;
        if (valid && req->range_suffix) {
            unsigned long long suffix = req->range_start;
            if (suffix >= (unsigned long long)total) {
                start = 0;
            } else {
                start = total - (off_t)suffix;
            }
        } else if (valid) {
            if (req->range_start >= (unsigned long long)total) {
                valid = false;
            } else {
                start = (off_t)req->range_start;
                if (req->range_has_end) {
                    end = req->range_end >= (unsigned long long)total ? total - 1 : (off_t)req->range_end;
                }
                if (end < start) {
                    valid = false;
                }
            }
        }
        if (!valid) {
            char unsat[128];
            snprintf(unsat, sizeof(unsat), "bytes */%lld", (long long)total);
            response_options opts = {
                .site = site,
                .content_range = unsat,
                .etag = etag,
                .file_stat = st,
                .cache_control = false,
                .accept_ranges = true
            };
            int rc = write_response_headers(client, 416, "text/plain; charset=utf-8", 0, req->keep_alive, &opts);
            trace_stage(client, logger, site, req, "headers-sent", "status=416 bytes=0");
            rpsiod_log_access(logger, site, client->client_ip, req->method, req->path, 416, 0);
            return rc;
        }
        off_t length = end - start + 1;
        char content_range[128];
        snprintf(content_range, sizeof(content_range), "bytes %lld-%lld/%lld", (long long)start, (long long)end, (long long)total);
        response_options opts = {
            .site = site,
            .content_range = content_range,
            .etag = etag,
            .file_stat = st,
            .cache_control = true,
            .accept_ranges = true
        };
        if (write_response_headers(client, 206, mime, length, req->keep_alive, &opts) < 0) {
            return -1;
        }
        trace_stage(client, logger, site, req, "headers-sent", "status=206 bytes=%lld", (long long)length);
        if (!req->head_only) {
            if (send_file_body(client, file_fd, start, length) < 0) return -1;
        }
        trace_stage(client, logger, site, req, "body-sent", "status=206 bytes=%lld send_method=%s",
                    (long long)length,
                    (client->tls || !client->sendfile_enabled) ? "read-write" : "sendfile");
        rpsiod_log_access(logger, site, client->client_ip, req->method, req->path, 206, (unsigned long long)length);
        return 0;
    }

    bool can_compress = status == 200 && site->compression_enabled &&
                        !req->upgrade_websocket && rpsiod_content_type_compressible(mime) && !rpsiod_path_already_compressed(path) &&
                        st->st_size >= 0 && (uint64_t)st->st_size >= site->compression_minimum_size &&
                        st->st_size <= (16 * 1024 * 1024);
    bool use_br = can_compress && site->compression_br && rpsiod_accepts_br(req->accept_encoding);
    bool use_gzip = can_compress && (site->compression_gzip || !site->compression_br) && rpsiod_accepts_gzip(req->accept_encoding);
    if (use_gzip || use_br) {
        const char *variants[2] = {NULL, NULL};
        const char *encodings[2] = {NULL, NULL};
        size_t variant_count = 0;
        char br_path[PATH_MAX];
        char gz_path[PATH_MAX];
        if (use_br && (meta == NULL || meta->has_br) && snprintf(br_path, sizeof(br_path), "%s.br", path) < (int)sizeof(br_path)) {
            variants[variant_count] = br_path;
            encodings[variant_count++] = "br";
        }
        if (use_gzip && (meta == NULL || meta->has_gzip) && snprintf(gz_path, sizeof(gz_path), "%s.gz", path) < (int)sizeof(gz_path)) {
            variants[variant_count] = gz_path;
            encodings[variant_count++] = "gzip";
        }
        for (size_t i = 0; i < variant_count; i++) {
            int cfd = rpsiod_static_open_site_path(site, variants[i]);
            if (cfd < 0) {
                continue;
            }
            struct stat cst;
            rpsiod_perf_inc(&rpsiod_perf.file_stat_calls);
            if (fstat(cfd, &cst) == 0 && S_ISREG(cst.st_mode)) {
                response_options opts = {
                    .site = site,
                    .content_encoding = encodings[i],
                    .etag = etag,
                    .file_stat = st,
                    .cache_control = true,
                    .accept_ranges = true,
                    .vary_accept_encoding = true
                };
                int rc = write_response_headers(client, status, mime, cst.st_size, req->keep_alive, &opts);
                trace_stage(client, logger, site, req, "headers-sent", "status=%d bytes=%lld encoding=%s",
                            status, (long long)cst.st_size, encodings[i]);
                if (rc == 0 && !req->head_only) {
                    rc = send_file_body(client, cfd, 0, cst.st_size);
                }
                trace_stage(client, logger, site, req, "body-sent", "status=%d bytes=%lld send_method=%s encoding=%s",
                            status,
                            (long long)cst.st_size,
                            (client->tls || !client->sendfile_enabled) ? "read-write" : "sendfile",
                            encodings[i]);
                close(cfd);
                rpsiod_log_access(logger, site, client->client_ip, req->method, req->path, status, (unsigned long long)cst.st_size);
                return rc;
            }
            close(cfd);
        }
    }
    if (can_compress && (use_gzip || use_br)) {
        unsigned char *plain = malloc((size_t)st->st_size);
        if (plain != NULL) {
            ssize_t got = pread(file_fd, plain, (size_t)st->st_size, 0);
            if (got == st->st_size) {
                unsigned char *compressed = NULL;
                size_t compressed_len = 0;
                const char *encoding = NULL;
                if (use_br && rpsiod_brotli_compress(plain, (size_t)st->st_size, &compressed, &compressed_len) == 0) {
                    encoding = "br";
                } else if (use_gzip) {
                    if (rpsiod_gzip_compress(plain, (size_t)st->st_size, &compressed, &compressed_len) != 0) {
                        (void)rpsiod_gzip_store(plain, (size_t)st->st_size, &compressed, &compressed_len);
                    }
                    if (compressed != NULL) {
                        encoding = "gzip";
                    }
                }
                if (compressed != NULL && encoding != NULL) {
                    response_options opts = {
                        .site = site,
                        .content_encoding = encoding,
                        .etag = etag,
                        .file_stat = st,
                        .cache_control = status == 200,
                        .accept_ranges = true,
                        .vary_accept_encoding = true
                    };
                    int rc = write_response_headers(client, status, mime, (off_t)compressed_len, req->keep_alive, &opts);
                    trace_stage(client, logger, site, req, "headers-sent", "status=%d bytes=%zu encoding=%s",
                                status, compressed_len, encoding);
                    if (rc == 0 && !req->head_only) {
                        rc = client_write_all(client, compressed, compressed_len);
                    }
                    trace_stage(client, logger, site, req, "body-sent", "status=%d bytes=%zu send_method=write encoding=%s",
                                status, compressed_len, encoding);
                    free(compressed);
                    free(plain);
                    rpsiod_log_access(logger, site, client->client_ip, req->method, req->path, status, (unsigned long long)compressed_len);
                    return rc;
                }
            }
            free(plain);
        }
    }
    response_options opts = {
        .site = site,
        .etag = etag,
        .file_stat = st,
        .cache_control = status == 200,
        .accept_ranges = true,
        .vary_accept_encoding = site->compression_enabled
    };
    if (!req->head_only && st->st_size >= 0 && st->st_size <= RPSIOD_SMALL_FILE_WRITEV_MAX) {
        int rc = write_small_file_response(client, status, mime, file_fd, st->st_size, req->keep_alive, &opts);
        if (rc == 0) {
            unsigned long long bytes = (unsigned long long)st->st_size;
            trace_stage(client, logger, site, req, "headers-sent", "status=%d bytes=%lld writev=true", status, (long long)st->st_size);
            trace_stage(client, logger, site, req, "body-sent", "status=%d bytes=%llu send_method=writev", status, bytes);
            rpsiod_log_access(logger, site, client->client_ip, req->method, req->path, status, bytes);
            return 0;
        }
    }
    if (write_response_headers(client, status, mime, st->st_size, req->keep_alive, &opts) < 0) {
        return -1;
    }
    trace_stage(client, logger, site, req, "headers-sent", "status=%d bytes=%lld", status, (long long)st->st_size);
    unsigned long long bytes = (unsigned long long)st->st_size;
    if (!req->head_only) {
        if (send_file_body(client, file_fd, 0, st->st_size) < 0) return -1;
    }
    trace_stage(client, logger, site, req, "body-sent", "status=%d bytes=%llu send_method=%s",
                status,
                bytes,
                (client->tls || !client->sendfile_enabled) ? "read-write" : "sendfile");
    rpsiod_log_access(logger, site, client->client_ip, req->method, req->path, status, bytes);
    return 0;
}

static int send_error_page(client_object *client, rpsiod_site_config *site, int status, const rpsiod_http_request *req, rpsiod_logger *logger) {
    const char *page = rpsiod_site_error_page(site, status);
    if (page != NULL && page[0] != '\0') {
        int fd = open(page, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            struct stat st;
            if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
                int rc = send_file_fd(client, site, status, page, fd, &st, NULL, req, logger);
                close(fd);
                return rc;
            }
            close(fd);
        }
    }
    char body[256];
    int len = snprintf(body, sizeof(body), "%d %s\n", status, rpsiod_http_status_text(status));
    if (len < 0) {
        return -1;
    }
    return send_text(client, site, status, body, req, logger);
}

static bool static_cache_path_blocked(const rpsiod_site_config *site, const char *relative_path) {
    if (rpsiod_php_path_is_source_like(relative_path)) {
        return true;
    }
    char request_path[PATH_MAX];
    if (snprintf(request_path, sizeof(request_path), "/%s", relative_path) >= (int)sizeof(request_path)) {
        return true;
    }
    return rpsiod_blocked_direct_access(site, request_path);
}

static bool selected_path_blocked_direct_access(const rpsiod_site_config *site, const char *selected) {
    char request_path[PATH_MAX];
    if (selected[0] == '/') {
        if (snprintf(request_path, sizeof(request_path), "%s", selected) >= (int)sizeof(request_path)) {
            return true;
        }
    } else if (snprintf(request_path, sizeof(request_path), "/%s", selected) >= (int)sizeof(request_path)) {
        return true;
    }
    return rpsiod_blocked_direct_access(site, request_path);
}

static void static_open_cache_invalidate_entry(rpsiod_open_file_cache_entry *entry) {
    if (entry->fd >= 0) {
        close(entry->fd);
    }
    memset(entry, 0, sizeof(*entry));
    entry->fd = -1;
}

static int static_open_cache_lookup(rpsiod_config *cfg, rpsiod_site_config *site, const char *relative_path, struct stat *st) {
    if (!cfg->open_file_cache_enabled || cfg->open_file_cache_max == 0 || static_cache_path_blocked(site, relative_path)) {
        return -1;
    }
    size_t max = cfg->open_file_cache_max > RPSIOD_OPEN_FILE_CACHE_MAX ? RPSIOD_OPEN_FILE_CACHE_MAX : cfg->open_file_cache_max;
    for (size_t i = 0; i < max; i++) {
        rpsiod_open_file_cache_entry *entry = &site->open_file_cache[i];
        if (!entry->valid || entry->fd < 0 || strcmp(entry->relative_path, relative_path) != 0) {
            continue;
        }
        int current_fd = rpsiod_static_open_site_path(site, relative_path);
        if (current_fd < 0) {
            static_open_cache_invalidate_entry(entry);
            if (site->open_file_cache_count > 0) {
                site->open_file_cache_count--;
            }
            return -1;
        }
        struct stat current;
        rpsiod_perf_inc(&rpsiod_perf.file_stat_calls);
        if (fstat(current_fd, &current) < 0 ||
            !S_ISREG(current.st_mode) ||
            current.st_size != entry->size ||
            current.st_mtime != entry->mtime ||
            (unsigned long long)current.st_ino != entry->inode) {
            close(current_fd);
            static_open_cache_invalidate_entry(entry);
            if (site->open_file_cache_count > 0) {
                site->open_file_cache_count--;
            }
            return -1;
        }
        *st = current;
        entry->last_used = ++site->open_file_cache_tick;
        rpsiod_perf_inc(&rpsiod_perf.cache_hits);
        return current_fd;
    }
    return -1;
}

static void static_open_cache_store(rpsiod_config *cfg, rpsiod_site_config *site, const char *relative_path, int fd, const struct stat *st) {
    if (!cfg->open_file_cache_enabled || cfg->open_file_cache_max == 0 || fd < 0 || !S_ISREG(st->st_mode) ||
        static_cache_path_blocked(site, relative_path)) {
        return;
    }
    size_t max = cfg->open_file_cache_max > RPSIOD_OPEN_FILE_CACHE_MAX ? RPSIOD_OPEN_FILE_CACHE_MAX : cfg->open_file_cache_max;
    size_t slot = SIZE_MAX;
    unsigned long long oldest_tick = ULLONG_MAX;
    for (size_t i = 0; i < max; i++) {
        rpsiod_open_file_cache_entry *entry = &site->open_file_cache[i];
        if (entry->valid && strcmp(entry->relative_path, relative_path) == 0) {
            slot = i;
            break;
        }
        if (!entry->valid) {
            slot = i;
            break;
        }
        if (entry->last_used < oldest_tick) {
            oldest_tick = entry->last_used;
            slot = i;
        }
    }
    if (slot == SIZE_MAX) {
        return;
    }
    rpsiod_open_file_cache_entry *entry = &site->open_file_cache[slot];
    bool was_valid = entry->valid;
    if (entry->valid) {
        static_open_cache_invalidate_entry(entry);
    }
    int cached_fd = dup(fd);
    if (cached_fd < 0) {
        return;
    }
    entry->valid = true;
    entry->fd = cached_fd;
    rpsiod_safe_copy(entry->relative_path, sizeof(entry->relative_path), relative_path);
    entry->size = st->st_size;
    entry->mtime = st->st_mtime;
    entry->inode = (unsigned long long)st->st_ino;
    entry->last_used = ++site->open_file_cache_tick;
    if (!was_valid && site->open_file_cache_count < max) {
        site->open_file_cache_count++;
    }
}

static int open_static_path(rpsiod_config *cfg, rpsiod_site_config *site, const char *relative_path, struct stat *st) {
    int cached_fd = static_open_cache_lookup(cfg, site, relative_path, st);
    if (cached_fd >= 0) {
        return cached_fd;
    }
    int fd = rpsiod_static_open_site_path(site, relative_path);
    if (fd < 0) {
        return -1;
    }
    rpsiod_perf_inc(&rpsiod_perf.file_stat_calls);
    if (fstat(fd, st) < 0) {
        close(fd);
        return -1;
    }
    static_open_cache_store(cfg, site, relative_path, fd, st);
    return fd;
}

static int try_open_static(rpsiod_config *cfg, rpsiod_site_config *site, const char *request_path, char *selected, size_t selected_len, struct stat *st) {
    const char *rel = rpsiod_static_relative_request_path(request_path);
    size_t rel_len = strlen(rel);
    if (strcmp(rel, ".") == 0 || (rel_len > 0 && rel[rel_len - 1] == '/')) {
        for (size_t i = 0; i < site->index_count; i++) {
            char idx[PATH_MAX];
            if (strcmp(rel, ".") == 0) {
                if (snprintf(idx, sizeof(idx), "%s", site->indexes[i]) >= (int)sizeof(idx)) {
                    continue;
                }
            } else if (snprintf(idx, sizeof(idx), "%s%s", rel, site->indexes[i]) >= (int)sizeof(idx)) {
                continue;
            }
            int idx_fd = open_static_path(cfg, site, idx, st);
            if (idx_fd < 0) {
                continue;
            }
            if (S_ISREG(st->st_mode)) {
                rpsiod_safe_copy(selected, selected_len, idx);
                return idx_fd;
            }
            close(idx_fd);
        }
    }

    int fd = open_static_path(cfg, site, rel, st);
    if (fd < 0) {
        return -1;
    }
    if (S_ISDIR(st->st_mode)) {
        for (size_t i = 0; i < site->index_count; i++) {
            char idx[PATH_MAX];
            if (strcmp(rel, ".") == 0) {
                if (snprintf(idx, sizeof(idx), "%s", site->indexes[i]) >= (int)sizeof(idx)) {
                    continue;
                }
            } else if (snprintf(idx, sizeof(idx), "%s/%s", rel, site->indexes[i]) >= (int)sizeof(idx)) {
                continue;
            }
            int idx_fd = open_static_path(cfg, site, idx, st);
            if (idx_fd < 0) {
                continue;
            }
            if (S_ISREG(st->st_mode)) {
                rpsiod_safe_copy(selected, selected_len, idx);
                close(fd);
                return idx_fd;
            }
            close(idx_fd);
        }
        close(fd);
        errno = EISDIR;
        return -1;
    }
    if (!S_ISREG(st->st_mode)) {
        close(fd);
        errno = EACCES;
        return -1;
    }
    rpsiod_safe_copy(selected, selected_len, rel);
    return fd;
}

static int connect_with_timeout(int fd, const struct sockaddr *addr, socklen_t addr_len, int timeout_sec) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }
    int rc = connect(fd, addr, addr_len);
    if (rc < 0 && errno != EINPROGRESS) {
        return -1;
    }
    if (rc < 0) {
        struct pollfd poll_fd = {.fd = fd, .events = POLLOUT};
        int timeout_ms = timeout_sec > 0 ? timeout_sec * 1000 : 5000;
        do {
            rc = poll(&poll_fd, 1, timeout_ms);
        } while (rc < 0 && errno == EINTR);
        if (rc <= 0) {
            errno = rc == 0 ? ETIMEDOUT : errno;
            return -1;
        }
        int socket_error = 0;
        socklen_t socket_error_len = sizeof(socket_error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_len) < 0 || socket_error != 0) {
            errno = socket_error != 0 ? socket_error : errno;
            return -1;
        }
    }
    return fcntl(fd, F_SETFL, flags);
}

static int connect_php_fpm(const rpsiod_site_config *site) {
    int fd;
    if (rpsiod_streq_ci(site->php_handler_type, "socket")) {
        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) return -1;
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        rpsiod_safe_copy(addr.sun_path, sizeof(addr.sun_path), site->php_socket);
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(fd);
            return -1;
        }
        return fd;
    }
    char port[16];
    snprintf(port, sizeof(port), "%u", site->php_port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(site->php_host, port, &hints, &res) != 0) return -1;
    fd = -1;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect_with_timeout(fd, ai->ai_addr, ai->ai_addrlen, site->php_connect_timeout_sec) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int fcgi_write_record(int fd, uint8_t type, uint16_t request_id, const void *content, uint16_t content_len) {
    unsigned char hdr[8];
    uint8_t padding = (uint8_t)((8 - (content_len % 8)) % 8);
    hdr[0] = 1;
    hdr[1] = type;
    hdr[2] = (uint8_t)(request_id >> 8);
    hdr[3] = (uint8_t)(request_id & 0xff);
    hdr[4] = (uint8_t)(content_len >> 8);
    hdr[5] = (uint8_t)(content_len & 0xff);
    hdr[6] = padding;
    hdr[7] = 0;
    if (rpsiod_write_all(fd, hdr, sizeof(hdr)) < 0) return -1;
    if (content_len > 0 && rpsiod_write_all(fd, content, content_len) < 0) return -1;
    if (padding > 0) {
        unsigned char pad[8] = {0};
        if (rpsiod_write_all(fd, pad, padding) < 0) return -1;
    }
    return 0;
}

static int fcgi_read_exact(int fd, void *buf, size_t len) {
    unsigned char *cursor = buf;
    size_t total = 0;
    while (total < len) {
        ssize_t got = read(fd, cursor + total, len - total);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            return (errno == EAGAIN || errno == EWOULDBLOCK) ? -2 : -1;
        }
        if (got == 0) {
            return -1;
        }
        total += (size_t)got;
    }
    return 0;
}

static size_t fcgi_name_value(unsigned char *out, size_t out_len, const char *name, const char *value) {
    size_t nl = strlen(name);
    size_t vl = strlen(value);
    size_t nl_bytes = nl < 128 ? 1 : 4;
    size_t vl_bytes = vl < 128 ? 1 : 4;
    size_t need = nl + vl + nl_bytes + vl_bytes;
    if (need > out_len) return 0;
    size_t p = 0;
    if (nl < 128) {
        out[p++] = (unsigned char)nl;
    } else {
        out[p++] = (unsigned char)(0x80U | ((nl >> 24) & 0x7fU));
        out[p++] = (unsigned char)((nl >> 16) & 0xffU);
        out[p++] = (unsigned char)((nl >> 8) & 0xffU);
        out[p++] = (unsigned char)(nl & 0xffU);
    }
    if (vl < 128) {
        out[p++] = (unsigned char)vl;
    } else {
        out[p++] = (unsigned char)(0x80U | ((vl >> 24) & 0x7fU));
        out[p++] = (unsigned char)((vl >> 16) & 0xffU);
        out[p++] = (unsigned char)((vl >> 8) & 0xffU);
        out[p++] = (unsigned char)(vl & 0xffU);
    }
    memcpy(out + p, name, nl);
    p += nl;
    memcpy(out + p, value, vl);
    return need;
}

static int fcgi_add_param(unsigned char *buf, size_t buf_len, size_t *used, const char *name, const char *value) {
    size_t n = fcgi_name_value(buf + *used, buf_len - *used, name, value != NULL ? value : "");
    if (n == 0) return -1;
    *used += n;
    return 0;
}

static int send_php_fpm(client_object *client, rpsiod_site_config *site, rpsiod_logger *logger,
                        const rpsiod_http_request *req, const char *script_rel,
                        const unsigned char *request_body, size_t request_body_len) {
    int fpm = connect_php_fpm(site);
    if (fpm < 0) {
        return send_error_page(client, site, 502, req, logger);
    }
    struct timeval tv;
    tv.tv_sec = site->php_read_timeout_sec;
    tv.tv_usec = 0;
    (void)setsockopt(fpm, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    tv.tv_sec = site->php_write_timeout_sec;
    (void)setsockopt(fpm, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    unsigned char begin[8] = {0, 1, 0, 0, 0, 0, 0, 0};
    if (fcgi_write_record(fpm, 1, 1, begin, sizeof(begin)) < 0) {
        close(fpm);
        return send_error_page(client, site, 502, req, logger);
    }
    char clean_script[PATH_MAX];
    rpsiod_safe_copy(clean_script, sizeof(clean_script), script_rel);
    char *query_in_script = strchr(clean_script, '?');
    if (query_in_script != NULL) {
        *query_in_script = '\0';
    }
    char script_filename[PATH_MAX];
    if (snprintf(script_filename, sizeof(script_filename), "%s/%s", site->static_root_real, clean_script) >=
        (int)sizeof(script_filename)) {
        close(fpm);
        return send_error_page(client, site, 414, req, logger);
    }
    char script_name[PATH_MAX];
    if (snprintf(script_name, sizeof(script_name), "/%s", clean_script) >= (int)sizeof(script_name)) {
        close(fpm);
        return send_error_page(client, site, 414, req, logger);
    }
    char request_content_length[32];
    snprintf(request_content_length, sizeof(request_content_length), "%llu", req->content_length);
    bool trusted_internal_https = req->internal_https &&
                                  (strcmp(client->client_ip, "127.0.0.1") == 0 || strcmp(client->client_ip, "::1") == 0);
    bool request_https = client->local_port == site->https_port || trusted_internal_https;
    char server_port[16];
    snprintf(server_port, sizeof(server_port), "%u", request_https && site->https_port != 0 ? site->https_port : client->local_port);
    unsigned char params[8192];
    size_t used = 0;
    if (fcgi_add_param(params, sizeof(params), &used, "GATEWAY_INTERFACE", "CGI/1.1") < 0 ||
        fcgi_add_param(params, sizeof(params), &used, "SERVER_SOFTWARE", "rpsiod") < 0 ||
        fcgi_add_param(params, sizeof(params), &used, "REQUEST_METHOD", req->method) < 0 ||
        fcgi_add_param(params, sizeof(params), &used, "QUERY_STRING", req->query_string) < 0 ||
        fcgi_add_param(params, sizeof(params), &used, "REQUEST_URI", req->path) < 0 ||
        fcgi_add_param(params, sizeof(params), &used, "SCRIPT_FILENAME", script_filename) < 0 ||
        fcgi_add_param(params, sizeof(params), &used, "SCRIPT_NAME", script_name) < 0 ||
        fcgi_add_param(params, sizeof(params), &used, "DOCUMENT_ROOT", site->static_root_real) < 0 ||
        fcgi_add_param(params, sizeof(params), &used, "SERVER_PROTOCOL", "HTTP/1.1") < 0 ||
        fcgi_add_param(params, sizeof(params), &used, "REMOTE_ADDR", client->client_ip) < 0 ||
        fcgi_add_param(params, sizeof(params), &used, "SERVER_ADDR", client->server_ip) < 0 ||
        fcgi_add_param(params, sizeof(params), &used, "SERVER_NAME", req->host) < 0 ||
        fcgi_add_param(params, sizeof(params), &used, "HTTP_HOST", req->host) < 0 ||
        fcgi_add_param(params, sizeof(params), &used, "SERVER_PORT", server_port) < 0 ||
        fcgi_add_param(params, sizeof(params), &used, "REQUEST_SCHEME", request_https ? "https" : "http") < 0 ||
        fcgi_add_param(params, sizeof(params), &used, "HTTPS", request_https ? "on" : "off") < 0 ||
        fcgi_add_param(params, sizeof(params), &used, "CONTENT_LENGTH", request_content_length) < 0) {
        close(fpm);
        return send_error_page(client, site, 500, req, logger);
    }
    if (fcgi_write_record(fpm, 4, 1, params, (uint16_t)used) < 0 ||
        fcgi_write_record(fpm, 4, 1, NULL, 0) < 0) {
        close(fpm);
        return send_error_page(client, site, 502, req, logger);
    }
    if (request_body_len > UINT16_MAX) {
        close(fpm);
        return send_error_page(client, site, 413, req, logger);
    }
    if (request_body_len > 0 && fcgi_write_record(fpm, 5, 1, request_body, (uint16_t)request_body_len) < 0) {
        close(fpm);
        return send_error_page(client, site, 502, req, logger);
    }
    if (fcgi_write_record(fpm, 5, 1, NULL, 0) < 0) {
        close(fpm);
        return send_error_page(client, site, 502, req, logger);
    }

    unsigned char header_buffer[65536];
    size_t header_buffer_used = 0;
    bool response_started = false;
    bool chunked_response = false;
    int status = 200;
    off_t content_length = -1;
    const char *content_type = "text/html; charset=utf-8";
    unsigned long long bytes_streamed = 0;
    int stream_rc = 0;
    for (;;) {
        unsigned char hdr[8];
        int header_read = fcgi_read_exact(fpm, hdr, sizeof(hdr));
        if (header_read < 0) {
            close(fpm);
            return send_error_page(client, site, header_read == -2 ? 504 : 502, req, logger);
        }
        uint8_t type = hdr[1];
        uint16_t clen = (uint16_t)((hdr[4] << 8) | hdr[5]);
        uint8_t padding = hdr[6];
        unsigned char tmp[65536];
        int content_read = clen > 0 ? fcgi_read_exact(fpm, tmp, clen) : 0;
        if (content_read < 0) {
            close(fpm);
            return send_error_page(client, site, content_read == -2 ? 504 : 502, req, logger);
        }
        if (padding > 0) {
            unsigned char pad[256];
            int padding_read = fcgi_read_exact(fpm, pad, padding);
            if (padding_read < 0) {
                close(fpm);
                return send_error_page(client, site, padding_read == -2 ? 504 : 502, req, logger);
            }
        }
        if (type == 6 && clen > 0) {
            if (!response_started) {
                if ((size_t)clen > sizeof(header_buffer) - header_buffer_used) {
                    close(fpm);
                    return send_error_page(client, site, 502, req, logger);
                }
                memcpy(header_buffer + header_buffer_used, tmp, clen);
                header_buffer_used += clen;

                char *separator = memmem(header_buffer, header_buffer_used, "\r\n\r\n", 4);
                if (separator == NULL) {
                    continue;
                }

                size_t header_bytes = (size_t)((unsigned char *)separator - header_buffer);
                char *headers_for_parse = strndup((char *)header_buffer, header_bytes);
                char *headers_for_client = strndup((char *)header_buffer, header_bytes);
                if (headers_for_parse == NULL || headers_for_client == NULL) {
                    free(headers_for_parse);
                    free(headers_for_client);
                    close(fpm);
                    return send_error_page(client, site, 500, req, logger);
                }
                char content_type_storage[256];
                rpsiod_safe_copy(content_type_storage, sizeof(content_type_storage), content_type);
                char *save = NULL;
                for (char *line = strtok_r(headers_for_parse, "\r\n", &save); line != NULL; line = strtok_r(NULL, "\r\n", &save)) {
                    if (rpsiod_starts_with(line, "Status:")) {
                        status = atoi(line + 7);
                    } else if (rpsiod_starts_with(line, "Content-Type:")) {
                        const char *value = line + 13;
                        while (*value == ' ') value++;
                        rpsiod_safe_copy(content_type_storage, sizeof(content_type_storage), value);
                    } else if (rpsiod_starts_with(line, "Content-Length:")) {
                        const char *value = line + 15;
                        while (*value == ' ') value++;
                        char *end = NULL;
                        errno = 0;
                        unsigned long long parsed_length = strtoull(value, &end, 10);
                        while (end != NULL && (*end == ' ' || *end == '\t')) end++;
                        if (end != value && end != NULL && *end == '\0' && errno != ERANGE && parsed_length <= LLONG_MAX) {
                            content_length = (off_t)parsed_length;
                        }
                    }
                }
                content_type = content_type_storage;
                chunked_response = content_length < 0 && !req->head_only;
                stream_rc = write_php_response_headers(client, site, status, content_type, content_length, req->keep_alive,
                                                       headers_for_client, chunked_response);
                free(headers_for_parse);
                free(headers_for_client);
                if (stream_rc < 0) {
                    close(fpm);
                    return -1;
                }
                response_started = true;

                unsigned char *body_start = (unsigned char *)separator + 4;
                size_t body_size = header_buffer_used - header_bytes - 4;
                if (body_size > 0) {
                    bytes_streamed += (unsigned long long)body_size;
                    if (!req->head_only) {
                        stream_rc = chunked_response ?
                            client_write_chunked_body(client, body_start, body_size) :
                            client_write_all(client, body_start, body_size);
                        if (stream_rc < 0) {
                            close(fpm);
                            return -1;
                        }
                    }
                }
            } else {
                bytes_streamed += (unsigned long long)clen;
                if (!req->head_only) {
                    stream_rc = chunked_response ?
                        client_write_chunked_body(client, tmp, clen) :
                        client_write_all(client, tmp, clen);
                    if (stream_rc < 0) {
                        close(fpm);
                        return -1;
                    }
                }
            }
        } else if (type == 3) {
            break;
        }
    }
    close(fpm);

    if (!response_started) {
        content_length = (off_t)header_buffer_used;
        stream_rc = write_php_response_headers(client, site, status, content_type, content_length, req->keep_alive, NULL, false);
        if (stream_rc == 0 && !req->head_only && header_buffer_used > 0) {
            stream_rc = client_write_all(client, header_buffer, header_buffer_used);
        }
        bytes_streamed = (unsigned long long)header_buffer_used;
    } else if (chunked_response && !req->head_only) {
        stream_rc = client_write_chunked_end(client);
    }
    rpsiod_log_access(logger, site, client->client_ip, req->method, req->path, status, bytes_streamed);
    return stream_rc;
}

static int send_redirect(client_object *client, const rpsiod_site_config *site, int status, const char *location, const rpsiod_http_request *req, rpsiod_logger *logger) {
    char body[1024];
    int body_len = snprintf(body, sizeof(body), "%d %s\n%s\n", status, rpsiod_http_status_text(status), location);
    if (body_len < 0 || (size_t)body_len >= sizeof(body)) {
        return -1;
    }
    response_options opts = {.site = site, .location = location, .cache_control = false};
    if (write_response_headers(client, status, "text/plain; charset=utf-8", (off_t)body_len, req->keep_alive, &opts) < 0) {
        return -1;
    }
    struct iovec body_iov = {.iov_base = body, .iov_len = (size_t)body_len};
    if (!req->head_only && client_writev_all(client, &body_iov, 1) < 0) {
        return -1;
    }
    rpsiod_log_access(logger, site, client->client_ip, req->method, req->path, status, (unsigned long long)body_len);
    return 0;
}

static bool request_path_has_trailing_slash(const char *path) {
    const char *query = strchr(path, '?');
    size_t len = query != NULL ? (size_t)(query - path) : strlen(path);
    return len > 0 && path[len - 1] == '/';
}

static bool site_path_is_directory(const rpsiod_site_config *site, const char *decoded_path) {
    int fd = rpsiod_static_open_site_path(site, rpsiod_static_relative_request_path(decoded_path));
    if (fd < 0) {
        return false;
    }
    struct stat st;
    bool is_dir = fstat(fd, &st) == 0 && S_ISDIR(st.st_mode);
    close(fd);
    return is_dir;
}

static int redirect_directory_slash(client_object *client, rpsiod_site_config *site, const rpsiod_http_request *req, rpsiod_logger *logger) {
    char location[RPSIOD_PATH_LEN + 2];
    const char *query = strchr(req->path, '?');
    size_t path_len = query != NULL ? (size_t)(query - req->path) : strlen(req->path);
    if (path_len + 1 >= sizeof(location)) {
        return send_error_page(client, site, 414, req, logger);
    }
    memcpy(location, req->path, path_len);
    location[path_len++] = '/';
    if (query != NULL) {
        size_t query_len = strlen(query);
        if (path_len + query_len >= sizeof(location)) {
            return send_error_page(client, site, 414, req, logger);
        }
        memcpy(location + path_len, query, query_len + 1);
    } else {
        location[path_len] = '\0';
    }
    return send_redirect(client, site, 301, location, req, logger);
}

static int send_rate_limited(client_object *client, const rpsiod_site_config *site, int retry_after, const rpsiod_http_request *req, rpsiod_logger *logger) {
    char retry[32];
    snprintf(retry, sizeof(retry), "%d", retry_after > 0 ? retry_after : 1);
    const char *body = "429 Too Many Requests\n";
    response_options opts = {.site = site, .retry_after = retry, .cache_control = false};
    size_t len = strlen(body);
    if (write_response_headers(client, 429, "text/plain; charset=utf-8", (off_t)len, req->keep_alive, &opts) < 0) {
        return -1;
    }
    struct iovec body_iov = {.iov_base = (void *)body, .iov_len = len};
    if (!req->head_only && client_writev_all(client, &body_iov, 1) < 0) {
        return -1;
    }
    rpsiod_log_access(logger, site, client->client_ip, req->method, req->path, 429, (unsigned long long)len);
    return 0;
}

static int serve_static(client_object *client, rpsiod_config *cfg, rpsiod_site_config *site, rpsiod_logger *logger,
                        const rpsiod_http_request *req, const unsigned char *request_body, size_t request_body_len) {
    if (site->maintenance_enabled) {
        if (site->maintenance_page[0] != '\0') {
            int fd = open(site->maintenance_page, O_RDONLY | O_CLOEXEC);
            if (fd >= 0) {
                struct stat st;
                if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
                    int rc = send_file_fd(client, site, site->maintenance_status, site->maintenance_page, fd, &st, NULL, req, logger);
                    close(fd);
                    return rc;
                }
                close(fd);
            }
        }
        return send_error_page(client, site, site->maintenance_status, req, logger);
    }

    if (!rpsiod_site_allows_method(site, req->method)) {
        return send_error_page(client, site, 405, req, logger);
    }

    char decoded[RPSIOD_PATH_LEN];
    if (rpsiod_percent_decode_path(req->path, decoded, sizeof(decoded)) < 0 || rpsiod_path_has_forbidden_segment(decoded)) {
        return send_error_page(client, site, 400, req, logger);
    }
    if (rpsiod_blocked_direct_access(site, decoded)) {
        return send_error_page(client, site, 403, req, logger);
    }
    if (!request_path_has_trailing_slash(req->path) && site_path_is_directory(site, decoded)) {
        return redirect_directory_slash(client, site, req, logger);
    }

    bool php_routing = rpsiod_streq_ci(site->routing_type, "php");
    if (php_routing) {
        char php_target[RPSIOD_PATH_LEN];
        if (rpsiod_php_path_is_php(decoded)) {
            rpsiod_safe_copy(php_target, sizeof(php_target), decoded);
        } else if (site->fallback[0] != '\0') {
            rpsiod_safe_copy(php_target, sizeof(php_target), site->fallback);
        } else {
            rpsiod_safe_copy(php_target, sizeof(php_target), "/index.php");
        }
        char selected[PATH_MAX];
        struct stat st;
        int fd = try_open_static(cfg, site, php_target, selected, sizeof(selected), &st);
        if (fd < 0) {
            if (errno == EACCES || errno == EISDIR) {
                return send_error_page(client, site, 403, req, logger);
            }
            return send_error_page(client, site, 404, req, logger);
        }
        if (selected_path_blocked_direct_access(site, selected)) {
            close(fd);
            return send_error_page(client, site, 403, req, logger);
        }
        trace_stage(client, logger, site, req, "file-opened", "file=%s size=%lld php=true", selected, (long long)st.st_size);
        close(fd);
        if (!rpsiod_php_path_is_php(selected)) {
            return send_error_page(client, site, 403, req, logger);
        }
        if (req->content_length > site->php_max_body_size) {
            return send_error_page(client, site, 413, req, logger);
        }
        return send_php_fpm(client, site, logger, req, selected, request_body, request_body_len);
    }

    char selected[PATH_MAX];
    struct stat st;
    int fd = try_open_static(cfg, site, decoded, selected, sizeof(selected), &st);
    if (fd < 0 && site->fallback[0] != '\0' && errno == ENOENT && strcmp(decoded, "/") != 0) {
        fd = try_open_static(cfg, site, site->fallback, selected, sizeof(selected), &st);
    }
    if (fd < 0) {
        if (errno == EACCES || errno == EISDIR) {
            return send_error_page(client, site, 403, req, logger);
        }
        return send_error_page(client, site, 404, req, logger);
    }
    if (selected_path_blocked_direct_access(site, selected)) {
        close(fd);
        return send_error_page(client, site, 403, req, logger);
    }
    trace_stage(client, logger, site, req, "file-opened", "file=%s size=%lld", selected, (long long)st.st_size);
    if (site->php_enabled && rpsiod_php_path_is_php(selected)) {
        close(fd);
        if (req->content_length > site->php_max_body_size) {
            return send_error_page(client, site, 413, req, logger);
        }
        return send_php_fpm(client, site, logger, req, selected, request_body, request_body_len);
    }
    if (!rpsiod_streq_ci(req->method, "GET") && !rpsiod_streq_ci(req->method, "HEAD")) {
        close(fd);
        return send_error_page(client, site, 405, req, logger);
    }
    if (rpsiod_php_path_is_source_like(selected)) {
        close(fd);
        return send_error_page(client, site, 403, req, logger);
    }
    rpsiod_static_meta_cache_entry *meta = static_meta_get(site, selected, fd, &st);
    if (meta->blocked) {
        close(fd);
        return send_error_page(client, site, 403, req, logger);
    }
    int rc = send_file_fd(client, site, 200, selected, fd, &st, meta, req, logger);
    close(fd);
    return rc;
}

static int build_proxy_request(char *out, size_t out_len, const client_object *client, const rpsiod_site_config *site,
                               const rpsiod_http_request *req, const char *raw, size_t raw_len,
                               const unsigned char *body, size_t body_len) {
    size_t used = 0;
    int n = snprintf(out, out_len, "%s %s HTTP/1.1\r\n", req->method, req->path);
    if (n < 0 || (size_t)n >= out_len) return -1;
    used = (size_t)n;
    const char *host = site->proxy_pass_host && req->host[0] != '\0' ? req->host : site->proxy_host;
    if (append_header(out, out_len, &used, "Host", host) < 0) return -1;
    if (append_header(out, out_len, &used, "Connection", req->upgrade_websocket && site->proxy_websocket ? "Upgrade" : "close") < 0) return -1;

    const char *headers_start = memmem(raw, raw_len, "\r\n", 2);
    if (headers_start == NULL || req->header_len < 4 || req->header_len > raw_len) {
        return -1;
    }
    const char *headers_end = raw + req->header_len - 4;
    const char *p = headers_start + 2;
    while (p < headers_end) {
        const char *next = memmem(p, (size_t)(headers_end - p), "\r\n", 2);
        if (next == NULL) {
            break;
        }
        size_t line_len = (size_t)(next - p);
        if (line_len > 0 && !rpsiod_proxy_skip_header(p, line_len)) {
            if (used + line_len + 2 >= out_len) return -1;
            memcpy(out + used, p, line_len);
            used += line_len;
            out[used++] = '\r';
            out[used++] = '\n';
        }
        p = next + 2;
    }
    if (site->proxy_real_ip && append_header(out, out_len, &used, "X-Real-IP", client->client_ip) < 0) return -1;
    if (site->proxy_forwarded_for && append_header(out, out_len, &used, "X-Forwarded-For", client->client_ip) < 0) return -1;
    if (site->proxy_forwarded_proto && append_header(out, out_len, &used, "X-Forwarded-Proto", client->local_port == site->https_port ? "https" : "http") < 0) return -1;
    if (used + 2 + body_len >= out_len) return -1;
    out[used++] = '\r';
    out[used++] = '\n';
    if (body_len > 0) {
        memcpy(out + used, body, body_len);
        used += body_len;
    }
    return (int)used;
}

static int websocket_tunnel(client_object *client, int upstream) {
    char buf[16384];
    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(client->fd, &rfds);
        FD_SET(upstream, &rfds);
        int maxfd = client->fd > upstream ? client->fd : upstream;
        int rc = select(maxfd + 1, &rfds, NULL, NULL, NULL);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (FD_ISSET(client->fd, &rfds)) {
            ssize_t n = client_read(client, buf, sizeof(buf));
            if (n <= 0) return 0;
            if (rpsiod_write_all(upstream, buf, (size_t)n) < 0) return -1;
        }
        if (FD_ISSET(upstream, &rfds)) {
            ssize_t n = read(upstream, buf, sizeof(buf));
            if (n <= 0) return 0;
            if (client_write_all(client, buf, (size_t)n) < 0) return -1;
        }
    }
}

static bool parse_proxy_status_line(const char *buf, size_t len, int *status_out) {
    const char *line_end = memmem(buf, len, "\r\n", 2);
    size_t line_len = line_end != NULL ? (size_t)(line_end - buf) : len;
    if (line_len < 12 || strncmp(buf, "HTTP/", 5) != 0) {
        return false;
    }
    const char *space = memchr(buf, ' ', line_len);
    if (space == NULL) {
        return false;
    }
    size_t status_offset = (size_t)(space + 1 - buf);
    if (status_offset + 3 > line_len) {
        return false;
    }
    const char *digits = space + 1;
    if (digits[0] < '1' || digits[0] > '5' ||
        digits[1] < '0' || digits[1] > '9' ||
        digits[2] < '0' || digits[2] > '9' ||
        (status_offset + 3 < line_len && digits[3] != ' ')) {
        return false;
    }
    *status_out = (digits[0] - '0') * 100 + (digits[1] - '0') * 10 + (digits[2] - '0');
    return true;
}

static int serve_proxy(client_object *client, rpsiod_site_config *site, rpsiod_logger *logger,
                       const rpsiod_http_request *req, const unsigned char *request_body, size_t request_body_len) {
    int upstream = rpsiod_proxy_connect(site);
    if (upstream < 0) {
        return send_error_page(client, site, 502, req, logger);
    }
    size_t proxy_capacity = req->header_len + request_body_len + 4096;
    char *proxy_req = malloc(proxy_capacity);
    if (proxy_req == NULL) {
        close(upstream);
        return send_error_page(client, site, 500, req, logger);
    }
    int proxy_len = build_proxy_request(proxy_req, proxy_capacity, client, site, req,
                                        client->buf, client->used, request_body, request_body_len);
    if (proxy_len < 0 || rpsiod_write_all(upstream, proxy_req, (size_t)proxy_len) < 0) {
        free(proxy_req);
        close(upstream);
        return send_error_page(client, site, 502, req, logger);
    }
    free(proxy_req);

    char buf[65536];
    char first_response[8192];
    size_t first_response_len = 0;
    bool first = true;
    bool tunnel = req->upgrade_websocket && site->proxy_websocket;
    int status = 502;
    unsigned long long bytes = 0;
    for (;;) {
        ssize_t n = read(upstream, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(upstream);
            return send_error_page(client, site, errno == EAGAIN || errno == EWOULDBLOCK ? 504 : 502, req, logger);
        }
        if (n == 0) {
            break;
        }
        if (first) {
            if ((size_t)n > sizeof(first_response) - first_response_len) {
                close(upstream);
                return send_error_page(client, site, 502, req, logger);
            }
            memcpy(first_response + first_response_len, buf, (size_t)n);
            first_response_len += (size_t)n;
            if (memmem(first_response, first_response_len, "\r\n", 2) == NULL) {
                continue;
            }
            if (!parse_proxy_status_line(first_response, first_response_len, &status)) {
                close(upstream);
                return send_error_page(client, site, 502, req, logger);
            }
            if (client_write_all(client, first_response, first_response_len) < 0) {
                close(upstream);
                return -1;
            }
            bytes += (unsigned long long)first_response_len;
            first = false;
            if (tunnel && status == 101) {
                (void)websocket_tunnel(client, upstream);
                close(upstream);
                rpsiod_log_access(logger, site, client->client_ip, req->method, req->path, status, bytes);
                return 0;
            }
            continue;
        }
        if (client_write_all(client, buf, (size_t)n) < 0) {
            close(upstream);
            return -1;
        }
        bytes += (unsigned long long)n;
        if (tunnel && status == 101) {
            (void)websocket_tunnel(client, upstream);
            close(upstream);
            rpsiod_log_access(logger, site, client->client_ip, req->method, req->path, status, bytes);
            return 0;
        }
    }
    if (first) {
        close(upstream);
        return send_error_page(client, site, 502, req, logger);
    }
    close(upstream);
    rpsiod_log_access(logger, site, client->client_ip, req->method, req->path, status, bytes);
    return 0;
}

static int serve_request(client_object *client, rpsiod_config *cfg, rpsiod_logger *logger,
                         const rpsiod_http_request *req, const unsigned char *request_body, size_t request_body_len) {
    if (rpsiod_streq_ci(req->method, "TRACE") || rpsiod_streq_ci(req->method, "CONNECT")) {
        return send_text(client, NULL, 405, "405 Method Not Allowed\n", req, logger);
    }
    rpsiod_site_config *site = rpsiod_config_find_site_for_listener(cfg, req->host, client->local_port, client->server_ip);
    if (site == NULL) {
        trace_stage(client, logger, NULL, req, "route-matched", "site=- status=404");
        return send_text(client, NULL, 404, "404 Not Found\n", req, logger);
    }
    trace_stage(client, logger, site, req, "route-matched", "site=%s routing=%s", site->name, site->routing_type);
    if (strcmp(site->listen_ip, "0.0.0.0") != 0 && strcmp(site->listen_ip, client->server_ip) != 0) {
        return send_text(client, site, 400, "400 Bad Request\n", req, logger);
    }
    char location[1024];
    int redirect_status = 301;
    bool trusted_internal_https = req->internal_https &&
                                  (strcmp(client->client_ip, "127.0.0.1") == 0 || strcmp(client->client_ip, "::1") == 0);
    if (rpsiod_route_build_redirect_location(site, req, client->local_port, trusted_internal_https, location, sizeof(location), &redirect_status)) {
        return send_redirect(client, site, redirect_status, location, req, logger);
    }
    int retry_after = 0;
    if (rpsiod_rate_limit_exceeded(site, client->client_ip, &retry_after)) {
        return send_rate_limited(client, site, retry_after, req, logger);
    }
    if (rpsiod_streq_ci(site->routing_type, "proxy")) {
        if (!rpsiod_site_allows_method(site, req->method)) {
            return send_error_page(client, site, 405, req, logger);
        }
        return serve_proxy(client, site, logger, req, request_body, request_body_len);
    }
    return serve_static(client, cfg, site, logger, req, request_body, request_body_len);
}

static void close_client(int epfd, client_object **clients_head, client_object *client) {
    (void)epoll_ctl(epfd, EPOLL_CTL_DEL, client->fd, NULL);
    if (clients_head != NULL) {
        client_list_remove(clients_head, client);
    }
    if (client->ssl != NULL) {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
    }
    close(client->fd);
    rpsiod_perf_inc(&rpsiod_perf.closed_connections);
    if (rpsiod_perf_get(&rpsiod_perf.active_connections) > 0) {
        atomic_fetch_sub_explicit(&rpsiod_perf.active_connections, 1, memory_order_relaxed);
    }
    free(client);
}

static void discard_accepted_client(client_object *client) {
    if (client == NULL) {
        return;
    }
    if (client->ssl != NULL) {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
    }
    close(client->fd);
    rpsiod_perf_inc(&rpsiod_perf.closed_connections);
    if (rpsiod_perf_get(&rpsiod_perf.active_connections) > 0) {
        atomic_fetch_sub_explicit(&rpsiod_perf.active_connections, 1, memory_order_relaxed);
    }
    free(client);
}

static bool buffered_request_ready(const client_object *client) {
    if (client->used == 0) {
        return false;
    }
    rpsiod_http_request req;
    int parsed = rpsiod_http_parse_request(client->buf, client->used, &req);
    if (parsed < 0) {
        return true;
    }
    if (parsed == 0) {
        return false;
    }
    size_t body_have = client->used > req.header_len ? client->used - req.header_len : 0;
    return body_have >= req.content_length;
}

static bool timespec_elapsed_sec(const struct timespec *start, const struct timespec *now, int seconds) {
    if (seconds <= 0 || start->tv_sec == 0) {
        return false;
    }
    time_t sec = now->tv_sec - start->tv_sec;
    long nsec = now->tv_nsec - start->tv_nsec;
    if (nsec < 0) {
        sec--;
    }
    return sec >= seconds;
}

static void sweep_idle_keep_alive_clients(int epfd, client_object **clients_head, const rpsiod_config *cfg) {
    if (!cfg->keep_alive_enabled || cfg->keep_alive_timeout_sec <= 0) {
        return;
    }
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
        return;
    }
    client_object *client = *clients_head;
    while (client != NULL) {
        client_object *next = client->next;
        if (client->idle_keep_alive && client->used == 0 &&
            timespec_elapsed_sec(&client->last_active_mono, &now, cfg->keep_alive_timeout_sec)) {
            close_client(epfd, clients_head, client);
        }
        client = next;
    }
}

static void handle_client_event(int epfd, client_object **clients_head, client_object *client, rpsiod_config *cfg, rpsiod_logger *logger) {
    for (;;) {
        if (!buffered_request_ready(client)) {
            ssize_t n = client_read(client, client->buf + client->used, sizeof(client->buf) - client->used);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return;
                }
                close_client(epfd, clients_head, client);
                return;
            }
            if (n == 0) {
                close_client(epfd, clients_head, client);
                return;
            }
            client->used += (size_t)n;
            if (client->used == sizeof(client->buf)) {
                rpsiod_http_request req;
                memset(&req, 0, sizeof(req));
                rpsiod_safe_copy(req.method, sizeof(req.method), "GET");
                rpsiod_safe_copy(req.path, sizeof(req.path), "-");
                mark_request_start(client);
                (void)send_text(client, NULL, 400, "400 Bad Request\n", &req, logger);
                close_client(epfd, clients_head, client);
                return;
            }
        }
        rpsiod_http_request req;
        int parsed = rpsiod_http_parse_request(client->buf, client->used, &req);
        if (parsed == 0) {
            continue;
        }
        rpsiod_site_config *request_site = parsed > 0 ? rpsiod_config_find_site_for_listener(cfg, req.host, client->local_port, client->server_ip) : NULL;
        if (parsed > 0 && request_site != NULL && req.content_length > request_site->max_body_size) {
            (void)set_blocking(client->fd);
            req.keep_alive = false;
            mark_request_start(client);
            (void)send_error_page(client, request_site, 413, &req, logger);
            close_client(epfd, clients_head, client);
            return;
        }
        if (parsed > 0 && req.content_length > 0) {
            size_t body_have = client->used > req.header_len ? client->used - req.header_len : 0;
            if (body_have < req.content_length) {
                if (req.content_length > sizeof(client->buf) - req.header_len) {
                    (void)set_blocking(client->fd);
                    req.keep_alive = false;
                    mark_request_start(client);
                    (void)send_error_page(client, request_site, 413, &req, logger);
                    close_client(epfd, clients_head, client);
                    return;
                }
                continue;
            }
        }
        bool should_keep_alive = parsed > 0 && cfg->keep_alive_enabled && req.keep_alive &&
                                 client->keep_alive_requests + 1U < (unsigned)cfg->keep_alive_max_requests &&
                                 !(request_site != NULL && rpsiod_streq_ci(request_site->routing_type, "proxy"));
        if (!should_keep_alive) {
            req.keep_alive = false;
        }
        (void)set_blocking(client->fd);
        if (parsed < 0) {
            rpsiod_safe_copy(req.method, sizeof(req.method), "GET");
            rpsiod_safe_copy(req.path, sizeof(req.path), "-");
            mark_request_start(client);
            (void)send_text(client, NULL, 400, "400 Bad Request\n", &req, logger);
        } else {
            mark_request_start(client);
            trace_absolute_time(client, logger, request_site, &req, "accepted", &client->accepted_real);
            trace_stage(client, logger, request_site, &req, "parsed", "header_bytes=%zu content_length=%llu keep_alive=%s",
                        req.header_len,
                        req.content_length,
                        req.keep_alive ? "true" : "false");
            if (client->keep_alive_requests > 0) {
                rpsiod_perf_inc(&rpsiod_perf.keep_alive_reused_requests);
            }
            const unsigned char *request_body = (const unsigned char *)client->buf + req.header_len;
            size_t request_body_len = (size_t)req.content_length;
            int handler_rc = serve_request(client, cfg, logger, &req, request_body, request_body_len);
            if (handler_rc != 0) {
                req.keep_alive = false;
                should_keep_alive = false;
            }
        }
        if (should_keep_alive && parsed > 0) {
            size_t consumed = req.header_len + (size_t)req.content_length;
            if (consumed < client->used) {
                memmove(client->buf, client->buf + consumed, client->used - consumed);
                client->used -= consumed;
            } else {
                client->used = 0;
            }
            client->keep_alive_requests++;
            client->idle_keep_alive = true;
            (void)clock_gettime(CLOCK_MONOTONIC, &client->last_active_mono);
            trace_stage(client, logger, request_site, &req, "connection-reused", "completed_requests=%u", client->keep_alive_requests);
            if (buffered_request_ready(client)) {
                continue;
            }
            if (client->used > 0) {
                if (rpsiod_set_nonblocking(client->fd) == 0) {
                    return;
                }
            }
            if (rpsiod_set_nonblocking(client->fd) == 0) {
                return;
            }
        }
        trace_stage(client, logger, request_site, &req, "connection-closed", "total_ms=%.3f", elapsed_request_subms(client));
        close_client(epfd, clients_head, client);
        return;
    }
}

static int create_listener(const char *ip, uint16_t port, const rpsiod_config *cfg, char *err, size_t err_len) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        snprintf(err, err_len, "socket failed: %s", strerror(errno));
        return -1;
    }
    int yes = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_REUSEPORT
    if (cfg->reuse_port) {
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
    }
#endif
#ifdef TCP_FASTOPEN
    if (cfg->tcp_fast_open) {
        int qlen = cfg->backlog;
        (void)setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen));
    }
#endif
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(fd);
        snprintf(err, err_len, "invalid listen IP %s", ip);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        snprintf(err, err_len, "bind %s:%u failed: %s", ip, port, strerror(errno));
        close(fd);
        return -1;
    }
    if (listen(fd, cfg->backlog) < 0) {
        snprintf(err, err_len, "listen %s:%u failed: %s", ip, port, strerror(errno));
        close(fd);
        return -1;
    }
    if (rpsiod_set_nonblocking(fd) < 0) {
        snprintf(err, err_len, "nonblocking listen socket failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static bool listener_exists(listener_object *listeners, size_t count, const char *ip, uint16_t port, const rpsiod_config *cfg) {
    (void)cfg;
    for (size_t i = 0; i < count; i++) {
        if (listeners[i].port == port && strcmp(listeners[i].ip, ip) == 0) {
            return true;
        }
    }
    return false;
}

static int add_one_listener(int epfd, rpsiod_config *cfg, listener_object *listeners, size_t *listener_count, const char *ip, uint16_t port, bool tls, SSL_CTX *tls_ctx, char *err, size_t err_len) {
    if (listener_exists(listeners, *listener_count, ip, port, cfg)) {
        return 0;
    }
    if (*listener_count >= RPSIOD_MAX_LISTENERS) {
        snprintf(err, err_len, "too many listeners");
        return -1;
    }
    int fd = create_listener(ip, port, cfg, err, err_len);
    if (fd < 0) {
        return -1;
    }
    listener_object *listener = &listeners[*listener_count];
    listener->kind = OBJ_LISTENER;
    listener->fd = fd;
    rpsiod_safe_copy(listener->ip, sizeof(listener->ip), ip);
    listener->port = port;
    listener->tls = tls;
    listener->tls_ctx = tls_ctx;
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.ptr = listener;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        snprintf(err, err_len, "epoll add listener failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    (*listener_count)++;
    return 0;
}

static int add_listeners(int epfd, rpsiod_config *cfg, listener_object *listeners, size_t *listener_count, SSL_CTX *tls_ctx, char *err, size_t err_len) {
    for (size_t i = 0; i < cfg->site_count; i++) {
        rpsiod_site_config *site = &cfg->sites[i];
        if (!site->enabled) {
            continue;
        }
        if (site->http_port != 0 && add_one_listener(epfd, cfg, listeners, listener_count, site->listen_ip, site->http_port, false, NULL, err, err_len) < 0) {
            return -1;
        }
        if (site->ssl_enabled && site->https_port != 0) {
            if (tls_ctx == NULL) {
                snprintf(err, err_len, "TLS is enabled but no valid TLS context is available");
                return -1;
            }
            if (add_one_listener(epfd, cfg, listeners, listener_count, site->listen_ip, site->https_port, true, tls_ctx, err, err_len) < 0) {
                return -1;
            }
        }
    }
    return 0;
}

static void accept_clients(int epfd, listener_object *listener, client_object **clients_head, rpsiod_config *cfg, rpsiod_logger *logger) {
    for (;;) {
        struct sockaddr_storage ss;
        socklen_t slen = sizeof(ss);
        int fd = accept4(listener->fd, (struct sockaddr *)&ss, &slen, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            rpsiod_log_error(logger, NULL, "accept failed: %s", strerror(errno));
            return;
        }
        client_object *client = calloc(1, sizeof(*client));
        if (client == NULL) {
            close(fd);
            return;
        }
        client->kind = OBJ_CLIENT;
        client->fd = fd;
        client->local_port = listener->port;
        client->tls = listener->tls;
        client->sendfile_enabled = cfg->sendfile_enabled;
        int one = 1;
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        rpsiod_perf_inc(&rpsiod_perf.accepted_connections);
        rpsiod_perf_inc(&rpsiod_perf.active_connections);
        perf_note_active_connection();
        mark_request_start(client);
        (void)clock_gettime(CLOCK_REALTIME, &client->accepted_real);
        if (ss.ss_family == AF_INET) {
            struct sockaddr_in *in = (struct sockaddr_in *)&ss;
            inet_ntop(AF_INET, &in->sin_addr, client->client_ip, sizeof(client->client_ip));
        } else {
            rpsiod_safe_copy(client->client_ip, sizeof(client->client_ip), "-");
        }
        struct sockaddr_storage local_ss;
        socklen_t local_len = sizeof(local_ss);
        if (getsockname(fd, (struct sockaddr *)&local_ss, &local_len) == 0 && local_ss.ss_family == AF_INET) {
            struct sockaddr_in *in = (struct sockaddr_in *)&local_ss;
            inet_ntop(AF_INET, &in->sin_addr, client->server_ip, sizeof(client->server_ip));
        } else {
            rpsiod_safe_copy(client->server_ip, sizeof(client->server_ip), "0.0.0.0");
        }
        if (listener->tls) {
            client->ssl = SSL_new(listener->tls_ctx);
            if (client->ssl == NULL) {
                discard_accepted_client(client);
                continue;
            }
            struct timeval tls_timeout = {.tv_sec = 5, .tv_usec = 0};
            (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tls_timeout, sizeof(tls_timeout));
            (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tls_timeout, sizeof(tls_timeout));
            (void)set_blocking(fd);
            SSL_set_fd(client->ssl, fd);
            if (SSL_accept(client->ssl) <= 0) {
                discard_accepted_client(client);
                continue;
            }
            if (rpsiod_tls_selected_http2(client->ssl)) {
                struct timeval h2_timeout = {.tv_sec = 2, .tv_usec = 0};
                (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &h2_timeout, sizeof(h2_timeout));
                (void)rpsiod_set_nonblocking(fd);
                (void)rpsiod_http2_serve_connection(client->ssl, cfg, logger,
                                                    client->client_ip, client->server_ip, client->local_port);
                discard_accepted_client(client);
                continue;
            }
            (void)rpsiod_set_nonblocking(fd);
        }
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN | EPOLLRDHUP;
        ev.data.ptr = client;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
            rpsiod_log_error(logger, NULL, "epoll add client failed: %s", strerror(errno));
            discard_accepted_client(client);
        } else {
            client_list_add(clients_head, client);
        }
    }
}

static int rpsiod_server_run_worker(rpsiod_config *cfg, rpsiod_logger *logger, int worker_id, bool manage_pid_file) {
    rpsiod_signals_install_worker();

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        rpsiod_log_error(logger, NULL, "epoll_create1 failed: %s", strerror(errno));
        return 1;
    }

    listener_object listeners[RPSIOD_MAX_LISTENERS];
    memset(listeners, 0, sizeof(listeners));
    size_t listener_count = 0;
    SSL_CTX *tls_ctx = rpsiod_tls_create_context(cfg, logger);
    char err[512];
    if (add_listeners(epfd, cfg, listeners, &listener_count, tls_ctx, err, sizeof(err)) < 0) {
        rpsiod_log_error(logger, NULL, "%s", err);
        if (tls_ctx != NULL) SSL_CTX_free(tls_ctx);
        close(epfd);
        return 1;
    }
    if (listener_count == 0) {
        rpsiod_log_error(logger, NULL, "no HTTP listeners configured");
        if (tls_ctx != NULL) SSL_CTX_free(tls_ctx);
        close(epfd);
        return 1;
    }
    if (cfg->prevent_core_dumps && rpsiod_drop_core_dumps() < 0) {
        rpsiod_log_error(logger, NULL, "failed to disable core dumps: %s", strerror(errno));
    }
    if (manage_pid_file && rpsiod_write_pid_file(cfg->pid_file) < 0) {
        rpsiod_log_error(logger, NULL, "failed to write pid file %s: %s", cfg->pid_file, strerror(errno));
    }
    if (drop_privileges_after_bind(cfg, logger) < 0) {
        close(epfd);
        return 1;
    }

    for (size_t i = 0; i < listener_count; i++) {
        rpsiod_log_error(logger, NULL, "worker %d listening on %s port %u", worker_id, listeners[i].tls ? "HTTPS" : "HTTP", listeners[i].port);
    }

    client_object *clients_head = NULL;
    struct epoll_event events[RPSIOD_MAX_EVENTS];
    while (!rpsiod_stop_requested) {
        int n = epoll_wait(epfd, events, RPSIOD_MAX_EVENTS, 1000);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            rpsiod_log_error(logger, NULL, "epoll_wait failed: %s", strerror(errno));
            break;
        }
        for (int i = 0; i < n; i++) {
            object_kind kind = *((object_kind *)events[i].data.ptr);
            if (kind == OBJ_LISTENER) {
                accept_clients(epfd, (listener_object *)events[i].data.ptr, &clients_head, cfg, logger);
            } else if (kind == OBJ_CLIENT) {
                client_object *client = (client_object *)events[i].data.ptr;
                if ((events[i].events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) != 0) {
                    close_client(epfd, &clients_head, client);
                } else {
                    handle_client_event(epfd, &clients_head, client, cfg, logger);
                }
            }
        }
        sweep_idle_keep_alive_clients(epfd, &clients_head, cfg);
    }

    while (clients_head != NULL) {
        close_client(epfd, &clients_head, clients_head);
    }

    for (size_t i = 0; i < listener_count; i++) {
        close(listeners[i].fd);
    }
    close(epfd);
    if (tls_ctx != NULL) {
        SSL_CTX_free(tls_ctx);
    }
    if (manage_pid_file && cfg->pid_file[0] != '\0') {
        unlink(cfg->pid_file);
    }
    return 0;
}

static int resolved_worker_count(const rpsiod_config *cfg) {
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    int workers = cfg->workers_auto ? (int)(cpus > 0 ? cpus : 1) : cfg->workers;
    if (workers < 1) {
        workers = 1;
    }
    if (workers > 64) {
        workers = 64;
    }
    if (workers > 1 && !cfg->reuse_port) {
        workers = 1;
    }
    return workers;
}

static pid_t start_worker(rpsiod_config *cfg, rpsiod_logger *logger, int worker_id) {
    pid_t pid = fork();
    if (pid != 0) {
        return pid;
    }
    rpsiod_stop_requested = 0;
    rpsiod_reload_requested = 0;
    int rc = rpsiod_server_run_worker(cfg, logger, worker_id, false);
    _exit(rc == 0 ? 0 : 1);
}

static void stop_workers(pid_t *pids, int workers) {
    for (int i = 0; i < workers; i++) {
        if (pids[i] > 0) {
            kill(pids[i], SIGTERM);
        }
    }
}

static void wait_workers(pid_t *pids, int workers) {
    for (int i = 0; i < workers; i++) {
        if (pids[i] > 0) {
            (void)waitpid(pids[i], NULL, 0);
        }
    }
}

static int spawn_workers(rpsiod_config *cfg, rpsiod_logger *logger, pid_t *pids, int workers) {
    for (int i = 0; i < workers; i++) {
        pids[i] = start_worker(cfg, logger, i + 1);
        if (pids[i] < 0) {
            rpsiod_log_error(logger, NULL, "failed to fork worker %d: %s", i + 1, strerror(errno));
            return -1;
        }
    }
    return 0;
}

static int reload_workers(rpsiod_config *cfg, rpsiod_logger *logger, pid_t **pids, int *workers) {
    rpsiod_config *next = calloc(1, sizeof(*next));
    if (next == NULL) {
        rpsiod_log_error(logger, NULL, "reload failed: out of memory");
        return -1;
    }
    char err[1024] = {0};
    if (rpsiod_config_load(next, cfg->server_file, cfg->loaded_sites_file[0] != '\0' ? cfg->loaded_sites_file : NULL, err, sizeof(err)) < 0) {
        rpsiod_log_error(logger, NULL, "reload config validation failed: %s", err);
        free(next);
        return -1;
    }
    rpsiod_config_close_site_caches(cfg);
    *cfg = *next;
    free(next);
    int next_workers = resolved_worker_count(cfg);
    pid_t *next_pids = calloc((size_t)next_workers, sizeof(*next_pids));
    if (next_pids == NULL) {
        rpsiod_log_error(logger, NULL, "reload failed: out of memory");
        return -1;
    }
    if (spawn_workers(cfg, logger, next_pids, next_workers) < 0) {
        stop_workers(next_pids, next_workers);
        wait_workers(next_pids, next_workers);
        free(next_pids);
        return -1;
    }
    stop_workers(*pids, *workers);
    wait_workers(*pids, *workers);
    free(*pids);
    *pids = next_pids;
    *workers = next_workers;
    rpsiod_log_error(logger, NULL, "graceful reload complete: %d worker processes", *workers);
    return 0;
}

int rpsiod_server_run(rpsiod_config *cfg, rpsiod_logger *logger) {
    rpsiod_signals_install_parent();

    int workers = resolved_worker_count(cfg);
    if (workers == 1) {
        return rpsiod_server_run_worker(cfg, logger, 1, true);
    }

    if (cfg->prevent_core_dumps && rpsiod_drop_core_dumps() < 0) {
        rpsiod_log_error(logger, NULL, "failed to disable core dumps: %s", strerror(errno));
    }
    if (rpsiod_write_pid_file(cfg->pid_file) < 0) {
        rpsiod_log_error(logger, NULL, "failed to write pid file %s: %s", cfg->pid_file, strerror(errno));
    }

    pid_t *pids = calloc((size_t)workers, sizeof(*pids));
    if (pids == NULL) {
        return 1;
    }
    if (spawn_workers(cfg, logger, pids, workers) < 0) {
        rpsiod_stop_requested = 1;
    }
    rpsiod_log_error(logger, NULL, "started %d worker processes", workers);
    (void)rpsiod_systemd_notify("READY=1");

    while (!rpsiod_stop_requested) {
        if (rpsiod_reload_requested) {
            rpsiod_reload_requested = 0;
            (void)rpsiod_systemd_notify("RELOADING=1");
            (void)reload_workers(cfg, logger, &pids, &workers);
            (void)rpsiod_systemd_notify("READY=1");
            continue;
        }
        int status = 0;
        pid_t dead = waitpid(-1, &status, 0);
        if (dead < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        for (int i = 0; i < workers; i++) {
            if (pids[i] == dead) {
                if (!rpsiod_stop_requested) {
                    rpsiod_log_error(logger, NULL, "worker %d exited; restarting", i + 1);
                    pids[i] = start_worker(cfg, logger, i + 1);
                }
                break;
            }
        }
    }

    (void)rpsiod_systemd_notify("STOPPING=1");
    stop_workers(pids, workers);
    wait_workers(pids, workers);
    free(pids);
    if (cfg->pid_file[0] != '\0') {
        unlink(cfg->pid_file);
    }
    return 0;
}
