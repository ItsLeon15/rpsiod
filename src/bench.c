#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "bench.h"
#include "config.h"
#include "http.h"
#include "util.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PAGE_MAX_ASSETS 2048
#define PAGE_HTML_MAX (8U * 1024U * 1024U)

typedef struct {
    const char *kind;
    const char *site_name;
    const char *path;
    int connections;
    int duration_sec;
    const char *server_path;
    const char *sites_path;
} bench_args;

typedef struct {
    unsigned long long requests;
    unsigned long long failed;
    unsigned long long timeouts;
    unsigned long long bytes;
    unsigned long long accepted_connections;
    unsigned long long closed_connections;
    unsigned long long read_errors;
    unsigned long long write_errors;
    unsigned long long socket_errors;
    unsigned long long keep_alive_reused;
    unsigned long long status_codes[600];
    unsigned peak_active_connections;
    int worker_count;
    double *latencies;
    size_t latency_count;
    size_t latency_cap;
    double max_latency;
} bench_result;

typedef struct {
    const char *url;
    const char *host_header;
    const char *protocol;
    int concurrency;
} page_args;

typedef struct {
    char connect_host[256];
    char host_header[256];
    char path[RPSIOD_PATH_LEN];
    uint16_t port;
} page_target;

typedef struct {
    char path[RPSIOD_PATH_LEN];
    char kind[16];
    int status;
    unsigned long long bytes;
    double started_at;
    double total_ms;
    double ttfb_ms;
    int connection_id;
    bool reused_connection;
    bool failed;
    bool cacheable;
    char cache_control[256];
    char etag[128];
    char last_modified[128];
    char content_encoding[64];
} page_asset;

typedef struct {
    page_target target;
    page_asset assets[PAGE_MAX_ASSETS];
    size_t asset_count;
    size_t next_asset;
    pthread_mutex_t lock;
    unsigned long long accepted_connections;
    unsigned long long closed_connections;
    unsigned long long reused_requests;
    unsigned long long failed_requests;
    double started_at;
} page_context;

typedef struct {
    page_context *ctx;
    int connection_id;
} page_worker_arg;

static double now_sec(void) {
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

static int parse_duration_arg(const char *s, int fallback) {
    int sec = rpsiod_parse_duration_sec(s, fallback);
    return sec > 0 ? sec : fallback;
}

static int parse_bench_args(int argc, char **argv, bench_args *args) {
    args->site_name = "Example Website";
    args->path = "/index.html";
    args->connections = 100;
    args->duration_sec = 10;
    args->server_path = "/etc/rpsiod/server.yml";
    args->sites_path = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--site") == 0 && i + 1 < argc) {
            args->site_name = argv[++i];
        } else if (strcmp(argv[i], "--path") == 0 && i + 1 < argc) {
            args->path = argv[++i];
        } else if (strcmp(argv[i], "--connections") == 0 && i + 1 < argc) {
            args->connections = atoi(argv[++i]);
            if (args->connections <= 0) args->connections = 1;
        } else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            args->duration_sec = parse_duration_arg(argv[++i], args->duration_sec);
        } else if (strcmp(argv[i], "--server") == 0 && i + 1 < argc) {
            args->server_path = argv[++i];
        } else if (strcmp(argv[i], "--sites") == 0 && i + 1 < argc) {
            args->sites_path = argv[++i];
        } else {
            fprintf(stderr, "unknown benchmark argument: %s\n", argv[i]);
            return -1;
        }
    }
    return 0;
}

static int parse_compare_args(int argc, char **argv, const char **before, const char **after) {
    *before = NULL;
    *after = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--before") == 0 && i + 1 < argc) {
            *before = argv[++i];
        } else if (strcmp(argv[i], "--after") == 0 && i + 1 < argc) {
            *after = argv[++i];
        } else {
            fprintf(stderr, "unknown compare argument: %s\n", argv[i]);
            return -1;
        }
    }
    if (*before == NULL || *after == NULL) {
        fprintf(stderr, "usage: rpsiod bench compare --before old.txt --after new.txt\n");
        return -1;
    }
    return 0;
}

static rpsiod_site_config *find_site_by_name(rpsiod_config *cfg, const char *name) {
    for (size_t i = 0; i < cfg->site_count; i++) {
        if (cfg->sites[i].enabled && strcmp(cfg->sites[i].name, name) == 0) {
            return &cfg->sites[i];
        }
    }
    return NULL;
}

static int connect_site(const rpsiod_site_config *site) {
    const char *ip = strcmp(site->listen_ip, "0.0.0.0") == 0 ? "127.0.0.1" : site->listen_ip;
    char port[16];
    snprintf(port, sizeof(port), "%u", site->http_port != 0 ? site->http_port : site->https_port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    struct addrinfo *res = NULL;
    if (getaddrinfo(ip, port, &hints, &res) != 0) {
        return -1;
    }
    int fd = -1;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0) continue;
        struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int fd_count(void) {
    int count = 0;
    DIR *dir = opendir("/proc/self/fd");
    if (dir == NULL) {
        return -1;
    }
    while (readdir(dir) != NULL) {
        count++;
    }
    closedir(dir);
    return count > 2 ? count - 2 : count;
}

static long current_rss_kb(void) {
    FILE *fp = fopen("/proc/self/status", "r");
    if (fp == NULL) {
        return 0;
    }
    char line[256];
    long rss = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "VmRSS: %ld kB", &rss) == 1) {
            break;
        }
    }
    fclose(fp);
    return rss;
}

static int record_latency(bench_result *result, double latency) {
    if (result->latency_count == result->latency_cap) {
        size_t new_cap = result->latency_cap == 0 ? 4096 : result->latency_cap * 2;
        double *next = realloc(result->latencies, new_cap * sizeof(*next));
        if (next == NULL) {
            return -1;
        }
        result->latencies = next;
        result->latency_cap = new_cap;
    }
    result->latencies[result->latency_count++] = latency;
    if (latency > result->max_latency) {
        result->max_latency = latency;
    }
    return 0;
}

static int one_request(const rpsiod_site_config *site, const char *path, bench_result *result) {
    int fd = connect_site(site);
    if (fd < 0) {
        result->failed++;
        result->socket_errors++;
        return -1;
    }
    result->accepted_connections++;
    if (result->peak_active_connections < 1) {
        result->peak_active_connections = 1;
    }
    char req[4096];
    const char *host = site->domain_count > 0 ? site->domains[0] : "localhost";
    int n = snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host);
    if (n < 0 || (size_t)n >= sizeof(req)) {
        close(fd);
        result->failed++;
        return -1;
    }
    double start = now_sec();
    if (rpsiod_write_all(fd, req, (size_t)n) < 0) {
        close(fd);
        result->failed++;
        result->write_errors++;
        return -1;
    }
    char buf[16384];
    bool got_any = false;
    char header[8192];
    size_t header_used = 0;
    bool status_recorded = false;
    for (;;) {
        ssize_t rd = read(fd, buf, sizeof(buf));
        if (rd < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) result->timeouts++;
            close(fd);
            result->failed++;
            result->read_errors++;
            return -1;
        }
        if (rd == 0) break;
        got_any = true;
        result->bytes += (unsigned long long)rd;
        if (!status_recorded && header_used < sizeof(header) - 1) {
            size_t copy = (size_t)rd;
            if (copy > sizeof(header) - 1 - header_used) {
                copy = sizeof(header) - 1 - header_used;
            }
            memcpy(header + header_used, buf, copy);
            header_used += copy;
            header[header_used] = '\0';
            char *line_end = strstr(header, "\r\n");
            if (line_end != NULL) {
                int status = 0;
                if (sscanf(header, "HTTP/%*s %d", &status) == 1 && status >= 0 && status < 600) {
                    result->status_codes[status]++;
                }
                status_recorded = true;
            }
        }
    }
    close(fd);
    result->closed_connections++;
    double latency = now_sec() - start;
    if (!got_any) {
        result->failed++;
        return -1;
    }
    result->requests++;
    (void)record_latency(result, latency);
    return 0;
}

static int parse_page_args(int argc, char **argv, page_args *args) {
    args->url = NULL;
    args->host_header = NULL;
    args->protocol = "auto";
    args->concurrency = 6;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--url") == 0 && i + 1 < argc) {
            args->url = argv[++i];
        } else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            args->host_header = argv[++i];
        } else if (strcmp(argv[i], "--protocol") == 0 && i + 1 < argc) {
            args->protocol = argv[++i];
            if (!rpsiod_streq_ci(args->protocol, "auto") &&
                !rpsiod_streq_ci(args->protocol, "http1") &&
                !rpsiod_streq_ci(args->protocol, "h2")) {
                fprintf(stderr, "bench page --protocol must be auto, http1, or h2\n");
                return -1;
            }
        } else if (strcmp(argv[i], "--concurrency") == 0 && i + 1 < argc) {
            args->concurrency = atoi(argv[++i]);
            if (args->concurrency <= 0) args->concurrency = 1;
            if (args->concurrency > 32) args->concurrency = 32;
        } else {
            fprintf(stderr, "unknown page benchmark argument: %s\n", argv[i]);
            return -1;
        }
    }
    if (args->url == NULL) {
        fprintf(stderr, "usage: rpsiod bench page --url http://127.0.0.1/pma/ [--protocol http1|h2|auto] [--host example.com] [--concurrency 6]\n");
        return -1;
    }
    return 0;
}

static int parse_http_url(const char *url, const char *host_override, page_target *target) {
    memset(target, 0, sizeof(*target));
    if (!rpsiod_starts_with(url, "http://")) {
        fprintf(stderr, "only http:// URLs are supported by bench page\n");
        return -1;
    }
    const char *host_start = url + 7;
    const char *path_start = strchr(host_start, '/');
    size_t host_len = path_start == NULL ? strlen(host_start) : (size_t)(path_start - host_start);
    if (host_len == 0 || host_len >= sizeof(target->connect_host)) {
        return -1;
    }
    char host_port[512];
    memcpy(host_port, host_start, host_len);
    host_port[host_len] = '\0';
    char *port = strrchr(host_port, ':');
    target->port = 80;
    if (port != NULL && strchr(port + 1, ']') == NULL) {
        *port++ = '\0';
        long parsed = strtol(port, NULL, 10);
        if (parsed > 0 && parsed <= 65535) {
            target->port = (uint16_t)parsed;
        }
    }
    rpsiod_safe_copy(target->connect_host, sizeof(target->connect_host), host_port);
    rpsiod_safe_copy(target->host_header, sizeof(target->host_header), host_override != NULL ? host_override : host_port);
    rpsiod_safe_copy(target->path, sizeof(target->path), path_start != NULL ? path_start : "/");
    return 0;
}

static int connect_target(const page_target *target) {
    char port[16];
    snprintf(port, sizeof(port), "%u", target->port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    struct addrinfo *res = NULL;
    if (getaddrinfo(target->connect_host, port, &hints, &res) != 0) {
        return -1;
    }
    int fd = -1;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0) continue;
        struct timeval tv = {.tv_sec = 10, .tv_usec = 0};
        int one = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static char *header_value_dup(const char *headers, const char *name, char *out, size_t out_len) {
    size_t name_len = strlen(name);
    const char *p = headers;
    while (*p != '\0') {
        const char *line_end = strstr(p, "\r\n");
        if (line_end == NULL) break;
        const char *colon = memchr(p, ':', (size_t)(line_end - p));
        if (colon != NULL && (size_t)(colon - p) == name_len && strncasecmp(p, name, name_len) == 0) {
            const char *value = colon + 1;
            while (*value == ' ' || *value == '\t') value++;
            size_t len = (size_t)(line_end - value);
            while (len > 0 && (value[len - 1] == ' ' || value[len - 1] == '\t')) len--;
            if (len >= out_len) len = out_len - 1;
            memcpy(out, value, len);
            out[len] = '\0';
            return out;
        }
        p = line_end + 2;
    }
    if (out_len > 0) out[0] = '\0';
    return NULL;
}

static bool response_wants_close(const char *headers) {
    char value[64];
    if (header_value_dup(headers, "Connection", value, sizeof(value)) == NULL) {
        return false;
    }
    return strcasestr(value, "close") != NULL;
}

static int run_child_tool(char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) {
            continue;
        }
        return -1;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return 1;
}

static int run_external_https_page_benchmark(const page_args *args) {
    const char *protocol = rpsiod_streq_ci(args->protocol, "auto") ? "h2" : args->protocol;
    printf("benchmark: page\n");
    printf("url: %s\n", args->url);
    printf("protocol: %s\n", protocol);
    if (args->host_header != NULL) {
        printf("host header: %s\n", args->host_header);
        printf("note: --host is only used by the built-in plaintext HTTP page benchmark\n");
    }
    if (rpsiod_streq_ci(protocol, "h2")) {
        printf("benchmark backend: nghttp -y -n -a -s\n");
        printf("streams: reported by nghttp processed stream count\n");
        printf("max concurrent streams: reported from server SETTINGS when nghttp prints stats\n");
        printf("slowest asset: inspect nghttp per-request timing table\n\n");
        fflush(stdout);
        char *const cmd[] = {"nghttp", "-y", "-n", "-a", "-s", (char *)args->url, NULL};
        return run_child_tool(cmd);
    }
    if (rpsiod_streq_ci(protocol, "http1")) {
        printf("benchmark backend: curl --http1.1\n");
        printf("note: HTTPS HTTP/1.1 mode measures the page document; use the built-in http:// mode for per-asset plaintext waterfall details\n\n");
        fflush(stdout);
        char *const cmd[] = {
            "curl",
            "-k",
            "--http1.1",
            "-w",
            "\nhttp_version: %{http_version}\nhttp_code: %{http_code}\ntime_connect: %{time_connect}s\ntime_tls: %{time_appconnect}s\ntime_starttransfer: %{time_starttransfer}s\ntime_total: %{time_total}s\nbytes: %{size_download}\n",
            "-o",
            "/dev/null",
            (char *)args->url,
            NULL
        };
        return run_child_tool(cmd);
    }
    fprintf(stderr, "unsupported HTTPS page protocol: %s\n", protocol);
    return 2;
}

static unsigned long long response_content_length(const char *headers, bool *present) {
    char value[64];
    *present = false;
    if (header_value_dup(headers, "Content-Length", value, sizeof(value)) == NULL) {
        return 0;
    }
    *present = true;
    return strtoull(value, NULL, 10);
}

static int fetch_asset_on_fd(int fd, const page_target *target, page_asset *asset, bool accept_compressed, char **body_out, size_t *body_len_out) {
    char req[4096];
    int n = snprintf(req, sizeof(req),
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: rpsiod-bench-page/1.0\r\n"
                     "Accept: */*\r\n"
                     "%s"
                     "Connection: keep-alive\r\n"
                     "\r\n",
                     asset->path,
                     target->host_header,
                     accept_compressed ? "Accept-Encoding: br, gzip\r\n" : "");
    if (n < 0 || (size_t)n >= sizeof(req)) {
        return -1;
    }
    double start = now_sec();
    if (rpsiod_write_all(fd, req, (size_t)n) < 0) {
        return -1;
    }
    char header[32768];
    size_t header_used = 0;
    char *body = NULL;
    size_t body_used = 0;
    size_t body_cap = 0;
    bool saw_header = false;
    bool have_length = false;
    bool close_after = false;
    unsigned long long content_length = 0;
    double first_byte = 0.0;
    for (;;) {
        char buf[32768];
        ssize_t rd = read(fd, buf, sizeof(buf));
        if (rd < 0) {
            if (errno == EINTR) continue;
            free(body);
            return -1;
        }
        if (rd == 0) {
            close_after = true;
            break;
        }
        if (first_byte == 0.0) {
            first_byte = now_sec();
        }
        size_t off = 0;
        if (!saw_header) {
            size_t before_header_used = header_used;
            size_t copy = (size_t)rd;
            if (copy > sizeof(header) - 1 - header_used) {
                copy = sizeof(header) - 1 - header_used;
            }
            memcpy(header + header_used, buf, copy);
            header_used += copy;
            header[header_used] = '\0';
            char *header_end = strstr(header, "\r\n\r\n");
            if (header_end == NULL) {
                if (header_used == sizeof(header) - 1) {
                    free(body);
                    return -1;
                }
                continue;
            }
            saw_header = true;
            size_t header_bytes = (size_t)(header_end - header) + 4;
            size_t extra_in_header = header_used > header_bytes ? header_used - header_bytes : 0;
            size_t current_header_bytes;
            if (before_header_used < header_bytes) {
                current_header_bytes = header_bytes - before_header_used;
                if (current_header_bytes > copy) current_header_bytes = copy;
            } else {
                current_header_bytes = 0;
            }
            int status = 0;
            if (sscanf(header, "HTTP/%*s %d", &status) == 1) {
                asset->status = status;
            }
            header_value_dup(header, "Cache-Control", asset->cache_control, sizeof(asset->cache_control));
            header_value_dup(header, "ETag", asset->etag, sizeof(asset->etag));
            header_value_dup(header, "Last-Modified", asset->last_modified, sizeof(asset->last_modified));
            header_value_dup(header, "Content-Encoding", asset->content_encoding, sizeof(asset->content_encoding));
            asset->cacheable = asset->etag[0] != '\0' || asset->last_modified[0] != '\0' ||
                               (asset->cache_control[0] != '\0' && strcasestr(asset->cache_control, "no-store") == NULL);
            content_length = response_content_length(header, &have_length);
            close_after = response_wants_close(header);
            (void)extra_in_header;
            off = current_header_bytes;
        }
        if (off < (size_t)rd) {
            size_t chunk = (size_t)rd - off;
            asset->bytes += (unsigned long long)chunk;
            if (body_out != NULL && body_used + chunk <= PAGE_HTML_MAX) {
                if (body_used + chunk + 1 > body_cap) {
                    size_t next_cap = body_cap == 0 ? 65536 : body_cap * 2;
                    while (next_cap < body_used + chunk + 1) next_cap *= 2;
                    if (next_cap > PAGE_HTML_MAX + 1U) next_cap = PAGE_HTML_MAX + 1U;
                    char *next = realloc(body, next_cap);
                    if (next == NULL) {
                        free(body);
                        return -1;
                    }
                    body = next;
                    body_cap = next_cap;
                }
                memcpy(body + body_used, buf + off, chunk);
                body_used += chunk;
                body[body_used] = '\0';
            }
        }
        if (saw_header && have_length && asset->bytes >= content_length) {
            break;
        }
    }
    double end = now_sec();
    asset->ttfb_ms = first_byte > 0.0 ? (first_byte - start) * 1000.0 : 0.0;
    asset->total_ms = (end - start) * 1000.0;
    if (body_out != NULL) {
        *body_out = body;
        if (body_len_out != NULL) *body_len_out = body_used;
    } else {
        free(body);
    }
    return close_after ? 1 : 0;
}

static bool asset_exists(const page_context *ctx, const char *path) {
    for (size_t i = 0; i < ctx->asset_count; i++) {
        if (strcmp(ctx->assets[i].path, path) == 0) {
            return true;
        }
    }
    return false;
}

static const char *path_extension(const char *path) {
    const char *query = strchr(path, '?');
    const char *end = query != NULL ? query : path + strlen(path);
    const char *dot = NULL;
    for (const char *p = path; p < end; p++) {
        if (*p == '.') dot = p;
    }
    return dot != NULL ? dot : "";
}

static bool classify_asset(const char *path, char *kind, size_t kind_len) {
    const char *ext = path_extension(path);
    if (rpsiod_streq_ci(ext, ".css")) {
        rpsiod_safe_copy(kind, kind_len, "css");
        return true;
    }
    if (rpsiod_streq_ci(ext, ".js")) {
        rpsiod_safe_copy(kind, kind_len, "js");
        return true;
    }
    if (rpsiod_streq_ci(ext, ".png") || rpsiod_streq_ci(ext, ".jpg") || rpsiod_streq_ci(ext, ".jpeg") ||
        rpsiod_streq_ci(ext, ".gif") || rpsiod_streq_ci(ext, ".svg") || rpsiod_streq_ci(ext, ".webp")) {
        rpsiod_safe_copy(kind, kind_len, "image");
        return true;
    }
    if (rpsiod_streq_ci(ext, ".ico") || strcasestr(path, "favicon") != NULL) {
        rpsiod_safe_copy(kind, kind_len, "favicon");
        return true;
    }
    return false;
}

static bool resolve_asset_url(const page_target *target, const char *base_path, const char *url, char *out, size_t out_len) {
    if (url[0] == '\0' || url[0] == '#' || rpsiod_starts_with(url, "data:") ||
        rpsiod_starts_with(url, "mailto:") || rpsiod_starts_with(url, "javascript:") ||
        rpsiod_starts_with(url, "//")) {
        return false;
    }
    const char *path = url;
    if (rpsiod_starts_with(url, "http://")) {
        const char *host_start = url + 7;
        const char *path_start = strchr(host_start, '/');
        size_t host_len = path_start == NULL ? strlen(host_start) : (size_t)(path_start - host_start);
        if (host_len != strlen(target->host_header) || strncasecmp(host_start, target->host_header, host_len) != 0) {
            return false;
        }
        path = path_start != NULL ? path_start : "/";
    } else if (rpsiod_starts_with(url, "https://")) {
        return false;
    }
    char tmp[RPSIOD_PATH_LEN];
    if (path[0] == '/') {
        rpsiod_safe_copy(tmp, sizeof(tmp), path);
    } else {
        char dir[RPSIOD_PATH_LEN];
        rpsiod_safe_copy(dir, sizeof(dir), base_path);
        char *query = strchr(dir, '?');
        if (query != NULL) *query = '\0';
        char *slash = strrchr(dir, '/');
        if (slash != NULL) {
            slash[1] = '\0';
        } else {
            rpsiod_safe_copy(dir, sizeof(dir), "/");
        }
        if (snprintf(tmp, sizeof(tmp), "%s%s", dir, path) >= (int)sizeof(tmp)) {
            return false;
        }
    }
    char *fragment = strchr(tmp, '#');
    if (fragment != NULL) *fragment = '\0';
    if (tmp[0] != '/') {
        return false;
    }
    rpsiod_safe_copy(out, out_len, tmp);
    return true;
}

static void add_page_asset(page_context *ctx, const char *path, const char *kind) {
    if (ctx->asset_count >= PAGE_MAX_ASSETS || asset_exists(ctx, path)) {
        return;
    }
    page_asset *asset = &ctx->assets[ctx->asset_count++];
    memset(asset, 0, sizeof(*asset));
    rpsiod_safe_copy(asset->path, sizeof(asset->path), path);
    rpsiod_safe_copy(asset->kind, sizeof(asset->kind), kind);
}

static void parse_html_assets(page_context *ctx, const char *html) {
    const char *p = html;
    while ((p = strpbrk(p, "hsHS")) != NULL) {
        const char *attr = NULL;
        if (strncasecmp(p, "href", 4) == 0) {
            attr = p + 4;
        } else if (strncasecmp(p, "src", 3) == 0) {
            attr = p + 3;
        } else {
            p++;
            continue;
        }
        while (*attr == ' ' || *attr == '\t' || *attr == '\r' || *attr == '\n') attr++;
        if (*attr != '=') {
            p++;
            continue;
        }
        attr++;
        while (*attr == ' ' || *attr == '\t' || *attr == '\r' || *attr == '\n') attr++;
        char quote = (*attr == '"' || *attr == '\'') ? *attr++ : '\0';
        const char *value = attr;
        while (*attr != '\0' && ((quote != '\0' && *attr != quote) ||
               (quote == '\0' && *attr != ' ' && *attr != '\t' && *attr != '\r' && *attr != '\n' && *attr != '>'))) {
            attr++;
        }
        size_t value_len = (size_t)(attr - value);
        if (value_len > 0 && value_len < RPSIOD_PATH_LEN) {
            char raw[RPSIOD_PATH_LEN];
            memcpy(raw, value, value_len);
            raw[value_len] = '\0';
            char resolved[RPSIOD_PATH_LEN];
            char kind[16];
            if (resolve_asset_url(&ctx->target, ctx->target.path, raw, resolved, sizeof(resolved)) &&
                classify_asset(resolved, kind, sizeof(kind))) {
                add_page_asset(ctx, resolved, kind);
            }
        }
        p = attr;
    }
}

static void *page_worker(void *arg) {
    page_worker_arg *worker = arg;
    page_context *ctx = worker->ctx;
    int fd = -1;
    unsigned requests_on_connection = 0;
    for (;;) {
        pthread_mutex_lock(&ctx->lock);
        size_t idx = ctx->next_asset++;
        pthread_mutex_unlock(&ctx->lock);
        if (idx >= ctx->asset_count) {
            break;
        }
        page_asset *asset = &ctx->assets[idx];
        if (fd < 0) {
            fd = connect_target(&ctx->target);
            if (fd >= 0) {
                pthread_mutex_lock(&ctx->lock);
                ctx->accepted_connections++;
                pthread_mutex_unlock(&ctx->lock);
                requests_on_connection = 0;
            }
        }
        asset->started_at = (now_sec() - ctx->started_at) * 1000.0;
        asset->connection_id = worker->connection_id;
        asset->reused_connection = requests_on_connection > 0;
        if (asset->reused_connection) {
            pthread_mutex_lock(&ctx->lock);
            ctx->reused_requests++;
            pthread_mutex_unlock(&ctx->lock);
        }
        int rc = fd >= 0 ? fetch_asset_on_fd(fd, &ctx->target, asset, true, NULL, NULL) : -1;
        requests_on_connection++;
        if (rc < 0) {
            asset->failed = true;
            pthread_mutex_lock(&ctx->lock);
            ctx->failed_requests++;
            pthread_mutex_unlock(&ctx->lock);
            if (fd >= 0) {
                close(fd);
                fd = -1;
                pthread_mutex_lock(&ctx->lock);
                ctx->closed_connections++;
                pthread_mutex_unlock(&ctx->lock);
            }
        } else if (rc > 0) {
            close(fd);
            fd = -1;
            pthread_mutex_lock(&ctx->lock);
            ctx->closed_connections++;
            pthread_mutex_unlock(&ctx->lock);
        }
    }
    if (fd >= 0) {
        close(fd);
        pthread_mutex_lock(&ctx->lock);
        ctx->closed_connections++;
        pthread_mutex_unlock(&ctx->lock);
    }
    return NULL;
}

static int run_page_benchmark(int argc, char **argv) {
    page_args args;
    if (parse_page_args(argc, argv, &args) < 0) {
        return 2;
    }
    if (rpsiod_starts_with(args.url, "https://")) {
        return run_external_https_page_benchmark(&args);
    }
    if (!rpsiod_streq_ci(args.protocol, "auto") && !rpsiod_streq_ci(args.protocol, "http1")) {
        fprintf(stderr, "built-in plaintext page benchmark only supports --protocol http1 or auto\n");
        return 2;
    }
    page_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (parse_http_url(args.url, args.host_header, &ctx.target) < 0) {
        return 2;
    }
    pthread_mutex_init(&ctx.lock, NULL);
    add_page_asset(&ctx, ctx.target.path, "html");
    ctx.started_at = now_sec();
    int fd = connect_target(&ctx.target);
    if (fd < 0) {
        fprintf(stderr, "failed to connect to %s:%u\n", ctx.target.connect_host, ctx.target.port);
        pthread_mutex_destroy(&ctx.lock);
        return 1;
    }
    ctx.accepted_connections++;
    char *html = NULL;
    size_t html_len = 0;
    page_asset *html_asset = &ctx.assets[0];
    html_asset->connection_id = 1;
    html_asset->started_at = 0.0;
    int rc = fetch_asset_on_fd(fd, &ctx.target, html_asset, false, &html, &html_len);
    if (rc != 0) {
        close(fd);
        ctx.closed_connections++;
        fd = -1;
    }
    if (html_asset->failed || html == NULL) {
        fprintf(stderr, "failed to fetch page HTML\n");
        free(html);
        pthread_mutex_destroy(&ctx.lock);
        return 1;
    }
    parse_html_assets(&ctx, html);
    free(html);
    ctx.next_asset = 1;

    int workers = args.concurrency;
    if (workers > (int)(ctx.asset_count > 1 ? ctx.asset_count - 1 : 1)) {
        workers = (int)(ctx.asset_count > 1 ? ctx.asset_count - 1 : 1);
    }
    pthread_t threads[32];
    page_worker_arg worker_args[32];
    for (int i = 0; i < workers; i++) {
        worker_args[i].ctx = &ctx;
        worker_args[i].connection_id = i + 2;
        if (pthread_create(&threads[i], NULL, page_worker, &worker_args[i]) != 0) {
            workers = i;
            break;
        }
    }
    for (int i = 0; i < workers; i++) {
        (void)pthread_join(threads[i], NULL);
    }
    if (fd >= 0) {
        close(fd);
        ctx.closed_connections++;
    }
    double total_ms = (now_sec() - ctx.started_at) * 1000.0;
    unsigned long long bytes = 0;
    unsigned long long cacheable = 0;
    unsigned long long failed = ctx.failed_requests;
    for (size_t i = 0; i < ctx.asset_count; i++) {
        bytes += ctx.assets[i].bytes;
        if (ctx.assets[i].cacheable) cacheable++;
        if (ctx.assets[i].failed) failed++;
    }
    printf("benchmark: page\n");
    printf("url: %s\n", args.url);
    printf("host header: %s\n", ctx.target.host_header);
    printf("assets discovered: %zu\n", ctx.asset_count);
    printf("total page load time: %.3f ms\n", total_ms);
    printf("bytes transferred: %llu\n", bytes);
    printf("accepted connections: %llu\n", ctx.accepted_connections);
    printf("closed connections: %llu\n", ctx.closed_connections);
    printf("keep-alive reused requests: %llu\n", ctx.reused_requests);
    printf("requests per connection average: %.2f\n", ctx.accepted_connections > 0 ? (double)ctx.asset_count / (double)ctx.accepted_connections : 0.0);
    printf("cacheable assets: %llu/%zu\n", cacheable, ctx.asset_count);
    printf("failed requests: %llu\n", failed);
    printf("\nper-asset timings:\n");
    for (size_t i = 0; i < ctx.asset_count; i++) {
        page_asset *a = &ctx.assets[i];
        printf("%3zu %-7s %3d %8llu bytes conn=%d%s start=%.3fms ttfb=%.3fms total=%.3fms cache=\"%s\" etag=\"%s\" last-modified=\"%s\" encoding=\"%s\" %s\n",
               i + 1, a->kind, a->status, a->bytes, a->connection_id,
               a->reused_connection ? " reused" : "",
               a->started_at, a->ttfb_ms, a->total_ms,
               a->cache_control, a->etag, a->last_modified, a->content_encoding,
               a->failed ? "FAILED" : "");
    }
    printf("\nslowest assets:\n");
    bool printed[PAGE_MAX_ASSETS];
    for (size_t i = 0; i < PAGE_MAX_ASSETS; i++) {
        printed[i] = false;
    }
    for (int rank = 0; rank < 10 && rank < (int)ctx.asset_count; rank++) {
        size_t best = SIZE_MAX;
        for (size_t i = 0; i < ctx.asset_count; i++) {
            if (!printed[i] && (best == SIZE_MAX || ctx.assets[i].total_ms > ctx.assets[best].total_ms)) {
                best = i;
            }
        }
        if (best == SIZE_MAX) break;
        printf("%2d. %.3f ms %s\n", rank + 1, ctx.assets[best].total_ms, ctx.assets[best].path);
        printed[best] = true;
    }
    pthread_mutex_destroy(&ctx.lock);
    return failed == 0 ? 0 : 1;
}

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return da < db ? -1 : da > db ? 1 : 0;
}

static double percentile(const bench_result *result, double pct) {
    if (result->latency_count == 0) {
        return 0.0;
    }
    size_t idx = (size_t)((pct / 100.0) * (double)(result->latency_count - 1));
    return result->latencies[idx];
}

static void print_report(FILE *out, const bench_args *args, const bench_result *result, double elapsed) {
    struct rusage ru;
    memset(&ru, 0, sizeof(ru));
    (void)getrusage(RUSAGE_SELF, &ru);
    double avg = 0.0;
    for (size_t i = 0; i < result->latency_count; i++) {
        avg += result->latencies[i];
    }
    if (result->latency_count > 0) {
        avg /= (double)result->latency_count;
    }
    fprintf(out, "benchmark: %s\n", args->kind);
    fprintf(out, "site: %s\n", args->site_name);
    fprintf(out, "path: %s\n", args->path);
    fprintf(out, "total requests: %llu\n", result->requests);
    fprintf(out, "benchmark duration: %.3f s\n", elapsed);
    fprintf(out, "configured connections: %d\n", args->connections);
    fprintf(out, "worker count: %d\n", result->worker_count);
    fprintf(out, "requests per second: %.2f\n", elapsed > 0.0 ? (double)result->requests / elapsed : 0.0);
    fprintf(out, "average latency: %.3f ms\n", avg * 1000.0);
    fprintf(out, "p50 latency: %.3f ms\n", percentile(result, 50.0) * 1000.0);
    fprintf(out, "p90 latency: %.3f ms\n", percentile(result, 90.0) * 1000.0);
    fprintf(out, "p95 latency: %.3f ms\n", percentile(result, 95.0) * 1000.0);
    fprintf(out, "p99 latency: %.3f ms\n", percentile(result, 99.0) * 1000.0);
    fprintf(out, "max latency: %.3f ms\n", result->max_latency * 1000.0);
    fprintf(out, "failed requests: %llu\n", result->failed);
    fprintf(out, "timeouts: %llu\n", result->timeouts);
    fprintf(out, "bytes transferred: %llu\n", result->bytes);
    fprintf(out, "status code breakdown:");
    bool any_status = false;
    for (size_t i = 0; i < 600; i++) {
        if (result->status_codes[i] > 0) {
            fprintf(out, " %zu=%llu", i, result->status_codes[i]);
            any_status = true;
        }
    }
    fprintf(out, "%s\n", any_status ? "" : " none");
    fprintf(out, "peak active connections: %u\n", result->peak_active_connections);
    fprintf(out, "accepted connections: %llu\n", result->accepted_connections);
    fprintf(out, "closed connections: %llu\n", result->closed_connections);
    fprintf(out, "keep-alive reused requests: %llu\n", result->keep_alive_reused);
    fprintf(out, "read errors: %llu\n", result->read_errors);
    fprintf(out, "write errors: %llu\n", result->write_errors);
    fprintf(out, "socket errors: %llu\n", result->socket_errors);
    fprintf(out, "sendfile calls: server-side counter unavailable in CLI benchmark\n");
    fprintf(out, "sendfile bytes: server-side counter unavailable in CLI benchmark\n");
    fprintf(out, "fallback read/write count: server-side counter unavailable in CLI benchmark\n");
    fprintf(out, "cache hits: server-side counter unavailable in CLI benchmark\n");
    fprintf(out, "cache misses: server-side counter unavailable in CLI benchmark\n");
    fprintf(out, "file stat calls: server-side counter unavailable in CLI benchmark\n");
    fprintf(out, "CPU usage: user %.3fs system %.3fs\n",
            (double)ru.ru_utime.tv_sec + (double)ru.ru_utime.tv_usec / 1000000.0,
            (double)ru.ru_stime.tv_sec + (double)ru.ru_stime.tv_usec / 1000000.0);
    fprintf(out, "current RSS: %ld KB\n", current_rss_kb());
    fprintf(out, "memory usage: %ld KB\n", ru.ru_maxrss);
    fprintf(out, "peak RSS: %ld KB\n", ru.ru_maxrss);
    fprintf(out, "fd count: %d\n", fd_count());
    fprintf(out, "open connections: 0\n");
}

static double report_metric(const char *path, const char *name) {
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return 0.0;
    }
    char line[512];
    double value = 0.0;
    size_t name_len = strlen(name);
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strncmp(line, name, name_len) == 0 && line[name_len] == ':') {
            char *p = line + name_len + 1;
            while (*p == ' ') p++;
            value = strtod(p, NULL);
            break;
        }
    }
    fclose(fp);
    return value;
}

static double report_cpu_metric(const char *path) {
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return 0.0;
    }
    char line[512];
    double user = 0.0;
    double system = 0.0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "CPU usage: user %lfs system %lfs", &user, &system) == 2) {
            break;
        }
    }
    fclose(fp);
    return user + system;
}

static void print_metric_delta(const char *label, double before, double after) {
    double pct = before != 0.0 ? ((after - before) / before) * 100.0 : 0.0;
    printf("%s: %.3f -> %.3f (%+.2f%%)\n", label, before, after, pct);
}

static int run_compare(int argc, char **argv) {
    const char *before = NULL;
    const char *after = NULL;
    if (parse_compare_args(argc, argv, &before, &after) < 0) {
        return 2;
    }
    print_metric_delta("requests/sec", report_metric(before, "requests per second"), report_metric(after, "requests per second"));
    print_metric_delta("average latency", report_metric(before, "average latency"), report_metric(after, "average latency"));
    print_metric_delta("p95", report_metric(before, "p95 latency"), report_metric(after, "p95 latency"));
    print_metric_delta("p99", report_metric(before, "p99 latency"), report_metric(after, "p99 latency"));
    print_metric_delta("max latency", report_metric(before, "max latency"), report_metric(after, "max latency"));
    print_metric_delta("failed requests", report_metric(before, "failed requests"), report_metric(after, "failed requests"));
    print_metric_delta("CPU usage", report_cpu_metric(before), report_cpu_metric(after));
    print_metric_delta("memory usage", report_metric(before, "memory usage"), report_metric(after, "memory usage"));
    return 0;
}

static int save_report(const rpsiod_config *cfg, const bench_args *args, const bench_result *result, double elapsed) {
    char path[1024];
    time_t now = time(NULL);
    snprintf(path, sizeof(path), "%s/%s-%lld.txt", cfg->benchmarks_storage_path, args->kind, (long long)now);
    if (rpsiod_mkdir_parent(path) < 0) {
        return -1;
    }
    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        return -1;
    }
    print_report(fp, args, result, elapsed);
    fclose(fp);
    printf("saved report: %s\n", path);
    return 0;
}

static int run_one_benchmark(const bench_args *args) {
    rpsiod_config *cfg = calloc(1, sizeof(*cfg));
    if (cfg == NULL) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    char err[1024] = {0};
    if (rpsiod_config_load(cfg, args->server_path, args->sites_path, err, sizeof(err)) < 0) {
        fprintf(stderr, "config error: %s\n", err);
        free(cfg);
        return 1;
    }
    rpsiod_site_config *site = find_site_by_name(cfg, args->site_name);
    if (site == NULL) {
        fprintf(stderr, "benchmark site not found: %s\n", args->site_name);
        free(cfg);
        return 1;
    }
    bench_result result;
    memset(&result, 0, sizeof(result));
    result.worker_count = cfg->workers_auto ? (int)sysconf(_SC_NPROCESSORS_ONLN) : cfg->workers;
    if (result.worker_count < 1) {
        result.worker_count = 1;
    }
    double start = now_sec();
    double deadline = start + (double)args->duration_sec;
    while (now_sec() < deadline) {
        (void)one_request(site, args->path, &result);
    }
    double elapsed = now_sec() - start;
    qsort(result.latencies, result.latency_count, sizeof(*result.latencies), cmp_double);
    print_report(stdout, args, &result, elapsed);
    (void)save_report(cfg, args, &result, elapsed);
    free(result.latencies);
    free(cfg);
    return result.requests > 0 ? 0 : 1;
}

int rpsiod_bench_main(int argc, char **argv) {
    if (argc < 1) {
        fprintf(stderr, "usage: rpsiod bench <static|proxy|php|tls|all|compare> [options]\n");
        return 2;
    }
    if (strcmp(argv[0], "compare") == 0) {
        return run_compare(argc - 1, argv + 1);
    }
    if (strcmp(argv[0], "page") == 0) {
        return run_page_benchmark(argc - 1, argv + 1);
    }
    bench_args args;
    memset(&args, 0, sizeof(args));
    args.kind = argv[0];
    if (parse_bench_args(argc - 1, argv + 1, &args) < 0) {
        return 2;
    }
    if (strcmp(args.kind, "all") == 0) {
        args.kind = "static";
        int rc = run_one_benchmark(&args);
        args.kind = "all";
        return rc;
    }
    if (strcmp(args.kind, "static") == 0 || strcmp(args.kind, "proxy") == 0 ||
        strcmp(args.kind, "php") == 0 || strcmp(args.kind, "tls") == 0) {
        return run_one_benchmark(&args);
    }
    fprintf(stderr, "unknown benchmark command '%s'\n", args.kind);
    return 2;
}
