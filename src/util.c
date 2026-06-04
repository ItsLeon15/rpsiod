#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int rpsiod_set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int mkdir_recursive(char *path) {
    for (char *p = path + 1; *p != '\0'; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(path, 0755) < 0 && errno != EEXIST) {
                *p = '/';
                return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(path, 0755) < 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

int rpsiod_mkdir_parent(const char *path) {
    char tmp[PATH_MAX];
    rpsiod_safe_copy(tmp, sizeof(tmp), path);
    char *slash = strrchr(tmp, '/');
    if (slash == NULL) {
        return 0;
    }
    if (slash == tmp) {
        return 0;
    }
    *slash = '\0';
    return mkdir_recursive(tmp);
}

int rpsiod_open_append(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return -1;
    }
    (void)rpsiod_mkdir_parent(path);
    return open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0660);
}

void rpsiod_trim(char *s) {
    if (s == NULL) {
        return;
    }
    char *start = s;
    while (isspace((unsigned char)*start)) {
        start++;
    }
    if (start != s) {
        memmove(s, start, strlen(start) + 1);
    }
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[--len] = '\0';
    }
    if (len >= 2 && ((s[0] == '"' && s[len - 1] == '"') || (s[0] == '\'' && s[len - 1] == '\''))) {
        memmove(s, s + 1, len - 2);
        s[len - 2] = '\0';
    }
}

bool rpsiod_streq_ci(const char *a, const char *b) {
    if (a == NULL || b == NULL) {
        return false;
    }
    while (*a != '\0' && *b != '\0') {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return false;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

bool rpsiod_starts_with(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

uint64_t rpsiod_parse_size(const char *text, uint64_t fallback) {
    if (text == NULL || text[0] == '\0') {
        return fallback;
    }
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    if (end == text) {
        return fallback;
    }
    while (isspace((unsigned char)*end)) {
        end++;
    }
    uint64_t multiplier = 1;
    if (rpsiod_streq_ci(end, "kb") || rpsiod_streq_ci(end, "k")) {
        multiplier = 1024ULL;
    } else if (rpsiod_streq_ci(end, "mb") || rpsiod_streq_ci(end, "m")) {
        multiplier = 1024ULL * 1024ULL;
    } else if (rpsiod_streq_ci(end, "gb") || rpsiod_streq_ci(end, "g")) {
        multiplier = 1024ULL * 1024ULL * 1024ULL;
    }
    return (uint64_t)value * multiplier;
}

int rpsiod_parse_duration_sec(const char *text, int fallback) {
    if (text == NULL || text[0] == '\0') {
        return fallback;
    }
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (end == text || value < 0 || value > INT_MAX / 86400) {
        return fallback;
    }
    while (isspace((unsigned char)*end)) {
        end++;
    }
    if (rpsiod_streq_ci(end, "ms")) {
        return value > 0 ? 1 : 0;
    }
    if (rpsiod_streq_ci(end, "m")) {
        value *= 60;
    } else if (rpsiod_streq_ci(end, "h")) {
        value *= 3600;
    } else if (rpsiod_streq_ci(end, "d")) {
        value *= 86400;
    }
    return (int)value;
}

bool rpsiod_parse_bool(const char *text, bool fallback) {
    if (text == NULL) {
        return fallback;
    }
    if (rpsiod_streq_ci(text, "true") || rpsiod_streq_ci(text, "yes") || strcmp(text, "1") == 0) {
        return true;
    }
    if (rpsiod_streq_ci(text, "false") || rpsiod_streq_ci(text, "no") || strcmp(text, "0") == 0) {
        return false;
    }
    return fallback;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

int rpsiod_percent_decode_path(const char *in, char *out, size_t out_len) {
    if (out_len == 0) {
        return -1;
    }
    size_t oi = 0;
    for (size_t i = 0; in[i] != '\0'; i++) {
        unsigned char ch = (unsigned char)in[i];
        if (ch == '?') {
            break;
        }
        if (ch == '%') {
            if (in[i + 1] == '\0' || in[i + 2] == '\0') {
                return -1;
            }
            int hi = hexval(in[i + 1]);
            int lo = hexval(in[i + 2]);
            if (hi < 0 || lo < 0) {
                return -1;
            }
            ch = (unsigned char)((hi << 4) | lo);
            i += 2;
        }
        if (ch == '\0' || ch == '\\' || ch < 0x20) {
            return -1;
        }
        if (oi + 1 >= out_len) {
            return -1;
        }
        out[oi++] = (char)ch;
    }
    out[oi] = '\0';
    if (out[0] == '\0') {
        rpsiod_safe_copy(out, out_len, "/");
    }
    return 0;
}

bool rpsiod_path_has_forbidden_segment(const char *path) {
    if (path == NULL || path[0] != '/') {
        return true;
    }
    const char *p = path;
    while (*p != '\0') {
        while (*p == '/') {
            p++;
        }
        const char *start = p;
        while (*p != '\0' && *p != '/') {
            p++;
        }
        size_t len = (size_t)(p - start);
        if ((len == 1 && start[0] == '.') || (len == 2 && start[0] == '.' && start[1] == '.')) {
            return true;
        }
    }
    return false;
}

bool rpsiod_path_join(char *out, size_t out_len, const char *root, const char *request_path) {
    if (root == NULL || request_path == NULL || request_path[0] != '/') {
        return false;
    }
    if (snprintf(out, out_len, "%s%s", root, request_path) >= (int)out_len) {
        return false;
    }
    return true;
}

bool rpsiod_path_within_root(const char *root_real, const char *target_real) {
    size_t root_len = strlen(root_real);
    if (strncmp(root_real, target_real, root_len) != 0) {
        return false;
    }
    return target_real[root_len] == '\0' || target_real[root_len] == '/';
}

const char *rpsiod_mime_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (ext == NULL) {
        return "application/octet-stream";
    }
    if (rpsiod_streq_ci(ext, ".html") || rpsiod_streq_ci(ext, ".htm")) {
        return "text/html; charset=utf-8";
    }
    if (rpsiod_streq_ci(ext, ".css")) {
        return "text/css; charset=utf-8";
    }
    if (rpsiod_streq_ci(ext, ".js")) {
        return "application/javascript; charset=utf-8";
    }
    if (rpsiod_streq_ci(ext, ".json")) {
        return "application/json; charset=utf-8";
    }
    if (rpsiod_streq_ci(ext, ".txt")) {
        return "text/plain; charset=utf-8";
    }
    if (rpsiod_streq_ci(ext, ".png")) {
        return "image/png";
    }
    if (rpsiod_streq_ci(ext, ".jpg") || rpsiod_streq_ci(ext, ".jpeg")) {
        return "image/jpeg";
    }
    if (rpsiod_streq_ci(ext, ".gif")) {
        return "image/gif";
    }
    if (rpsiod_streq_ci(ext, ".svg")) {
        return "image/svg+xml";
    }
    if (rpsiod_streq_ci(ext, ".webp")) {
        return "image/webp";
    }
    if (rpsiod_streq_ci(ext, ".ico")) {
        return "image/x-icon";
    }
    if (rpsiod_streq_ci(ext, ".pdf")) {
        return "application/pdf";
    }
    return "application/octet-stream";
}

void rpsiod_strip_port(char *host) {
    if (host == NULL) {
        return;
    }
    char *space = strpbrk(host, " \t\r\n");
    if (space != NULL) {
        *space = '\0';
    }
    if (host[0] == '[') {
        char *end = strchr(host, ']');
        if (end != NULL) {
            end[1] = '\0';
        }
        return;
    }
    char *colon = strrchr(host, ':');
    if (colon != NULL) {
        *colon = '\0';
    }
}

void rpsiod_safe_copy(char *dst, size_t dst_len, const char *src) {
    if (dst_len == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    snprintf(dst, dst_len, "%s", src);
}

int rpsiod_write_all(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd poll_fd = {.fd = fd, .events = POLLOUT};
                int poll_result;
                do {
                    poll_result = poll(&poll_fd, 1, 1000);
                } while (poll_result < 0 && errno == EINTR);
                if (poll_result > 0) {
                    continue;
                }
                return -1;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

int rpsiod_drop_core_dumps(void) {
    struct rlimit rl = {0, 0};
    return setrlimit(RLIMIT_CORE, &rl);
}

int rpsiod_write_pid_file(const char *path) {
    static int pid_fd = -1;
    if (path == NULL || path[0] == '\0') {
        return 0;
    }
    if (rpsiod_mkdir_parent(path) < 0) {
        return -1;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        return -1;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        close(fd);
        return -1;
    }
    char buf[64];
    int len = snprintf(buf, sizeof(buf), "%ld\n", (long)getpid());
    int rc = rpsiod_write_all(fd, buf, (size_t)len);
    if (pid_fd >= 0) {
        close(pid_fd);
    }
    pid_fd = fd;
    return rc;
}
