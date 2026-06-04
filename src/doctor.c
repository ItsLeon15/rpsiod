#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "doctor.h"
#include "config.h"
#include "proxy.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int failures = 0;

static void check_line(bool ok, const char *name, const char *detail) {
    printf("%s %-32s %s\n", ok ? "ok" : "fail", name, detail != NULL ? detail : "");
    if (!ok) failures++;
}

static int parse_args(int argc, char **argv, const char **server_path, const char **sites_path) {
    *server_path = "/etc/rpsiod/server.yml";
    *sites_path = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--server") == 0 && i + 1 < argc) {
            *server_path = argv[++i];
        } else if (strcmp(argv[i], "--sites") == 0 && i + 1 < argc) {
            *sites_path = argv[++i];
        } else {
            fprintf(stderr, "unknown doctor argument: %s\n", argv[i]);
            return -1;
        }
    }
    return 0;
}

static bool path_writable_parent(const char *path) {
    char tmp[512];
    rpsiod_safe_copy(tmp, sizeof(tmp), path);
    char *slash = strrchr(tmp, '/');
    if (slash == NULL || slash == tmp) return false;
    *slash = '\0';
    return access(tmp, W_OK | X_OK) == 0;
}

static bool connect_php(const rpsiod_site_config *site, char *detail, size_t detail_len) {
    if (!site->php_enabled) {
        rpsiod_safe_copy(detail, detail_len, "disabled");
        return true;
    }
    if (rpsiod_streq_ci(site->php_handler_type, "socket")) {
        struct stat st;
        if (stat(site->php_socket, &st) < 0) {
            snprintf(detail, detail_len, "%s: %s", site->php_socket, strerror(errno));
            return false;
        }
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            snprintf(detail, detail_len, "socket: %s", strerror(errno));
            return false;
        }
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        rpsiod_safe_copy(addr.sun_path, sizeof(addr.sun_path), site->php_socket);
        bool ok = connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0;
        snprintf(detail, detail_len, "%s%s", site->php_socket, ok ? "" : strerror(errno));
        close(fd);
        return ok;
    }
    char port[16];
    snprintf(port, sizeof(port), "%u", site->php_port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(site->php_host, port, &hints, &res) != 0) {
        snprintf(detail, detail_len, "%s:%u resolve failed", site->php_host, site->php_port);
        return false;
    }
    bool ok = false;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) ok = true;
        close(fd);
        if (ok) break;
    }
    freeaddrinfo(res);
    snprintf(detail, detail_len, "%s:%u", site->php_host, site->php_port);
    return ok;
}

static bool port_available_or_owned(uint16_t port, char *detail, size_t detail_len) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return false;
    int yes = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    bool ok = bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0 || errno == EADDRINUSE;
    snprintf(detail, detail_len, "port %u %s", port, ok ? "usable/in use" : strerror(errno));
    close(fd);
    return ok;
}

int rpsiod_doctor_main(int argc, char **argv) {
    const char *server_path = NULL;
    const char *sites_path = NULL;
    if (parse_args(argc, argv, &server_path, &sites_path) < 0) return 2;
    rpsiod_config *cfg = calloc(1, sizeof(*cfg));
    if (cfg == NULL) return 1;
    char err[1024] = {0};
    check_line(rpsiod_config_load(cfg, server_path, sites_path, err, sizeof(err)) == 0, "config validation", err);
    if (err[0] != '\0') {
        free(cfg);
        return 1;
    }

    struct passwd *pw = getpwnam(cfg->linux_user);
    struct group *gr = getgrnam(cfg->linux_group);
    check_line(pw != NULL, "linux user", cfg->linux_user);
    check_line(gr != NULL, "linux group", cfg->linux_group);
    check_line(path_writable_parent(cfg->pid_file), "pid path", cfg->pid_file);
    if (cfg->access_log.enabled) check_line(path_writable_parent(cfg->access_log.path), "access log path", cfg->access_log.path);
    if (cfg->error_log.enabled) check_line(path_writable_parent(cfg->error_log.path), "error log path", cfg->error_log.path);
    check_line(path_writable_parent(cfg->benchmarks_storage_path), "benchmark storage", cfg->benchmarks_storage_path);
    check_line(!cfg->chroot_enabled || access(cfg->chroot_path, R_OK | X_OK) == 0, "root jail", cfg->chroot_enabled ? cfg->chroot_path : "disabled");

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        check_line(rl.rlim_cur >= 1024, "open file limit", "RLIMIT_NOFILE");
    }
    if (getrlimit(RLIMIT_NPROC, &rl) == 0) {
        check_line(rl.rlim_cur >= 128, "process limit", "RLIMIT_NPROC");
    }

    for (size_t i = 0; i < cfg->site_count; i++) {
        rpsiod_site_config *site = &cfg->sites[i];
        char detail[512];
        snprintf(detail, sizeof(detail), "%s root=%s", site->name, site->static_root_real);
        if (rpsiod_streq_ci(site->routing_type, "static") || rpsiod_streq_ci(site->routing_type, "php")) {
            check_line(site->static_root_fd >= 0 && access(site->static_root_real, R_OK | X_OK) == 0, "web root", detail);
            check_line(!site->allow_symlinks, "symlinks disabled", site->name);
        }
        if (site->http_port) {
            char port_detail[128];
            check_line(port_available_or_owned(site->http_port, port_detail, sizeof(port_detail)), "http port", port_detail);
        }
        if (site->ssl_enabled) {
            check_line(path_writable_parent(site->ssl_storage), "ssl storage", site->ssl_storage);
        }
        if (site->access_log.enabled) check_line(path_writable_parent(site->access_log.path), "site access log", site->access_log.path);
        if (site->error_log.enabled) check_line(path_writable_parent(site->error_log.path), "site error log", site->error_log.path);
        char php_detail[512];
        check_line(connect_php(site, php_detail, sizeof(php_detail)), "PHP-FPM", php_detail);
        if (rpsiod_streq_ci(site->routing_type, "proxy")) {
            int fd = rpsiod_proxy_connect(site);
            check_line(fd >= 0, "proxy upstream", site->proxy_host);
            if (fd >= 0) close(fd);
        }
        bool blocks_dotfiles = false;
        for (size_t j = 0; j < site->blocked_direct_access_count; j++) {
            if (strcmp(site->blocked_direct_access[j], ".env") == 0 || strcmp(site->blocked_direct_access[j], ".git") == 0) {
                blocks_dotfiles = true;
            }
        }
        check_line(blocks_dotfiles, "blocked files", site->name);
    }
    printf("doctor: %s\n", failures == 0 ? "ok" : "issues found");
    free(cfg);
    return failures == 0 ? 0 : 1;
}
