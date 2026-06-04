#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "bench.h"
#include "config.h"
#include "config_validate.h"
#include "doctor.h"
#include "log.h"
#include "reload.h"
#include "server.h"
#include "status.h"
#include "trace.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static void usage(FILE *out) {
    fprintf(out,
            "usage:\n"
            "  rpsiod serve [--server /etc/rpsiod/server.yml] [--sites /etc/rpsiod/sites.yml]\n"
            "  rpsiod configtest [--server /etc/rpsiod/server.yml] [--sites /etc/rpsiod/sites.yml]\n"
            "  rpsiod config-check [--server /etc/rpsiod/server.yml] [--sites /etc/rpsiod/sites.yml]\n"
            "  rpsiod status [--server /etc/rpsiod/server.yml] [--sites /etc/rpsiod/sites.yml]\n"
            "  rpsiod trace request --host example.com --path /pma/\n"
            "  rpsiod reload [--pid-file /run/rpsiod/rpsiod.pid]\n"
            "  rpsiod doctor [--server /etc/rpsiod/server.yml] [--sites /etc/rpsiod/sites.yml]\n"
            "  rpsiod test [--server /etc/rpsiod/server.yml] [--sites /etc/rpsiod/sites.yml]\n"
            "  rpsiod bench <static|proxy|php|tls|page|all> [options]\n");
}

static int parse_common_args(int argc, char **argv, const char **server_path, const char **sites_path) {
    *server_path = "/etc/rpsiod/server.yml";
    *sites_path = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--server") == 0 && i + 1 < argc) {
            *server_path = argv[++i];
        } else if (strcmp(argv[i], "--sites") == 0 && i + 1 < argc) {
            *sites_path = argv[++i];
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[i]);
            return -1;
        }
    }
    return 0;
}

static void apply_limits(const rpsiod_config *cfg) {
    if (cfg->open_files > 0) {
        struct rlimit rl;
        rl.rlim_cur = cfg->open_files;
        rl.rlim_max = cfg->open_files;
        (void)setrlimit(RLIMIT_NOFILE, &rl);
    }
    if (cfg->max_processes > 0) {
        struct rlimit rl;
        rl.rlim_cur = cfg->max_processes;
        rl.rlim_max = cfg->max_processes;
        (void)setrlimit(RLIMIT_NPROC, &rl);
    }
}

static int apply_root_jail(const rpsiod_config *cfg) {
    if (!cfg->chroot_enabled) {
        return 0;
    }
    if (cfg->chroot_path[0] == '\0') {
        fprintf(stderr, "chroot enabled but no path configured\n");
        return -1;
    }
    if (chroot(cfg->chroot_path) < 0 || chdir("/") < 0) {
        perror("chroot");
        return -1;
    }
    return 0;
}

static void test_line(bool ok, const char *name, int *failures) {
    printf("%s %s\n", ok ? "ok" : "fail", name);
    if (!ok) {
        (*failures)++;
    }
}

static bool connect_tcp_host(const char *host, uint16_t port) {
    char port_text[16];
    snprintf(port_text, sizeof(port_text), "%u", port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_text, &hints, &res) != 0) {
        return false;
    }
    bool ok = false;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            ok = true;
            close(fd);
            break;
        }
        close(fd);
    }
    freeaddrinfo(res);
    return ok;
}

static bool connect_php_handler(const rpsiod_site_config *site) {
    if (!site->php_enabled) {
        return true;
    }
    if (rpsiod_streq_ci(site->php_handler_type, "socket")) {
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) return false;
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        rpsiod_safe_copy(addr.sun_path, sizeof(addr.sun_path), site->php_socket);
        bool ok = connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0;
        close(fd);
        return ok;
    }
    return connect_tcp_host(site->php_host, site->php_port);
}

static bool valid_configured_headers(const rpsiod_site_config *site) {
    for (size_t i = 0; i < site->headers_add_count; i++) {
        if (strchr(site->headers_add[i].name, ' ') != NULL || strchr(site->headers_add[i].name, '\t') != NULL) {
            return false;
        }
    }
    for (size_t i = 0; i < site->headers_remove_count; i++) {
        if (strchr(site->headers_remove[i], ' ') != NULL || strchr(site->headers_remove[i], '\t') != NULL) {
            return false;
        }
    }
    return true;
}

static int run_regression_tests(rpsiod_config *cfg) {
    int failures = 0;
    test_line(cfg->site_count > 0, "config validation", &failures);
    for (size_t i = 0; i < cfg->site_count; i++) {
        rpsiod_site_config *site = &cfg->sites[i];
        bool matched = site->domain_count > 0 &&
                       rpsiod_config_find_site(cfg, site->domains[0], site->http_port != 0 ? site->http_port : site->https_port) == site;
        test_line(matched, "site matching", &failures);
        if (rpsiod_streq_ci(site->routing_type, "static") || rpsiod_streq_ci(site->routing_type, "php")) {
            test_line(site->static_root_fd >= 0, "static files", &failures);
        }
        test_line(connect_php_handler(site), "PHP-FPM connection", &failures);
        test_line(!site->ssl_enabled || site->ssl_storage[0] != '\0', "SSL config", &failures);
        test_line(site->blocked_direct_access_count < RPSIOD_MAX_BLOCKED, "blocked files", &failures);
        test_line(valid_configured_headers(site), "headers", &failures);
        test_line(!site->rate_limit_enabled || (site->rate_limit_requests > 0 && site->rate_limit_window_sec > 0), "rate limits", &failures);
        test_line(!site->compression_enabled || (site->compression_gzip || site->compression_br), "compression config", &failures);
        if (rpsiod_streq_ci(site->routing_type, "proxy")) {
            test_line(connect_tcp_host(site->proxy_host, site->proxy_port), "proxy upstream reachability", &failures);
        }
    }
    return failures == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(stderr);
        return 2;
    }
    if (strcmp(argv[1], "bench") == 0) {
        return rpsiod_bench_main(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "configtest") == 0 || strcmp(argv[1], "config-check") == 0) {
        return rpsiod_configtest_main(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "status") == 0) {
        return rpsiod_status_main(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "trace") == 0) {
        return rpsiod_trace_main(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "reload") == 0) {
        return rpsiod_reload_main(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "doctor") == 0) {
        return rpsiod_doctor_main(argc - 2, argv + 2);
    }
    const char *server_path = NULL;
    const char *sites_path = NULL;
    if (parse_common_args(argc - 2, argv + 2, &server_path, &sites_path) < 0) {
        usage(stderr);
        return 2;
    }
    rpsiod_config *cfg = calloc(1, sizeof(*cfg));
    if (cfg == NULL) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    char err[1024] = {0};
    if (rpsiod_config_load(cfg, server_path, sites_path, err, sizeof(err)) < 0) {
        fprintf(stderr, "config error: %s\n", err);
        free(cfg);
        return 1;
    }
    if (strcmp(argv[1], "test") == 0) {
        int rc = run_regression_tests(cfg);
        free(cfg);
        return rc;
    }
    if (strcmp(argv[1], "serve") != 0) {
        usage(stderr);
        free(cfg);
        return 2;
    }

    apply_limits(cfg);
    rpsiod_logger logger;
    (void)rpsiod_log_open(&logger, cfg);
    rpsiod_log_error(&logger, NULL, "startup config validation ok: server=%s sites=%s", cfg->server_file, cfg->loaded_sites_file);
    if (apply_root_jail(cfg) < 0) {
        rpsiod_log_close(&logger);
        free(cfg);
        return 1;
    }
    int rc = rpsiod_server_run(cfg, &logger);
    rpsiod_log_close(&logger);
    rpsiod_config_close_site_caches(cfg);
    free(cfg);
    return rc;
}
