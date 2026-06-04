#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "status.h"
#include "config.h"
#include "proxy.h"
#include "util.h"

#include <dirent.h>
#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static int parse_args(int argc, char **argv, const char **server_path, const char **sites_path, const char **pid_file) {
    *server_path = "/etc/rpsiod/server.yml";
    *sites_path = NULL;
    *pid_file = "/run/rpsiod/rpsiod.pid";
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--server") == 0 && i + 1 < argc) {
            *server_path = argv[++i];
        } else if (strcmp(argv[i], "--sites") == 0 && i + 1 < argc) {
            *sites_path = argv[++i];
        } else if (strcmp(argv[i], "--pid-file") == 0 && i + 1 < argc) {
            *pid_file = argv[++i];
        } else {
            fprintf(stderr, "unknown status argument: %s\n", argv[i]);
            return -1;
        }
    }
    return 0;
}

static long read_pid_file(const char *pid_file) {
    FILE *fp = fopen(pid_file, "r");
    if (fp == NULL) return -1;
    long pid = -1;
    if (fscanf(fp, "%ld", &pid) != 1) {
        pid = -1;
    }
    fclose(fp);
    return pid;
}

static int count_worker_processes(long parent_pid) {
    DIR *dir = opendir("/proc");
    if (dir == NULL) return 0;
    int count = 0;
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        char *end = NULL;
        long pid = strtol(de->d_name, &end, 10);
        if (end == de->d_name || *end != '\0') continue;
        char stat_path[128];
        snprintf(stat_path, sizeof(stat_path), "/proc/%ld/stat", pid);
        FILE *fp = fopen(stat_path, "r");
        if (fp == NULL) continue;
        long parsed_pid = 0;
        char comm[256];
        char state = 0;
        long ppid = 0;
        if (fscanf(fp, "%ld %255s %c %ld", &parsed_pid, comm, &state, &ppid) == 4 && ppid == parent_pid) {
            count++;
        }
        fclose(fp);
    }
    closedir(dir);
    return count;
}

static unsigned long uptime_seconds(long pid) {
    char stat_path[128];
    snprintf(stat_path, sizeof(stat_path), "/proc/%ld/stat", pid);
    FILE *fp = fopen(stat_path, "r");
    if (fp == NULL) return 0;
    char buf[4096];
    if (fgets(buf, sizeof(buf), fp) == NULL) {
        fclose(fp);
        return 0;
    }
    fclose(fp);
    char *p = strrchr(buf, ')');
    if (p == NULL) return 0;
    p++;
    for (int field = 3; field < 22 && *p != '\0'; field++) {
        while (*p == ' ') p++;
        while (*p != ' ' && *p != '\0') p++;
    }
    while (*p == ' ') p++;
    unsigned long long start_ticks = strtoull(p, NULL, 10);
    long ticks = sysconf(_SC_CLK_TCK);
    FILE *up = fopen("/proc/uptime", "r");
    double uptime = 0.0;
    if (up != NULL) {
        if (fscanf(up, "%lf", &uptime) != 1) {
            uptime = 0.0;
        }
        fclose(up);
    }
    double started = ticks > 0 ? (double)start_ticks / (double)ticks : 0.0;
    return uptime > started ? (unsigned long)(uptime - started) : 0;
}

static bool php_ok(const rpsiod_site_config *site) {
    if (!site->php_enabled) return true;
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
    rpsiod_site_config tcp_site;
    memset(&tcp_site, 0, sizeof(tcp_site));
    rpsiod_safe_copy(tcp_site.proxy_host, sizeof(tcp_site.proxy_host), site->php_host);
    tcp_site.proxy_port = site->php_port;
    tcp_site.proxy_read_timeout_sec = site->php_read_timeout_sec;
    tcp_site.proxy_write_timeout_sec = site->php_write_timeout_sec;
    int fd = rpsiod_proxy_connect(&tcp_site);
    if (fd >= 0) close(fd);
    return fd >= 0;
}

static bool proxy_ok(const rpsiod_site_config *site) {
    if (!rpsiod_streq_ci(site->routing_type, "proxy")) {
        return true;
    }
    int fd = rpsiod_proxy_connect(site);
    if (fd >= 0) {
        close(fd);
        return true;
    }
    return false;
}

static unsigned count_active_connections(const rpsiod_config *cfg) {
    FILE *fp = fopen("/proc/net/tcp", "r");
    if (fp == NULL) return 0;
    char line[512];
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return 0;
    }
    unsigned count = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned local_port = 0;
        unsigned state = 0;
        if (sscanf(line, " %*d: %*8X:%X %*8X:%*X %X", &local_port, &state) != 2) continue;
        if (state != 1) continue;
        for (size_t i = 0; i < cfg->site_count; i++) {
            if (cfg->sites[i].http_port == local_port || cfg->sites[i].https_port == local_port) {
                count++;
                break;
            }
        }
    }
    fclose(fp);
    return count;
}

int rpsiod_status_main(int argc, char **argv) {
    const char *server_path = NULL;
    const char *sites_path = NULL;
    const char *pid_file = NULL;
    if (parse_args(argc, argv, &server_path, &sites_path, &pid_file) < 0) return 2;
    rpsiod_config *cfg = calloc(1, sizeof(*cfg));
    if (cfg == NULL) return 1;
    char err[1024] = {0};
    if (rpsiod_config_load(cfg, server_path, sites_path, err, sizeof(err)) < 0) {
        fprintf(stderr, "config error: %s\n", err);
        free(cfg);
        return 1;
    }
    long pid = read_pid_file(pid_file);
    printf("rpsiod status\n");
    printf("pid: %ld\n", pid);
    printf("uptime: %lu seconds\n", pid > 0 ? uptime_seconds(pid) : 0);
    printf("workers: %d configured, %d running\n", cfg->workers_auto ? (int)sysconf(_SC_NPROCESSORS_ONLN) : cfg->workers, pid > 0 ? count_worker_processes(pid) : 0);
    printf("active connections: %u\n", count_active_connections(cfg));
    printf("route entries: %zu\n", cfg->route_count);
    printf("open file cache: enabled=%s max=%zu current=worker-local\n",
           cfg->open_file_cache_enabled ? "true" : "false",
           cfg->open_file_cache_max);
    for (size_t i = 0; i < cfg->site_count; i++) {
        rpsiod_site_config *site = &cfg->sites[i];
        printf("site: %s enabled=%s routing=%s http=%u https=%u ssl=%s http2=%s php-fpm=%s proxy=%s\n",
               site->name,
               site->enabled ? "true" : "false",
               site->routing_type,
               site->http_port,
               site->https_port,
               site->ssl_enabled ? "enabled" : "disabled",
               site->ssl_enabled ? "enabled" : "disabled",
               php_ok(site) ? "ok" : "failed",
               rpsiod_streq_ci(site->routing_type, "proxy") ? (proxy_ok(site) ? "ok" : "failed") : "n/a");
    }
    free(cfg);
    return 0;
}
