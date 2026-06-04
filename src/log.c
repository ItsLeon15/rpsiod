#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "log.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void timestamp(char *buf, size_t len) {
    time_t now = time(NULL);
    struct tm tmv;
    gmtime_r(&now, &tmv);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", &tmv);
}

int rpsiod_log_open(rpsiod_logger *logger, rpsiod_config *cfg) {
    logger->access_fd = STDERR_FILENO;
    logger->error_fd = STDERR_FILENO;
    if (cfg->access_log.enabled) {
        int fd = rpsiod_open_append(cfg->access_log.path);
        if (fd >= 0) {
            logger->access_fd = fd;
            cfg->access_log.fd = fd;
        }
    }
    if (cfg->error_log.enabled) {
        int fd = rpsiod_open_append(cfg->error_log.path);
        if (fd >= 0) {
            logger->error_fd = fd;
            cfg->error_log.fd = fd;
        }
    }
    for (size_t i = 0; i < cfg->site_count; i++) {
        if (cfg->sites[i].access_log.enabled) {
            int fd = rpsiod_open_append(cfg->sites[i].access_log.path);
            if (fd >= 0) {
                cfg->sites[i].access_log.fd = fd;
            }
        }
        if (cfg->sites[i].error_log.enabled) {
            int fd = rpsiod_open_append(cfg->sites[i].error_log.path);
            if (fd >= 0) {
                cfg->sites[i].error_log.fd = fd;
            }
        }
    }
    return 0;
}

void rpsiod_log_close(rpsiod_logger *logger) {
    if (logger->access_fd > STDERR_FILENO) {
        close(logger->access_fd);
    }
    if (logger->error_fd > STDERR_FILENO && logger->error_fd != logger->access_fd) {
        close(logger->error_fd);
    }
}

void rpsiod_log_vwrite(int fd, const char *level, const char *fmt, va_list ap) {
    char ts[64];
    timestamp(ts, sizeof(ts));
    char msg[2048];
    vsnprintf(msg, sizeof(msg), fmt, ap);
    char line[2300];
    int len = snprintf(line, sizeof(line), "%s rpsiod[%ld]: %s %s\n", ts, (long)getpid(), level, msg);
    if (len > 0) {
        (void)rpsiod_write_all(fd, line, (size_t)len);
    }
}

void rpsiod_log_error(rpsiod_logger *logger, const rpsiod_site_config *site, const char *fmt, ...) {
    int fd = logger->error_fd;
    if (site != NULL && site->error_log.enabled && site->error_log.fd >= 0) {
        fd = site->error_log.fd;
    }
    va_list ap;
    va_start(ap, fmt);
    rpsiod_log_vwrite(fd, "error", fmt, ap);
    va_end(ap);
}

void rpsiod_log_access(rpsiod_logger *logger, const rpsiod_site_config *site, const char *client, const char *method, const char *path, int status, unsigned long long bytes) {
    int fd = logger->access_fd;
    if (site != NULL && site->access_log.enabled && site->access_log.fd >= 0) {
        fd = site->access_log.fd;
    }
    char ts[64];
    timestamp(ts, sizeof(ts));
    char line[2300];
    int len = snprintf(line, sizeof(line), "%s %s \"%s %s\" %d %llu\n",
                       ts, client != NULL ? client : "-", method != NULL ? method : "-",
                       path != NULL ? path : "-", status, bytes);
    if (len > 0) {
        (void)rpsiod_write_all(fd, line, (size_t)len);
    }
}
