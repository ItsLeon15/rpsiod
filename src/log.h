#ifndef RPSIOD_LOG_H
#define RPSIOD_LOG_H

#include "config.h"

#include <stdarg.h>

typedef struct {
    int access_fd;
    int error_fd;
} rpsiod_logger;

int rpsiod_log_open(rpsiod_logger *logger, rpsiod_config *cfg);
void rpsiod_log_close(rpsiod_logger *logger);
void rpsiod_log_error(rpsiod_logger *logger, const rpsiod_site_config *site, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
void rpsiod_log_access(rpsiod_logger *logger, const rpsiod_site_config *site, const char *client, const char *method, const char *path, int status, unsigned long long bytes);
void rpsiod_log_vwrite(int fd, const char *level, const char *fmt, va_list ap);

#endif
