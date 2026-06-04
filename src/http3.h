#ifndef RPSIOD_HTTP3_H
#define RPSIOD_HTTP3_H

#include "config.h"
#include "log.h"

#include <stdbool.h>

bool rpsiod_http3_library_available(void);
void rpsiod_http3_log_status(const rpsiod_config *cfg, rpsiod_logger *logger);

#endif
