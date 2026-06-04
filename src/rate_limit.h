#ifndef RPSIOD_RATE_LIMIT_H
#define RPSIOD_RATE_LIMIT_H

#include "config.h"

#include <stdbool.h>

bool rpsiod_rate_limit_exceeded(rpsiod_site_config *site, const char *client_ip, int *retry_after);

#endif
