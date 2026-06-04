#ifndef RPSIOD_SECURITY_H
#define RPSIOD_SECURITY_H

#include "config.h"

#include <stdbool.h>

bool rpsiod_blocked_direct_access(const rpsiod_site_config *site, const char *path);

#endif
