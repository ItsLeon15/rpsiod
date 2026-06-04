#ifndef RPSIOD_PROXY_H
#define RPSIOD_PROXY_H

#include "config.h"

#include <stdbool.h>
#include <stddef.h>

bool rpsiod_proxy_skip_header(const char *line, size_t line_len);
int rpsiod_proxy_connect(const rpsiod_site_config *site);
int rpsiod_proxy_parse_response_status(const char *buf, size_t len);

#endif
