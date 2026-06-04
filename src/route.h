#ifndef RPSIOD_ROUTE_H
#define RPSIOD_ROUTE_H

#include "config.h"
#include "http.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool rpsiod_route_build_redirect_location(const rpsiod_site_config *site, const rpsiod_http_request *req, uint16_t port,
                                          bool suppress_http_to_https, char *out, size_t out_len, int *status);

#endif
