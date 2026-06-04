#ifndef RPSIOD_STATIC_H
#define RPSIOD_STATIC_H

#include "config.h"

const char *rpsiod_static_relative_request_path(const char *request_path);
int rpsiod_static_open_site_path(const rpsiod_site_config *site, const char *relative_path);

#endif
