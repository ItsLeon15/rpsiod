#ifndef RPSIOD_CONFIG_VALIDATE_H
#define RPSIOD_CONFIG_VALIDATE_H

#include "config.h"

#include <stddef.h>

int rpsiod_config_validate_files(rpsiod_config *cfg, const char *server_path, const char *sites_path, char *err, size_t err_len);
int rpsiod_configtest_main(int argc, char **argv);

#endif
