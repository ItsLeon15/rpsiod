#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "config_validate.h"
#include "tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_paths(int argc, char **argv, const char **server_path, const char **sites_path) {
    *server_path = "/etc/rpsiod/server.yml";
    *sites_path = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--server") == 0 && i + 1 < argc) {
            *server_path = argv[++i];
        } else if (strcmp(argv[i], "--sites") == 0 && i + 1 < argc) {
            *sites_path = argv[++i];
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[i]);
            return -1;
        }
    }
    return 0;
}

int rpsiod_config_validate_files(rpsiod_config *cfg, const char *server_path, const char *sites_path, char *err, size_t err_len) {
    if (rpsiod_config_load(cfg, server_path, sites_path, err, err_len) < 0) {
        return -1;
    }
    return rpsiod_tls_validate_material(cfg, err, err_len);
}

int rpsiod_configtest_main(int argc, char **argv) {
    const char *server_path = NULL;
    const char *sites_path = NULL;
    if (parse_paths(argc, argv, &server_path, &sites_path) < 0) {
        return 2;
    }
    rpsiod_config *cfg = calloc(1, sizeof(*cfg));
    if (cfg == NULL) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    char err[1024] = {0};
    if (rpsiod_config_validate_files(cfg, server_path, sites_path, err, sizeof(err)) < 0) {
        fprintf(stderr, "configtest failed: %s\n", err);
        free(cfg);
        return 1;
    }
    printf("configtest ok: %zu site(s), server=%s, sites=%s\n", cfg->site_count, cfg->server_file, cfg->loaded_sites_file);
    free(cfg);
    return 0;
}
