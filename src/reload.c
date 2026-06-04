#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "reload.h"
#include "util.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int parse_pid_file(int argc, char **argv, const char **pid_file) {
    *pid_file = "/run/rpsiod/rpsiod.pid";
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--pid-file") == 0 && i + 1 < argc) {
            *pid_file = argv[++i];
        } else {
            fprintf(stderr, "unknown reload argument: %s\n", argv[i]);
            return -1;
        }
    }
    return 0;
}

int rpsiod_reload_main(int argc, char **argv) {
    const char *pid_file = NULL;
    if (parse_pid_file(argc, argv, &pid_file) < 0) {
        return 2;
    }
    FILE *fp = fopen(pid_file, "r");
    if (fp == NULL) {
        perror("open pid file");
        return 1;
    }
    long pid = 0;
    if (fscanf(fp, "%ld", &pid) != 1 || pid <= 1) {
        fclose(fp);
        fprintf(stderr, "invalid pid file: %s\n", pid_file);
        return 1;
    }
    fclose(fp);
    if (kill((pid_t)pid, SIGHUP) < 0) {
        perror("reload signal");
        return 1;
    }
    printf("reload signaled: pid %ld\n", pid);
    return 0;
}
