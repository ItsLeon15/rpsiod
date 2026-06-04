#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "static.h"

#include <fcntl.h>
#include <linux/openat2.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

const char *rpsiod_static_relative_request_path(const char *request_path) {
    while (*request_path == '/') {
        request_path++;
    }
    return request_path[0] == '\0' ? "." : request_path;
}

int rpsiod_static_open_site_path(const rpsiod_site_config *site, const char *relative_path) {
    struct open_how how;
    memset(&how, 0, sizeof(how));
    how.flags = O_RDONLY | O_CLOEXEC;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
    if (!site->allow_symlinks) {
        how.resolve |= RESOLVE_NO_SYMLINKS;
    }
    return (int)syscall(SYS_openat2, site->static_root_fd, relative_path, &how, sizeof(how));
}
