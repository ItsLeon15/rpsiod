#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "security.h"

#include <string.h>

bool rpsiod_blocked_direct_access(const rpsiod_site_config *site, const char *path) {
    for (size_t i = 0; i < site->blocked_direct_access_count; i++) {
        const char *blocked = site->blocked_direct_access[i];
        size_t blocked_len = strlen(blocked);
        const char *p = path;
        while ((p = strstr(p, blocked)) != NULL) {
            bool left_ok = (p == path) || (p[-1] == '/');
            bool right_ok = (p[blocked_len] == '\0') || (p[blocked_len] == '/');
            if (left_ok && right_ok) {
                return true;
            }
            p += blocked_len;
        }
    }
    return false;
}
