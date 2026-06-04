#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "route.h"
#include "util.h"

#include <stdio.h>
#include <string.h>

bool rpsiod_route_build_redirect_location(const rpsiod_site_config *site, const rpsiod_http_request *req, uint16_t port,
                                          bool suppress_http_to_https, char *out, size_t out_len, int *status) {
    const char *host = req->host[0] != '\0' ? req->host : site->domains[0];
    char target_host[256];
    rpsiod_safe_copy(target_host, sizeof(target_host), host);
    bool changed = false;
    bool https = false;

    if (!suppress_http_to_https && site->redirect_http_to_https && port == site->http_port && site->https_port != 0) {
        https = true;
        *status = 301;
        changed = true;
    }

    if (site->redirect_www_enabled) {
        if (rpsiod_streq_ci(site->redirect_www_mode, "apexToWww") && strncmp(target_host, "www.", 4) != 0) {
            char tmp[256];
            if (snprintf(tmp, sizeof(tmp), "www.%s", target_host) < (int)sizeof(tmp)) {
                rpsiod_safe_copy(target_host, sizeof(target_host), tmp);
                *status = site->redirect_www_status;
                changed = true;
            }
        } else if (rpsiod_streq_ci(site->redirect_www_mode, "wwwToApex") && strncmp(target_host, "www.", 4) == 0) {
            memmove(target_host, target_host + 4, strlen(target_host + 4) + 1);
            *status = site->redirect_www_status;
            changed = true;
        }
    }

    if (!changed) {
        return false;
    }
    const char *scheme = https || rpsiod_streq_ci(site->serve_as, "https") ? "https" : "http";
    bool include_port = (strcmp(scheme, "http") == 0 && site->http_port != 80) ||
                        (strcmp(scheme, "https") == 0 && site->https_port != 443);
    int n;
    if (include_port) {
        uint16_t out_port = strcmp(scheme, "https") == 0 ? site->https_port : site->http_port;
        n = snprintf(out, out_len, "%s://%s:%u%s", scheme, target_host, out_port, req->path);
    } else {
        n = snprintf(out, out_len, "%s://%s%s", scheme, target_host, req->path);
    }
    return n > 0 && (size_t)n < out_len;
}
