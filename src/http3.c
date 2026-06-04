#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "http3.h"

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>

bool rpsiod_http3_library_available(void) {
    return ngtcp2_version(0) != NULL && nghttp3_version(0) != NULL;
}

void rpsiod_http3_log_status(const rpsiod_config *cfg, rpsiod_logger *logger) {
    if (cfg == NULL || logger == NULL || !rpsiod_http3_library_available()) {
        return;
    }
    const ngtcp2_info *tcp2 = ngtcp2_version(0);
    const nghttp3_info *http3 = nghttp3_version(0);
    rpsiod_log_error(logger, NULL, "HTTP/3 QUIC libraries available: ngtcp2=%s nghttp3=%s",
                     tcp2 != NULL ? tcp2->version_str : "unknown",
                     http3 != NULL ? http3->version_str : "unknown");
}
