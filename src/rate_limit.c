#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "rate_limit.h"
#include "util.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <time.h>

bool rpsiod_rate_limit_exceeded(rpsiod_site_config *site, const char *client_ip, int *retry_after) {
    if (retry_after != NULL) {
        *retry_after = 0;
    }
    if (!site->rate_limit_enabled || site->rate_limit_requests == 0 || site->rate_limit_window_sec <= 0) {
        return false;
    }
    struct in_addr addr;
    if (inet_pton(AF_INET, client_ip, &addr) != 1) {
        return false;
    }
    uint32_t ip = ntohl(addr.s_addr);
    size_t idx = (size_t)(ip % RPSIOD_RATE_BUCKETS);
    rpsiod_rate_bucket *bucket = &site->rate_buckets[idx];
    uint64_t now = (uint64_t)time(NULL);
    if (bucket->ip != ip || now >= bucket->window_start + (uint64_t)site->rate_limit_window_sec) {
        bucket->ip = ip;
        bucket->window_start = now;
        bucket->count = 1;
        return false;
    }
    if (bucket->count >= site->rate_limit_requests) {
        if (retry_after != NULL) {
            uint64_t reset = bucket->window_start + (uint64_t)site->rate_limit_window_sec;
            *retry_after = reset > now ? (int)(reset - now) : 1;
        }
        return true;
    }
    bucket->count++;
    return false;
}
