#ifndef RPSIOD_PERF_H
#define RPSIOD_PERF_H

#include <stdatomic.h>
#include <stdint.h>

typedef struct {
    atomic_ullong accepted_connections;
    atomic_ullong closed_connections;
    atomic_ullong active_connections;
    atomic_ullong peak_active_connections;
    atomic_ullong keep_alive_reused_requests;
    atomic_ullong read_errors;
    atomic_ullong write_errors;
    atomic_ullong socket_errors;
    atomic_ullong sendfile_calls;
    atomic_ullong sendfile_bytes;
    atomic_ullong fallback_read_write_count;
    atomic_ullong cache_hits;
    atomic_ullong cache_misses;
    atomic_ullong file_stat_calls;
} rpsiod_perf_counters;

extern rpsiod_perf_counters rpsiod_perf;

static inline void rpsiod_perf_inc(atomic_ullong *counter) {
    atomic_fetch_add_explicit(counter, 1, memory_order_relaxed);
}

static inline void rpsiod_perf_add(atomic_ullong *counter, unsigned long long value) {
    atomic_fetch_add_explicit(counter, value, memory_order_relaxed);
}

static inline unsigned long long rpsiod_perf_get(const atomic_ullong *counter) {
    return atomic_load_explicit((atomic_ullong *)counter, memory_order_relaxed);
}

#endif
