#ifndef __linux__
#error "rpsiod is Linux-only and must be built on Linux."
#endif

#include "perf.h"

rpsiod_perf_counters rpsiod_perf;
