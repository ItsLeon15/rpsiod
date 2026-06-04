#!/usr/bin/env bash
set -euo pipefail

BEFORE="${1:-}"
AFTER="${2:-}"

if [[ -z "$BEFORE" || -z "$AFTER" || ! -r "$BEFORE" || ! -r "$AFTER" ]]; then
    echo "usage: scripts/perf-regression.sh before-report.txt after-report.txt" >&2
    exit 2
fi

metric() {
    local file="$1"
    local name="$2"
    awk -F': ' -v key="$name" '$1 == key {print $2; exit}' "$file" | awk '{print $1}'
}

fail_if_gt() {
    local label="$1"
    local value="$2"
    local limit="$3"
    awk -v value="$value" -v limit="$limit" -v label="$label" 'BEGIN {
        if (value > limit) {
            printf "%s regression: %.6f > %.6f\n", label, value, limit > "/dev/stderr";
            exit 1;
        }
    }'
}

before_rps="$(metric "$BEFORE" "requests per second")"
after_rps="$(metric "$AFTER" "requests per second")"
before_p99="$(metric "$BEFORE" "p99 latency")"
after_p99="$(metric "$AFTER" "p99 latency")"
after_failed="$(metric "$AFTER" "failed requests")"
before_rss="$(metric "$BEFORE" "current RSS")"
after_rss="$(metric "$AFTER" "current RSS")"

rps_drop_pct="$(awk -v before="$before_rps" -v after="$after_rps" 'BEGIN { if (before == 0) print 0; else print ((before - after) / before) * 100 }')"
p99_increase_pct="$(awk -v before="$before_p99" -v after="$after_p99" 'BEGIN { if (before == 0) print 0; else print ((after - before) / before) * 100 }')"
rss_growth_pct="$(awk -v before="$before_rss" -v after="$after_rss" 'BEGIN { if (before == 0) print 0; else print ((after - before) / before) * 100 }')"

fail_if_gt "requests/sec drop" "$rps_drop_pct" 20
fail_if_gt "p99 latency increase" "$p99_increase_pct" 50
fail_if_gt "failed requests" "$after_failed" 0
fail_if_gt "RSS growth" "$rss_growth_pct" 25

rpsiod bench compare --before "$BEFORE" --after "$AFTER"
echo "performance regression checks ok"
