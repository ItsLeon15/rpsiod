#!/usr/bin/env bash
set -euo pipefail

PID_FILE="${PID_FILE:-/run/rpsiod/rpsiod.pid}"
DURATION="${DURATION:-30}"
OUT_DIR="${OUT_DIR:-/var/cache/rpsiod/benchmarks/profile-$(date +%Y%m%d-%H%M%S)}"

if [[ ! -r "$PID_FILE" ]]; then
    echo "pid file not readable: $PID_FILE" >&2
    exit 1
fi

PID="$(cat "$PID_FILE")"
mkdir -p "$OUT_DIR"

echo "rpsiod profiling target pid: $PID"
echo "output directory: $OUT_DIR"
echo
echo "Run live perf top:"
echo "  perf top -p $PID"
echo
echo "Recording perf samples for ${DURATION}s..."
perf record -F 99 -p "$PID" -g -- sleep "$DURATION" || true
if [[ -f perf.data ]]; then
    mv perf.data "$OUT_DIR/perf.data"
    perf report -i "$OUT_DIR/perf.data" --stdio > "$OUT_DIR/perf-report.txt" || true
    echo "perf report: $OUT_DIR/perf-report.txt"
fi

echo "Collecting syscall summary for ${DURATION}s..."
timeout "$DURATION" strace -c -p "$PID" -o "$OUT_DIR/strace-summary.txt" || true
echo "strace summary: $OUT_DIR/strace-summary.txt"

echo "Watching FD count and RSS for ${DURATION}s..."
{
    echo "second fd_count rss_kb"
    for ((i = 0; i < DURATION; i++)); do
        fd_count="$(find "/proc/$PID/fd" -maxdepth 1 -type l 2>/dev/null | wc -l || true)"
        rss_kb="$(awk '/VmRSS:/ {print $2}' "/proc/$PID/status" 2>/dev/null || echo 0)"
        echo "$i $fd_count $rss_kb"
        sleep 1
    done
} > "$OUT_DIR/fd-rss-watch.txt"
echo "FD/RSS watch: $OUT_DIR/fd-rss-watch.txt"
