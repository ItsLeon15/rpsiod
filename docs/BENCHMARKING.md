# Benchmarking

`rpsiod` includes built-in benchmark commands for local evaluation.

## Static Benchmark

```bash
rpsiod bench static --site "Example Website" --path /index.html --connections 100 --duration 10s
```

Reports are written under the configured benchmark storage path, usually:

```txt
/var/cache/rpsiod/benchmarks/
```

## Page Benchmark

HTTP/2 page timing uses `nghttp` when available:

```bash
rpsiod bench page --url https://example.com/pma/ --protocol h2
```

HTTP/1.1 HTTPS document timing uses `curl`:

```bash
rpsiod bench page --url https://example.com/pma/ --protocol http1
```

## wrk Smoke Test

For a virtual-hosted site, include the host header:

```bash
wrk -t12 -c400 -d30s -H "Host: example.com" http://127.0.0.1/index.html
```

Without the correct host header, results may measure the default site, a redirect, or a 404 instead of the intended application.

## Regression Comparison

```bash
rpsiod bench compare --before old-report.txt --after new-report.txt
scripts/perf-regression.sh old-report.txt new-report.txt
```

