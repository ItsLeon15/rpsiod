# Security Review

Review date: 2026-06-04

Scope:

- `src/http.c`
- `src/http2.c`
- `src/php.c`
- `src/proxy.c`
- `src/tls.c`

## Critical Findings

None open.

## High Findings

None open.

## Medium Findings

None open.

## Low Findings

- `src/proxy.c`: reverse proxy support is intentionally limited to HTTP upstreams. Public documentation notes that HTTPS upstream proxying is unsupported.
- `src/tls.c`: automatic TLS generation currently creates local self-signed certificates when configured certificate material is absent. Public documentation notes that public ACME issuance is not implemented.

## Resolved Findings

- PHP-specific `limits.maxBodySize` parsing was made effective before generic `security.maxBodySize` parsing.
- Static routes with PHP enabled now allow configured PHP methods to reach PHP-FPM while ordinary static files still reject non-GET/HEAD methods.
- HTTP/2 PHP responses are dechunked before submission to the client.
- HTTP/2 TLS responses include HSTS when absent.
- `Server` is hidden by default in site configuration and verified by regression tests.
- Malformed request lines, invalid header names, control header values, negative/overflowing `Content-Length`, `Content-Length` plus `Transfer-Encoding`, and `TRACE` are covered by regression tests.
- Dotfile, sensitive-file, traversal, encoded traversal, PHP source, and PHP chunk-framing protections are covered by `check-rpsiod-issues.sh` and regression tests.

## Verification Commands

```bash
make
bash test.sh
bash check-rpsiod-issues.sh
rpsiod configtest
rpsiod doctor
```

