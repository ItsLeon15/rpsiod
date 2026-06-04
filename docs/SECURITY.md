# Security

This document summarizes the security posture expected for release evaluation.

## Request Validation

The server rejects malformed request lines, malformed header names, control characters in header values, negative or overflowing `Content-Length`, and requests containing both `Content-Length` and `Transfer-Encoding`.

`TRACE` is blocked.

## Path Safety

Static paths are percent-decoded before validation. Traversal attempts, encoded traversal, and forbidden segments are rejected before file access. File serving remains constrained to the configured static root.

Sensitive paths such as `.env`, `.git`, `.htaccess`, `composer.json`, `composer.lock`, and `storage` should be blocked in site configuration.

## PHP-FPM

PHP source files must not be served as static text. PHP responses must not expose FastCGI or internal HTTP chunk framing. PHP-specific body limits are enforced before forwarding to FastCGI.

See [PHP.md](PHP.md).

## TLS

TLS 1.0 and TLS 1.1 are disabled. TLS 1.2 and TLS 1.3 are expected to work when configured. HTTPS responses should hide the `Server` header by default and include HSTS when absent.

## HTTP/2

HTTP/2 responses must not expose hop-by-hop HTTP/1.1 headers or chunk framing. PHP responses over HTTP/2 are regression-tested for dechunking.

## Verification

```bash
bash test.sh
bash check-rpsiod-issues.sh
```

The checker covers source patterns, compiler warnings, ASAN/UBSAN build status, config tools, traversal probes, malformed headers, PHP source/chunk leaks, headers, TLS, wrk smoke, and FD growth.

When phpMyAdmin is not installed, the checker skips the phpMyAdmin-specific PHP chunk-framing URL. Set `PHP_TEST_URL` to a deployed PHP endpoint when validating a PHP application.
