# Changelog

All notable changes should be documented in this file.

This project does not currently publish versioned releases. Entries are grouped by development state until release tags exist.

## Unreleased

- Added automated security checker for source-level, build, runtime, HTTP, PHP, TLS, benchmark, and FD-leak checks.
- Hardened default response header behavior and HTTPS security headers.
- Added regressions for malformed requests, PHP source blocking, PHP response framing, PHP body limits, static POST handling, and HTTP/2 PHP responses.
- Added browser-style page benchmark support for HTTP/2 and HTTP/1.1 comparison.
- Improved HTTP/2 loopback scheduling and PHP response dechunking.
- Added publish-oriented repository metadata and cleanup rules.

