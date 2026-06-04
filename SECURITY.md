# Security Policy

## Supported Versions

This project is under active development. Security fixes should target the current main development line unless a maintained release branch is created.

## Reporting a Vulnerability

Do not publish exploit details before maintainers have had a chance to investigate.

When reporting a vulnerability, include:

- affected commit or release, if known
- operating system and architecture
- relevant configuration snippets with secrets removed
- request/response samples
- crash logs or sanitizer output, if applicable
- whether the issue affects HTTP/1.1, HTTPS, HTTP/2, PHP-FPM, static files, reverse proxying, or WebSockets

## Security Expectations

Changes must not weaken:

- root containment and path traversal protection
- encoded or double-encoded traversal rejection
- dotfile and sensitive-file blocking
- malformed request rejection
- `Content-Length` plus `Transfer-Encoding` rejection
- PHP source exposure protections
- PHP response framing correctness
- TLS 1.0/1.1 disabling
- configured security headers
- FastCGI request handling
- HTTP/2 response framing

Use `check-rpsiod-issues.sh` and `bash test.sh` before publishing security-sensitive changes.

