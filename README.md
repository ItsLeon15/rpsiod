# rpsiod

rpsiod (pronounced "Rip-see-oid") is an experimental C-based web server for Linux, designed for static file serving, PHP-FPM, HTTPS, HTTP/2, reverse proxying, WebSocket tunneling, and operational diagnostics.

It is built around an epoll-based HTTP/1.1 core, OpenSSL TLS support, nghttp2 HTTP/2 support, sendfile static delivery, FastCGI/PHP-FPM integration, virtual hosts, security-focused request validation, and built-in tooling for testing, tracing, benchmarking, and diagnostics.

The project is currently in developer beta and should not be used in production environments.

## Status

`rpsiod` is under active development. It is intended for Linux hosts and systemd-based deployments.

## Features

- C-based Linux web server
- Static file serving with `sendfile`
- HTTPS with OpenSSL
- HTTP/2 over TLS using nghttp2
- PHP-FPM/FastCGI support
- Reverse proxy support
- WebSocket proxy tunneling
- Virtual host configuration
- Built-in config validation, doctor checks, tracing, and benchmarking
- Security-focused request parsing and path validation

## License

This project is currently distributed without an open-source license. See [LICENSE](LICENSE).

## Requirements

Build requirements:

- Linux
- C compiler with C11/GNU extensions
- `make`
- OpenSSL development headers
- nghttp2 development headers
- ngtcp2 development headers if building the current tree as-is
- pthreads and standard Linux system headers

Useful test and diagnostic tools:

- `python3`
- `curl`
- `nc`
- `wrk`
- `cppcheck`
- `openssl`

## Build

```bash
make
make check
```

The build produces `build/rpsiod`. The binary, objects, and `build/` directory are generated artifacts and are ignored by Git.

## Test

```bash
bash test.sh
./check-rpsiod-issues.sh
```

The security checker writes reports under `security-check-results/`, which is ignored by Git.

By default the checker targets a local install using `https://localhost` and `Host: localhost`. For live checks, set the target explicitly:

```bash
TARGET_URL="https://example.com" \
LOCAL_URL="http://127.0.0.1" \
HOST_HEADER="example.com" \
./check-rpsiod-issues.sh
```

## Run Locally

```bash
./build/rpsiod serve --server examples/server.yml --sites examples/sites.yml
```

Then request the example site:

```bash
curl -H 'Host: localhost' http://127.0.0.1:8080/
```

## Docker

```bash
docker compose up --build
```

Compose publishes HTTP on `localhost:8080` and HTTPS on `localhost:8443`. It bind-mounts `./config`, `./docker/www`, and `./www/rpsiod-errors`; the container does not overwrite existing files in those mount locations.

See [Docker](docs/DOCKER.md).

## Install

The helper script builds, installs symlinks, enables the service, and restarts it:

```bash
scripts/install.sh
```

Equivalent manual install:

```bash
make
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now rpsiod
```

Uninstall without removing user configuration:

```bash
sudo make uninstall
```

Remove configuration and runtime data as well:

```bash
sudo make uninstall PURGE=1
```

The installed service expects:

```txt
/etc/rpsiod/server.yml
/etc/rpsiod/sites.yml
/etc/systemd/system/rpsiod.service
/usr/local/sbin/rpsiod
```

`make install` creates the `rpsiod` system user/group when missing and installs the shipped example site and error pages under:

```txt
/var/www/rpsiod-example/
/var/www/rpsiod-errors/
```

Runtime paths:

```txt
/run/rpsiod/
/var/log/rpsiod/
/var/cache/rpsiod/
/var/lib/rpsiod/ssl/
```

## CLI

```bash
rpsiod serve [--server /etc/rpsiod/server.yml] [--sites /etc/rpsiod/sites.yml]
rpsiod configtest [--server /etc/rpsiod/server.yml] [--sites /etc/rpsiod/sites.yml]
rpsiod config-check [--server /etc/rpsiod/server.yml] [--sites /etc/rpsiod/sites.yml]
rpsiod test [--server /etc/rpsiod/server.yml] [--sites /etc/rpsiod/sites.yml]
rpsiod status
rpsiod reload
rpsiod doctor
rpsiod trace request --host example.com --path /
rpsiod bench static --site "Example Website" --path /index.html --connections 1000 --duration 30s
rpsiod bench page --url https://example.com/pma/ --protocol h2
rpsiod bench page --url https://example.com/pma/ --protocol http1
rpsiod bench all --site "Example Website"
```

## Repository Layout

```txt
src/                    C source and headers
config/                 local deployment config
examples/               example configs and example site files
packaging/              packaging-oriented config and service templates
scripts/                install, reload, benchmark, and profiling helpers
tests/                  Python regression tests and test configs
test-fixtures/          fixture files used by tests
www/rpsiod-errors/      default error pages
check-rpsiod-issues.sh  automated security and runtime checker
test.sh                 project smoke/regression test runner
```

Additional documentation:

- [Configuration](docs/CONFIGURATION.md)
- [Installation](docs/INSTALLATION.md)
- [Security](docs/SECURITY.md)
- [Benchmarking](docs/BENCHMARKING.md)
- [Docker](docs/DOCKER.md)
- [PHP-FPM](docs/PHP.md)
- [Security Review](docs/security-review.md)
- [Source Audit](docs/source-audit.md)

## Security Notes

The default posture is conservative:

- dotfiles and common sensitive paths are blocked
- path traversal and encoded traversal are rejected
- malformed header names and conflicting `Content-Length`/`Transfer-Encoding` are rejected
- `TRACE` is blocked
- PHP source files are not served as static text
- TLS 1.0 and TLS 1.1 are disabled
- `Server` is hidden by default in site configuration
- HSTS is added on HTTPS responses when absent

See [SECURITY.md](SECURITY.md) for reporting guidance.
