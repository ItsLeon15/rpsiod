# Contributing

`rpsiod` is a Linux-only C web server. Changes should preserve security, correctness, and operational behavior before style or cleanup.

## Development Rules

- Do not weaken path traversal, blocked-file, malformed-request, TLS, PHP source, or request-smuggling protections.
- Do not add configuration options when a secure internal default is enough.
- Keep behavior changes narrow and covered by tests.
- Do not commit generated binaries, object files, logs, benchmark output, security reports, certificates, or local environment files.
- Prefer existing project patterns over new abstractions.

## Build

```bash
make
make check
```

## Test

Run the core regression suite:

```bash
bash test.sh
```

Run the security checker:

```bash
TARGET_URL="https://example.com" \
LOCAL_URL="http://127.0.0.1" \
HOST_HEADER="example.com" \
./check-rpsiod-issues.sh
```

Optional diagnostics:

```bash
rpsiod doctor
rpsiod bench all
scripts/perf-regression.sh
```

## Pull Request Checklist

- Build passes with `make`.
- Config validation passes with `make check`.
- Regression tests pass with `bash test.sh`.
- Security checker has zero failures.
- Any remaining warnings are documented and non-security-related.
- Runtime behavior changes are described clearly.
- Generated artifacts are not included.

## Release Hygiene

Before publishing, verify:

```bash
make clean
find . -maxdepth 3 \( -path './build' -o -name '*.o' -o -name 'rpsiod' -o -name '*.log' -o -name '*.tmp' \) -print
```

The `find` command should not list generated files in the repository root or source tree.
