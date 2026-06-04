# Source Audit

Review date: 2026-06-04

## Large Files

Files larger than 20KB:

- `src/server.c`: main maintenance hotspot; contains response helpers, static serving, PHP/FastCGI dispatch, proxy/WebSocket handling, event loop, listener setup, and worker lifecycle.
- `src/config.c`: large but cohesive around parsing, site application, validation, and route construction.
- `src/bench.c`: large but isolated to CLI benchmarking.
- `src/http2.c`: large but cohesive around the HTTP/2 TLS loopback bridge.

## Refactor Decision

No large behavior-preserving source split was performed for this release pass.

Reasoning:

- `src/server.c` has clear future split boundaries, but it also owns central request and connection lifecycle state. A split immediately before public release would add risk without changing runtime behavior.
- `src/http2.c` contains recent correctness-sensitive fixes for PHP response dechunking and stream scheduling. It should remain stable until further targeted HTTP/2 work is required.
- `src/config.c` and `src/bench.c` are large but not immediate release blockers.

Recommended future split order:

1. `server_response.c` for response/header helpers.
2. `server_static.c` for static file metadata, ranges, validators, compression, and file send logic.
3. `server_php.c` for PHP/FastCGI request dispatch.
4. `server_proxy.c` for proxy and WebSocket tunnel handling.
5. `server_worker.c` for listener and event-loop lifecycle.

Any split should be mechanical, behavior-preserving, and followed by:

```bash
make clean
make
bash test.sh
bash check-rpsiod-issues.sh
```

## Hygiene Search

Reviewed markers:

```txt
TODO
FIXME
HACK
TEMP
DEBUG
XXX
```

No actionable source hygiene markers were found. Matches are constants or third-party library names such as `NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`.

## Dead Code Review

Reviewed previously suspicious patterns:

- delayed HTTP/2 loopback retry helper
- empty host checks
- compression branch conditions
- TLS cert/key existence checks
- static metadata null checks

No open dead-code or duplicate-condition release blockers remain.

