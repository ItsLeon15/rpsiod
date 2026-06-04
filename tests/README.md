# Tests

The regression suite has top-level smoke scripts and category wrappers.

Coverage map:

- security: `tests/security_regression.py`
- PHP/FastCGI: `tests/security_regression.py`, `tests/streaming_regression.py`, `tests/php/index.php`
- static files: `build/rpsiod test --server config/server.yml --sites config/sites.yml`
- proxy: `build/rpsiod test --server config/server.yml --sites config/sites.yml`, `tests/fake_ws.py`
- config: `make check`, `build/rpsiod configtest`
- benchmark commands: `rpsiod bench all`, `scripts/perf-regression.sh`
- HTTP/2 regressions: `tests/streaming_regression.py`

Run:

```bash
make
bash test.sh
```

Category wrappers:

```bash
bash tests/security/run.sh
bash tests/php/run.sh
bash tests/static/run.sh
bash tests/proxy/run.sh
bash tests/config/run.sh
bash tests/bench/run.sh
```
