#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")" && pwd)"
python3 "$repo_dir/tests/security_regression.py"
python3 "$repo_dir/tests/streaming_regression.py"

"$repo_dir/build/rpsiod" test --server "$repo_dir/config/server.yml" --sites "$repo_dir/config/sites.yml"
"$repo_dir/build/rpsiod" configtest --server "$repo_dir/examples/server.yml" --sites "$repo_dir/examples/sites.yml"

php_body="$(curl -s http://127.0.0.1/php-test.php)"
if [[ "$php_body" == "PHP_OK" ]]; then
    if curl -s http://127.0.0.1/php-test.php | grep -q '<?php'; then
        echo "PHP source leaked" >&2
        exit 1
    fi

    curl -fsSI -H "Range: bytes=0-99" http://127.0.0.1/large-test.bin | grep -q "206 Partial Content"
    curl -fsSI -H "Accept-Encoding: gzip" http://127.0.0.1/test.js | grep -q "Content-Encoding: gzip"
    printf 'GET / HTTP/1.1\r\nHost: example.com\r\nBad Header: value\r\n\r\n' | nc -w 3 127.0.0.1 80 | grep -q "400 Bad Request"
else
    echo "installed-service smoke skipped: http://127.0.0.1/php-test.php did not return PHP_OK"
fi

echo "smoke tests ok"
