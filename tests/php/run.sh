#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")/../.." && pwd)"
python3 "$repo_dir/tests/security_regression.py"
python3 "$repo_dir/tests/streaming_regression.py"
