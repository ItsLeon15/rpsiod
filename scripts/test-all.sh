#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_dir"
make check
rpsiod configtest
rpsiod doctor
rpsiod test --server /etc/rpsiod/server.yml --sites /etc/rpsiod/sites.yml
bash ./test.sh
