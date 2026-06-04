#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")/../.." && pwd)"
"$repo_dir/build/rpsiod" test --server "$repo_dir/config/server.yml" --sites "$repo_dir/config/sites.yml"
