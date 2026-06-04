#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_dir"
make
make install
systemctl daemon-reload
systemctl enable rpsiod.service
systemctl restart rpsiod.service
rpsiod status
