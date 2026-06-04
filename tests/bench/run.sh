#!/usr/bin/env bash
set -euo pipefail

command -v rpsiod >/dev/null 2>&1
rpsiod bench all
