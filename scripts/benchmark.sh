#!/usr/bin/env bash
set -euo pipefail

rpsiod bench static --site "Example Website" --path /index.html --connections "${CONNECTIONS:-250}" --duration "${DURATION:-15s}"
