#!/usr/bin/env bash
set -euo pipefail

rpsiod configtest
rpsiod reload
rpsiod status
