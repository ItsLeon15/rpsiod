#!/usr/bin/env bash
set -euo pipefail

systemctl disable --now rpsiod.service 2>/dev/null || true
rm -f /etc/systemd/system/rpsiod.service /usr/local/sbin/rpsiod
systemctl daemon-reload
if [[ "${PURGE:-0}" == "1" ]]; then
    rm -rf /etc/rpsiod /var/log/rpsiod /var/cache/rpsiod /var/lib/rpsiod /run/rpsiod /var/www/rpsiod-example /var/www/rpsiod-errors
    echo "rpsiod service, binary, configs, logs, cache, state, runtime directories, and example web roots removed"
else
    echo "rpsiod service and binary removed; configs and runtime data were left in place"
    echo "run 'PURGE=1 scripts/uninstall.sh' to remove /etc/rpsiod and rpsiod runtime data"
fi
