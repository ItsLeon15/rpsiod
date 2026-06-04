#!/usr/bin/env bash
set -euo pipefail

install -d -m 0755 /etc/rpsiod
install -d -m 0750 /var/log/rpsiod /var/cache/rpsiod /run/rpsiod
install -d -m 0700 /var/lib/rpsiod/ssl
install -d -m 0755 /var/www/rpsiod-example /var/www/rpsiod-errors

if [[ ! -f /etc/rpsiod/server.yml ]]; then
    install -m 0644 /usr/share/rpsiod/config/server.yml /etc/rpsiod/server.yml
fi

if [[ ! -f /etc/rpsiod/sites.yml ]]; then
    install -m 0644 /usr/share/rpsiod/config/sites.yml /etc/rpsiod/sites.yml
fi

if [[ ! -e /var/www/rpsiod-example/index.html && -z "$(find /var/www/rpsiod-example -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]; then
    cp -a /usr/share/rpsiod/www/. /var/www/rpsiod-example/
fi

if [[ ! -e /var/www/rpsiod-errors/404.html && -z "$(find /var/www/rpsiod-errors -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]; then
    cp -a /usr/share/rpsiod/errors/. /var/www/rpsiod-errors/
fi

exec "$@"
