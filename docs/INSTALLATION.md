# Installation

## Build

```bash
make
```

The binary is written to:

```txt
build/rpsiod
```

## Install

```bash
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now rpsiod
```

`make install` creates the required directories and installs:

```txt
/usr/local/sbin/rpsiod
/etc/systemd/system/rpsiod.service
/etc/rpsiod/server.yml
/etc/rpsiod/sites.yml
/var/log/rpsiod/
/var/cache/rpsiod/
/var/lib/rpsiod/
/run/rpsiod/
/var/www/rpsiod-example/
/var/www/rpsiod-errors/
```

Existing `/etc/rpsiod/server.yml` and `/etc/rpsiod/sites.yml` are not overwritten.

The install target creates the `rpsiod` system user and group if they do not already exist.

## Verify

```bash
rpsiod configtest
rpsiod doctor
systemctl status rpsiod
```

## Reload

```bash
rpsiod configtest
sudo systemctl reload rpsiod
```

## Uninstall

Remove the service and installed binary while preserving user configuration and runtime data:

```bash
sudo make uninstall
```

Remove configuration and runtime data as well:

```bash
sudo make uninstall PURGE=1
```
