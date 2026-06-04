# Configuration

`rpsiod` uses two YAML-like configuration files:

```txt
/etc/rpsiod/server.yml
/etc/rpsiod/sites.yml
```

Use `--server` and `--sites` to test alternate files:

```bash
rpsiod configtest --server examples/server.yml --sites examples/sites.yml
```

## Server Configuration

`server.yml` controls process-level behavior:

- Linux user/group and PID file
- socket backlog and reuse settings
- worker and connection limits
- keep-alive and buffer sizing
- logging paths
- benchmark report storage
- path to `sites.yml`

Runtime directories used by the default packaging:

```txt
/run/rpsiod/
/var/log/rpsiod/
/var/cache/rpsiod/
/var/lib/rpsiod/ssl/
```

## Site Configuration

`sites.yml` defines virtual hosts:

- matching domains
- HTTP and HTTPS listener ports
- TLS settings
- redirects
- routing mode
- static document root and index files
- PHP-FPM handler settings
- maintenance and error pages
- security policy
- compression, cache, headers, and logging

## Security Defaults

Recommended site settings:

```yaml
security:
    maxBodySize: 25mb
    hideServerHeader: true
    allowSymlinks: false
    allowedMethods:
        - GET
        - HEAD
        - POST
```

Common sensitive files should remain blocked under PHP security settings:

```yaml
php:
    security:
        blockDirectAccess:
            - .env
            - composer.json
            - composer.lock
            - .git
            - .gitignore
            - .htaccess
            - storage
```

## Validation

Run:

```bash
rpsiod configtest
rpsiod doctor
```

`configtest` validates configuration structure. `doctor` checks runtime paths, user/group setup, PHP-FPM reachability, blocked-file settings, and other operational prerequisites.

The repository default config is intentionally neutral and uses localhost/example domains. Live deployment domains, public IP addresses, private email addresses, and certificate material should not be committed.
