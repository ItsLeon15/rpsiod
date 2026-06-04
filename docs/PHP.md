# PHP-FPM

`rpsiod` can forward PHP requests to PHP-FPM over a Unix socket or TCP.

## Unix Socket Example

```yaml
php:
    enabled: true
    mode: fpm
    handler:
        type: socket
        socket: /run/php/php-fpm.sock
    security:
        allowPathInfo: false
```

## TCP Example

```yaml
php:
    enabled: true
    mode: fpm
    handler:
        type: tcp
        host: 127.0.0.1
        port: 9000
```

## Security

Keep sensitive files blocked:

```yaml
php:
    security:
        blockDirectAccess:
            - .env
            - composer.json
            - composer.lock
            - .git
            - .htaccess
            - storage
```

PHP source files should never be served as static content. The regression tests and security checker verify that PHP source does not leak and that chunk framing does not appear in PHP responses.

## Validation

```bash
rpsiod doctor
bash test.sh
```

