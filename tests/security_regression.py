#!/usr/bin/env python3
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "build" / "rpsiod"
HOST = "127.0.0.1"
STATIC_HOST = "security-static.local"
PHP_LIMIT_HOST = "security-php-limit.local"


def reserve_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def write_config(workdir, static_port, php_limit_port, unused_fcgi_port, bench_port):
    docroot = workdir / "www"
    docroot.mkdir()
    (docroot / "index.html").write_text("SECURITY_INDEX\n", encoding="utf-8")
    (docroot / "ok.txt").write_text("PIPELINE_OK\n", encoding="utf-8")
    (docroot / "smuggled.txt").write_text("SMUGGLED\n", encoding="utf-8")
    (docroot / "space name.txt").write_text("SPACE_OK\n", encoding="utf-8")
    (docroot / "source.php").write_text("<?php echo 'LEAK';\n", encoding="utf-8")
    php_docroot = workdir / "php"
    php_docroot.mkdir()
    (php_docroot / "index.php").write_text("<?php echo 'SHOULD_NOT_RUN';\n", encoding="utf-8")

    server = workdir / "server.yml"
    sites = workdir / "sites.yml"
    server.write_text(
        f"""server:
    name: rpsiod-security-test
    environment: test
    linux:
        pidFile: /run/rpsiod/rpsiod-security-test.pid
    performance:
        workers: 1
        keepAlive:
            enabled: true
            timeout: 2s
            maxRequests: 10
        buffers:
            requestHeader: 16kb
            response: 64kb
        staticFiles:
            sendfile: false
            readAhead: false
    security:
        dropPrivileges: false
    logging:
        access:
            enabled: true
            path: /var/log/rpsiod/security-test-access.log
        error:
            enabled: true
            path: /var/log/rpsiod/security-test-error.log
    benchmarks:
        listen:
            ip: 127.0.0.1
            port: {bench_port}
        storage:
            path: /var/cache/rpsiod/security-test-benchmarks
    config:
        sitesFile: /etc/rpsiod/sites.yml
""",
        encoding="utf-8",
    )
    sites.write_text(
        f"""sites:
    -
        name: Security Static
        enabled: true
        serveAs: http
        match:
            domains:
                - {STATIC_HOST}
        listen:
            ip: 127.0.0.1
            ports:
                http: {static_port}
        routing:
            type: static
        static:
            root: {docroot}
            index:
                - index.html
            directoryListing: false
        php:
            enabled: false
        security:
            maxBodySize: 1mb
            hideServerHeader: true
            allowSymlinks: false
            allowedMethods:
                - GET
                - HEAD
    -
        name: Security PHP Limit
        enabled: true
        serveAs: http
        match:
            domains:
                - {PHP_LIMIT_HOST}
        listen:
            ip: 127.0.0.1
            ports:
                http: {php_limit_port}
        routing:
            type: static
        static:
            root: {php_docroot}
            index:
                - index.php
            directoryListing: false
        php:
            enabled: true
            mode: fpm
            handler:
                type: tcp
                host: 127.0.0.1
                port: {unused_fcgi_port}
            limits:
                maxBodySize: 1b
        security:
            maxBodySize: 1mb
            hideServerHeader: true
            allowSymlinks: false
            allowedMethods:
                - GET
                - HEAD
                - POST
""",
        encoding="utf-8",
    )
    return server, sites


def send_raw(port, payload, timeout=2.0, read_all=True):
    chunks = []
    with socket.create_connection((HOST, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(payload)
        if not read_all:
            return sock.recv(65536)
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def status_line(response):
    return response.split(b"\r\n", 1)[0]


def assert_status(name, port, payload, expected):
    response = send_raw(port, payload)
    line = status_line(response)
    if not line.startswith(f"HTTP/1.1 {expected} ".encode()):
        raise AssertionError(f"{name}: expected {expected}, got {line!r}")
    print(f"ok {name}")
    return response


def request(path, extra=None):
    if extra is None:
        extra = b"Connection: close\r\n"
    return b"GET " + path + b" HTTP/1.1\r\nHost: " + STATIC_HOST.encode() + b"\r\n" + extra + b"\r\n"


def php_limit_request(body):
    return (
        b"POST /index.php HTTP/1.1\r\n"
        b"Host: " + PHP_LIMIT_HOST.encode() + b"\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n" + body
    )


def static_post_request(path, body):
    return (
        b"POST " + path + b" HTTP/1.1\r\n"
        b"Host: " + STATIC_HOST.encode() + b"\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n" + body
    )


def wait_for_server(port, proc, log_path):
    deadline = time.time() + 5.0
    probe = request(b"/")
    while time.time() < deadline:
        if proc.poll() is not None:
            log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
            raise RuntimeError(f"rpsiod exited during startup with {proc.returncode}\n{log}")
        try:
            response = send_raw(port, probe, timeout=0.25)
            if status_line(response).startswith(b"HTTP/1.1 200 "):
                return
        except OSError:
            time.sleep(0.05)
    log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    raise RuntimeError(f"rpsiod did not listen on {HOST}:{port}\n{log}")


def run_tests(port, php_limit_port):
    assert_status("malformed request line rejected", port, b"GET /\r\nHost: " + STATIC_HOST.encode() + b"\r\n\r\n", 400)
    assert_status("NUL header name rejected", port, b"GET / HTTP/1.1\r\nHost: " + STATIC_HOST.encode() + b"\r\nBad\x00Name: value\r\n\r\n", 400)
    assert_status("control header value rejected", port, b"GET / HTTP/1.1\r\nHost: " + STATIC_HOST.encode() + b"\r\nX-Test: bad\x1fvalue\r\n\r\n", 400)
    assert_status("negative Content-Length rejected", port, b"GET / HTTP/1.1\r\nHost: " + STATIC_HOST.encode() + b"\r\nContent-Length: -1\r\n\r\n", 400)
    assert_status("overflow Content-Length rejected", port, b"GET / HTTP/1.1\r\nHost: " + STATIC_HOST.encode() + b"\r\nContent-Length: 184467440737095516160\r\n\r\n", 400)
    assert_status("TRACE blocked", port, b"TRACE / HTTP/1.1\r\nHost: " + STATIC_HOST.encode() + b"\r\n\r\n", 405)

    assert_status("bad percent escape rejected", port, request(b"/bad%ZZ"), 400)
    assert_status("percent-decoded NUL rejected", port, request(b"/bad%00path"), 400)
    assert_status("percent-decoded traversal rejected", port, request(b"/%2e%2e/index.html"), 400)
    response = assert_status("valid percent-decoded path served", port, request(b"/space%20name.txt"), 200)
    if b"SPACE_OK" not in response:
        raise AssertionError("valid percent-decoded path served: missing body")
    if b"\r\nServer:" in response:
        raise AssertionError("hideServerHeader did not suppress Server header")
    print("ok hideServerHeader suppresses Server header")

    response = assert_status("PHP source suffix blocked on static route", port, request(b"/source.p%68p"), 403)
    if b"<?php" in response:
        raise AssertionError("PHP source suffix blocked on static route: source leaked")

    smuggled = request(b"/smuggled.txt")
    legitimate = request(b"/ok.txt")
    first = (
        b"GET / HTTP/1.1\r\nHost: " + STATIC_HOST.encode() +
        b"\r\nContent-Length: " + str(len(smuggled)).encode() +
        b"\r\nConnection: keep-alive\r\n\r\n" + smuggled + legitimate
    )
    response = send_raw(port, first)
    count = response.count(b"HTTP/1.1 ")
    if count != 2 or b"PIPELINE_OK" not in response or b"SMUGGLED" in response:
        raise AssertionError(f"body smuggling/pipelining: expected two responses without smuggled body, got {count}")
    print("ok body smuggling/pipelining consumes declared body only")

    assert_status("PHP-specific maxBodySize enforced before FastCGI", php_limit_port, php_limit_request(b"xx"), 413)
    assert_status("POST remains blocked for ordinary static files", port, static_post_request(b"/ok.txt", b"xx"), 405)


def main():
    if not BIN.exists():
        raise SystemExit(f"missing binary: {BIN}")
    for path in ("/run/rpsiod", "/var/log/rpsiod", "/var/cache/rpsiod"):
        os.makedirs(path, exist_ok=True)

    workdir = Path(tempfile.mkdtemp(prefix="rpsiod-security-"))
    proc = None
    try:
        static_port = reserve_port()
        php_limit_port = reserve_port()
        unused_fcgi_port = reserve_port()
        bench_port = reserve_port()
        server, sites = write_config(workdir, static_port, php_limit_port, unused_fcgi_port, bench_port)
        log_path = workdir / "rpsiod.log"
        with log_path.open("wb") as log:
            proc = subprocess.Popen(
                [str(BIN), "serve", "--server", str(server), "--sites", str(sites)],
                cwd=str(ROOT),
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        wait_for_server(static_port, proc, log_path)
        run_tests(static_port, php_limit_port)
        print("security regression tests ok")
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
