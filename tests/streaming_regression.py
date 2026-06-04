#!/usr/bin/env python3
import os
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "build" / "rpsiod"
HOST = "127.0.0.1"
PHP_HOST = "streaming-php.local"
LARGE_BODY_SIZE = 17 * 1024 * 1024
FIRST_BODY_RECORD_SIZE = 0x5660
MESSAGES_BODY_SIZE = FIRST_BODY_RECORD_SIZE


def reserve_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def fcgi_record(record_type, request_id, payload=b""):
    padding = (-len(payload)) % 8
    return struct.pack("!BBHHBB", 1, record_type, request_id, len(payload), padding, 0) + payload + (b"\0" * padding)


def read_exact(conn, size):
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def read_fcgi_record(conn):
    header = read_exact(conn, 8)
    if header is None:
        return None, 0, b""
    version, record_type, request_id, content_len, padding, reserved = struct.unpack("!BBHHBB", header)
    if version != 1 or reserved != 0:
        return None, 0, b""
    payload = read_exact(conn, content_len) if content_len else b""
    if payload is None:
        return None, 0, b""
    if padding and read_exact(conn, padding) is None:
        return None, 0, b""
    return record_type, request_id, payload


def parse_fcgi_params(payload):
    params = {}
    offset = 0
    while offset < len(payload):
        name_len = payload[offset]
        offset += 1
        if name_len & 0x80:
            if offset + 3 > len(payload):
                break
            name_len = ((name_len & 0x7f) << 24) | (payload[offset] << 16) | (payload[offset + 1] << 8) | payload[offset + 2]
            offset += 3
        value_len = payload[offset]
        offset += 1
        if value_len & 0x80:
            if offset + 3 > len(payload):
                break
            value_len = ((value_len & 0x7f) << 24) | (payload[offset] << 16) | (payload[offset + 1] << 8) | payload[offset + 2]
            offset += 3
        if offset + name_len + value_len > len(payload):
            break
        name = payload[offset:offset + name_len].decode("utf-8", errors="replace")
        offset += name_len
        value = payload[offset:offset + value_len].decode("utf-8", errors="replace")
        offset += value_len
        params[name] = value
    return params


class FakeFastCGI:
    def __init__(self, port):
        self.port = port
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.ready = threading.Event()

    def start(self):
        self.thread.start()
        if not self.ready.wait(timeout=5):
            raise RuntimeError("fake FastCGI server did not start")

    def stop(self):
        self.stop_event.set()
        try:
            with socket.create_connection((HOST, self.port), timeout=0.2):
                pass
        except OSError:
            pass
        self.thread.join(timeout=3)

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((HOST, self.port))
            sock.listen(16)
            sock.settimeout(0.25)
            self.ready.set()
            while not self.stop_event.is_set():
                try:
                    conn, _ = sock.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=self.handle_conn, args=(conn,), daemon=True).start()

    def handle_conn(self, conn):
        with conn:
            request_id = 1
            params_payload = b""
            while True:
                record_type, record_request_id, payload = read_fcgi_record(conn)
                if record_type is None:
                    return
                request_id = record_request_id
                if record_type == 4 and payload:
                    params_payload += payload
                if record_type == 5 and not payload:
                    break
            params = parse_fcgi_params(params_payload)
            response_size = MESSAGES_BODY_SIZE if params.get("SCRIPT_NAME") == "/pma/js/messages.php" else LARGE_BODY_SIZE
            first_headers = b"Status: 200 OK\r\nContent-Type: text/plain\r\nX-Stream-Test: split"
            second_headers = b"\r\n\r\n"
            first_body = b"var Messages = " + (b"A" * (FIRST_BODY_RECORD_SIZE - len(b"var Messages = ")))
            conn.sendall(fcgi_record(6, request_id, first_headers))
            conn.sendall(fcgi_record(6, request_id, second_headers + first_body))
            chunk = b"A" * 65535
            remaining = response_size - len(first_body)
            while remaining > 0:
                size = min(remaining, len(chunk))
                conn.sendall(fcgi_record(6, request_id, chunk[:size]))
                remaining -= size
            conn.sendall(fcgi_record(6, request_id, b""))
            conn.sendall(fcgi_record(3, request_id, b"\0" * 8))


def write_config(workdir, http_port, https_port, bench_port, fcgi_port):
    docroot = workdir / "php"
    (docroot / "pma" / "js").mkdir(parents=True)
    (docroot / "index.php").write_text("<?php echo 'stream';\n", encoding="utf-8")
    (docroot / "pma" / "js" / "messages.php").write_text("<?php echo 'messages';\n", encoding="utf-8")
    server = workdir / "server.yml"
    sites = workdir / "sites.yml"
    ssl_storage = f"/var/lib/rpsiod/ssl/streaming-test-{os.getpid()}"
    server.write_text(
        f"""server:
    name: rpsiod-streaming-test
    environment: test
    linux:
        pidFile: /run/rpsiod/rpsiod-streaming-test.pid
    performance:
        workers: 2
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
            path: /var/log/rpsiod/streaming-test-access.log
        error:
            enabled: true
            path: /var/log/rpsiod/streaming-test-error.log
    benchmarks:
        listen:
            ip: 127.0.0.1
            port: {bench_port}
        storage:
            path: /var/cache/rpsiod/streaming-test-benchmarks
    config:
        sitesFile: /etc/rpsiod/sites.yml
""",
        encoding="utf-8",
    )
    sites.write_text(
        f"""sites:
    -
        name: Streaming PHP
        enabled: true
        serveAs: http
        match:
            domains:
                - {PHP_HOST}
        listen:
            ip: 127.0.0.1
            ports:
                http: {http_port}
                https: {https_port}
        ssl:
            enabled: true
            mode: auto
            provider: local
            storage: {ssl_storage}
        routing:
            type: static
        static:
            root: {docroot}
            index:
                - index.php
            directoryListing: false
        php:
            enabled: true
            mode: fpm
            handler:
                type: tcp
                host: 127.0.0.1
                port: {fcgi_port}
            timeouts:
                connect: 2s
                read: 5s
                write: 5s
            limits:
                maxBodySize: 1mb
        security:
            maxBodySize: 1mb
            hideServerHeader: true
            allowSymlinks: false
            allowedMethods:
                - GET
                - HEAD
""",
        encoding="utf-8",
    )
    return server, sites


def send_raw(port, payload, timeout=10.0):
    chunks = []
    with socket.create_connection((HOST, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(payload)
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def wait_for_server(port, proc, log_path):
    deadline = time.time() + 5.0
    probe = b"GET /index.php HTTP/1.1\r\nHost: " + PHP_HOST.encode() + b"\r\nConnection: close\r\n\r\n"
    while time.time() < deadline:
        if proc.poll() is not None:
            log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
            raise RuntimeError(f"rpsiod exited during startup with {proc.returncode}\n{log}")
        try:
            response = send_raw(port, probe, timeout=0.5)
            if response.startswith(b"HTTP/1.1 200 "):
                return
        except OSError:
            time.sleep(0.05)
    log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    raise RuntimeError(f"rpsiod did not listen on {HOST}:{port}\n{log}")


def split_response(response):
    header_end = response.find(b"\r\n\r\n")
    if header_end < 0:
        raise AssertionError("response missing header terminator")
    return response[:header_end].decode("iso-8859-1"), response[header_end + 4:]


def chunked_body_size(body):
    total = 0
    offset = 0
    while True:
        line_end = body.find(b"\r\n", offset)
        if line_end < 0:
            raise AssertionError("chunked response missing chunk size")
        size = int(body[offset:line_end], 16)
        offset = line_end + 2
        if size == 0:
            if body[offset:offset + 2] != b"\r\n":
                raise AssertionError("chunked response missing final terminator")
            return total
        total += size
        offset += size
        if body[offset:offset + 2] != b"\r\n":
            raise AssertionError("chunked response missing chunk terminator")
        offset += 2


def run_streaming_tests(port):
    request = b"GET /index.php HTTP/1.1\r\nHost: " + PHP_HOST.encode() + b"\r\nConnection: close\r\n\r\n"
    response = send_raw(port, request)
    headers, body = split_response(response)
    if not headers.startswith("HTTP/1.1 200 "):
        raise AssertionError(f"streaming GET expected 200, got {headers.splitlines()[0]!r}")
    if "Transfer-Encoding: chunked" not in headers:
        raise AssertionError("streaming GET did not use chunked transfer for unknown-length PHP response")
    if "X-Stream-Test: split" not in headers:
        raise AssertionError("streaming GET did not preserve split PHP header")
    size = chunked_body_size(body)
    if size != LARGE_BODY_SIZE:
        raise AssertionError(f"streaming GET body size mismatch: {size} != {LARGE_BODY_SIZE}")
    print("ok PHP FastCGI streams split-header body over old buffer limit")

    head_request = b"HEAD /index.php HTTP/1.1\r\nHost: " + PHP_HOST.encode() + b"\r\nConnection: close\r\n\r\n"
    head_response = send_raw(port, head_request)
    head_headers, head_body = split_response(head_response)
    if not head_headers.startswith("HTTP/1.1 200 "):
        raise AssertionError(f"streaming HEAD expected 200, got {head_headers.splitlines()[0]!r}")
    if head_body:
        raise AssertionError("streaming HEAD returned a body")
    print("ok PHP FastCGI HEAD drains backend without client body")


def run_h2_streaming_tests(https_port, workdir):
    headers_path = workdir / "h2.headers"
    body_path = workdir / "h2.body"
    url = f"https://{PHP_HOST}:{https_port}/pma/js/messages.php"
    result = subprocess.run(
        [
            "curl",
            "--http2",
            "-k",
            "--noproxy",
            "*",
            "--resolve",
            f"{PHP_HOST}:{https_port}:127.0.0.1",
            "-sS",
            "-D",
            str(headers_path),
            "-o",
            str(body_path),
            url,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"HTTP/2 curl failed: {result.stderr.decode('utf-8', errors='replace')}")
    headers = headers_path.read_text(encoding="iso-8859-1")
    body = body_path.read_bytes()
    if not headers.startswith("HTTP/2 200"):
        raise AssertionError(f"HTTP/2 PHP expected 200, got {headers.splitlines()[0]!r}")
    if re.search(r"(?im)^server:", headers):
        raise AssertionError("HTTP/2 response exposed Server header despite hideServerHeader")
    if not re.search(r"(?im)^strict-transport-security:", headers):
        raise AssertionError("HTTP/2 TLS response did not include HSTS")
    if re.search(r"(?im)^transfer-encoding:", headers):
        raise AssertionError("HTTP/2 PHP response exposed Transfer-Encoding header")
    if not body.startswith(b"var Messages ="):
        raise AssertionError(f"HTTP/2 PHP body did not start with raw PHP content: {body[:32]!r}")
    if any(re.fullmatch(rb"[0-9A-Fa-f]+", line) for line in body.splitlines()):
        raise AssertionError("HTTP/2 PHP body contains a standalone hex chunk marker")
    if b"\r\n0\r\n\r\n" in body or b"\n0\n" in body:
        raise AssertionError("HTTP/2 PHP body contains a terminal chunk marker")
    if len(body) != MESSAGES_BODY_SIZE:
        raise AssertionError(f"HTTP/2 PHP body size mismatch: {len(body)} != {MESSAGES_BODY_SIZE}")
    print("ok HTTP/2 PHP response dechunks internal HTTP/1.1 framing")


def main():
    if not BIN.exists():
        raise SystemExit(f"missing binary: {BIN}")
    for path in ("/run/rpsiod", "/var/log/rpsiod", "/var/cache/rpsiod"):
        os.makedirs(path, exist_ok=True)

    workdir = Path(tempfile.mkdtemp(prefix="rpsiod-streaming-"))
    proc = None
    fcgi = None
    try:
        http_port = reserve_port()
        https_port = reserve_port()
        bench_port = reserve_port()
        fcgi_port = reserve_port()
        fcgi = FakeFastCGI(fcgi_port)
        fcgi.start()
        server, sites = write_config(workdir, http_port, https_port, bench_port, fcgi_port)
        log_path = workdir / "rpsiod.log"
        with log_path.open("wb") as log:
            proc = subprocess.Popen(
                [str(BIN), "serve", "--server", str(server), "--sites", str(sites)],
                cwd=str(ROOT),
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        wait_for_server(http_port, proc, log_path)
        run_streaming_tests(http_port)
        run_h2_streaming_tests(https_port, workdir)
        print("streaming regression tests ok")
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        if fcgi is not None:
            fcgi.stop()
        shutil.rmtree(f"/var/lib/rpsiod/ssl/streaming-test-{os.getpid()}", ignore_errors=True)
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
