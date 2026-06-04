import socket
import struct

def rec(record_type, request_id, payload=b""):
    padding = (-len(payload)) % 8
    return struct.pack("!BBHHBB", 1, record_type, request_id, len(payload), padding, 0) + payload + (b"\0" * padding)

def read_record(conn):
    hdr = conn.recv(8)
    if not hdr:
        return None, None, b""
    version, record_type, request_id, content_len, padding, reserved = struct.unpack("!BBHHBB", hdr)
    payload = b""
    while len(payload) < content_len:
        chunk = conn.recv(content_len - len(payload))
        if not chunk:
            break
        payload += chunk
    if padding:
        conn.recv(padding)
    return record_type, request_id, payload

sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", 19091))
sock.listen(5)

while True:
    conn, _ = sock.accept()
    with conn:
        request_id = 1
        while True:
            record_type, rid, payload = read_record(conn)
            if record_type is None:
                break
            request_id = rid
            if record_type == 5 and not payload:
                break
        stdout = b"Status: 200 OK\r\nContent-Type: text/plain\r\n\r\nphase3 php\n"
        conn.sendall(rec(6, request_id, stdout))
        conn.sendall(rec(6, request_id, b""))
        conn.sendall(rec(3, request_id, b"\0" * 8))
