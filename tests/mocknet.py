"""Deterministic loopback mock network for netrecon E2E fixtures.

Two virtual hosts answer on the loopback range, so a full scan can run
offline with no root and no LAN:

  host            VLAN   label      open TCP listeners
  --------------- ------ ---------  -----------------------------------------
  127.0.0.1       900    Mock-Lab   41022 (ssh banner), 41080 (http), 41883 (silent)
  127.0.0.2       901    Mock-IoT   46668 (silent), 48123 (http)

Both addresses reply to ICMP on loopback (TTL=64) -> hosts are "up".
No L2 MACs are visible for 127.x (same as a routed VLAN), so vendor
resolution is exercised in unit tests via a patched ARP table against the
fixture OUI DB.

Closed probe: 49999 on both hosts (must NOT appear in results).

Banners (what banner_grab reports):
  41022 -> SSH-2.0-OpenSSH_fixture
  41080 -> HTTP/1.0 200 OK | mock-nginx/1.2.3 | Fixture Web One
  48123 -> HTTP/1.0 200 OK | mock-hass/0.1 | Fixture IoT Hub
  41883 / 46668 -> "" (silent listener)
"""

from __future__ import annotations

import socket
import threading
import time

# --------------------------------------------------------------------------- spec

HOSTS = {
    "127.0.0.1": {"vlan": "900", "label": "Mock-Lab"},
    "127.0.0.2": {"vlan": "901", "label": "Mock-IoT"},
}

# port -> (kind, banner_bytes or http headers)
SSH_BANNER = b"SSH-2.0-OpenSSH_fixture\r\n"

HTTP_RESPONSES = {
    41080: (
        b"HTTP/1.0 200 OK\r\n"
        b"Server: mock-nginx/1.2.3\r\n"
        b"Content-Type: text/html\r\n"
        b"\r\n"
        b"<html><head><title>Fixture Web One</title></head>"
        b"<body>hello</body></html>\r\n"
    ),
    48123: (
        b"HTTP/1.0 200 OK\r\n"
        b"Server: mock-hass/0.1\r\n"
        b"Content-Type: text/html\r\n"
        b"\r\n"
        b"<html><head><title>Fixture IoT Hub</title></head>"
        b"<body>hass</body></html>\r\n"
    ),
}

LISTENERS = {
    "127.0.0.1": {41022: "ssh", 41080: "http", 41883: "silent"},
    "127.0.0.2": {46668: "silent", 48123: "http"},
}

CLOSED_PROBE = 49999  # probed by the fixture config but never opened


# --------------------------------------------------------------------------- mock servers

def _serve(ip: str, port: int, kind: str, stop: threading.Event) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((ip, port))
    srv.listen(16)
    srv.settimeout(0.5)
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        t = threading.Thread(target=_handle, args=(conn, kind), daemon=True)
        t.start()
    srv.close()


def _handle(conn: socket.socket, kind: str) -> None:
    try:
        if kind == "ssh":
            conn.sendall(SSH_BANNER)
        elif kind == "http":
            try:
                conn.recv(2048)  # consume the GET
            except OSError:
                pass
            conn.sendall(HTTP_RESPONSES[conn.getsockname()[1]])
        elif kind == "silent":
            time.sleep(1.0)  # hold open; banner grab times out -> ""
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


class MockNet:
    """Start/stop the fixture network. Importable from unit tests and runners."""

    def __init__(self):
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()

    def start(self) -> None:
        self._stop.clear()
        for ip, ports in LISTENERS.items():
            for port, kind in ports.items():
                t = threading.Thread(target=_serve, args=(ip, port, kind, self._stop), daemon=True)
                t.start()
                self._threads.append(t)
        time.sleep(0.3)  # let listeners bind

    def stop(self) -> None:
        self._stop.set()
        time.sleep(0.4)


if __name__ == "__main__":
    net = MockNet()
    net.start()
    print("[*] mocknet up (loopback listeners bound)")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        net.stop()
