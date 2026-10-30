"""LAN peers: discovery of other Ping Tray instances and speed tests between them.

Discovery: every instance broadcasts a small UDP beacon every BEACON_INTERVAL_S seconds on
lan_port and listens for the others' beacons. A peer that stops announcing itself is dropped
after PEER_TIMEOUT_S.

Speed test: every instance runs a TCP server (on lan_port, or a free port if it is taken; the
port travels in the beacon). The client sends one JSON header line, the server answers with
one JSON line, and then:

    download  the server sends data for N seconds and closes; the client counts the bytes
    upload    the client sends data for N seconds and half-closes; the server counts the bytes
              and replies with {"bytes": ..., "seconds": ...}

The server handles one test at a time and caps its duration at MAX_TEST_SECONDS, so another
machine on the LAN can't keep it busy indefinitely.
"""

import hmac
import json
import socket
import threading
import time
import uuid
from dataclasses import dataclass

PROTOCOL = 1
BEACON_INTERVAL_S = 3.0
PEER_TIMEOUT_S = 10.0
MAX_TEST_SECONDS = 30
IO_TIMEOUT_S = 10.0
HEADER_MAX_BYTES = 1024
CHUNK = bytes(256 * 1024)
SOCK_BUFFER = 1024 * 1024


@dataclass
class Peer:
    id: str
    name: str
    addr: str
    port: int
    version: str
    last_seen: float


@dataclass
class SpeedResult:
    down_mbps: float
    up_mbps: float


def _mbps(nbytes: int, seconds: float) -> float:
    return nbytes * 8 / seconds / 1e6 if seconds > 0 else 0.0


def _broadcast_addresses() -> set[str]:
    """255.255.255.255 plus a /24 directed broadcast per local IPv4.

    Windows sends 255.255.255.255 out of a single interface only, so with several adapters
    (Ethernet + Wi-Fi + VPN) the directed broadcasts are what reach every network.
    """
    addrs = {"255.255.255.255"}
    try:
        local_ips = socket.gethostbyname_ex(socket.gethostname())[2]
    except OSError:
        local_ips = []
    for ip in local_ips:
        if not ip.startswith("127."):
            addrs.add(ip.rsplit(".", 1)[0] + ".255")
    return addrs


def _recv_line(sock: socket.socket) -> dict:
    """Reads one JSON line byte by byte, so no data after the newline is consumed."""
    buf = bytearray()
    while len(buf) < HEADER_MAX_BYTES:
        b = sock.recv(1)
        if not b:
            raise ConnectionError("connection closed by peer")
        if b == b"\n":
            return json.loads(buf)
        buf += b
    raise ValueError("header too long")


def _send_line(sock: socket.socket, obj: dict):
    sock.sendall(json.dumps(obj).encode() + b"\n")


def _tune(sock: socket.socket):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUFFER)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUFFER)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


def _send_for(sock: socket.socket, seconds: float) -> int:
    sent = 0
    end = time.perf_counter() + seconds
    while time.perf_counter() < end:
        sock.sendall(CHUNK)
        sent += len(CHUNK)
    return sent


def _recv_until_eof(sock: socket.socket, max_seconds: float) -> tuple[int, float]:
    """Returns (bytes, seconds from the first byte to EOF)."""
    received = 0
    first = None
    deadline = time.perf_counter() + max_seconds
    while time.perf_counter() < deadline:
        data = sock.recv(len(CHUNK))
        if not data:
            break
        if first is None:
            first = time.perf_counter()
        received += len(data)
    return received, (time.perf_counter() - first) if first is not None else 0.0


class LanNode:
    """Announces this instance, tracks the other ones and serves speed tests."""

    def __init__(self, name: str, port: int, secret: str, version: str):
        self.id = uuid.uuid4().hex
        self.name = name
        self.port = port
        self.secret = secret
        self.version = version
        self.tcp_port: int | None = None
        self.error: str | None = None
        self._peers: dict[str, Peer] = {}
        self._lock = threading.Lock()
        self._busy = threading.Lock()  # one speed test served at a time
        self._stop = threading.Event()
        self._udp: socket.socket | None = None
        self._tcp: socket.socket | None = None

    def start(self):
        try:
            self._tcp = self._open_tcp()
            self.tcp_port = self._tcp.getsockname()[1]
            self._udp = self._open_udp()
        except OSError as e:
            self.error = f"LAN disabled: {e}"
            self.stop()
            return
        for target in (self._beacon_loop, self._listen_loop, self._accept_loop):
            threading.Thread(target=target, daemon=True).start()

    def stop(self):
        self._stop.set()
        for sock in (self._udp, self._tcp):
            if sock is not None:
                try:
                    sock.close()  # unblocks recvfrom/accept in the worker threads
                except OSError:
                    pass

    def peers(self) -> list[Peer]:
        with self._lock:
            now = time.monotonic()
            for pid in [pid for pid, p in self._peers.items() if now - p.last_seen > PEER_TIMEOUT_S]:
                del self._peers[pid]
            return sorted(self._peers.values(), key=lambda p: p.name.lower())

    # Discovery

    def _open_udp(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # lets two instances share a PC
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", self.port))
        return sock

    def _beacon_loop(self):
        beacon = json.dumps({
            "app": "ping-tray", "proto": PROTOCOL, "id": self.id,
            "name": self.name, "port": self.tcp_port, "version": self.version,
        }).encode()
        while not self._stop.is_set():
            for addr in _broadcast_addresses():
                try:
                    self._udp.sendto(beacon, (addr, self.port))
                except OSError:
                    pass  # e.g. an adapter that went down
            self._stop.wait(BEACON_INTERVAL_S)

    def _listen_loop(self):
        while not self._stop.is_set():
            try:
                data, (addr, _) = self._udp.recvfrom(2048)
                msg = json.loads(data)
                if msg.get("app") != "ping-tray" or msg.get("proto") != PROTOCOL or msg["id"] == self.id:
                    continue
                peer = Peer(
                    id=str(msg["id"]), name=str(msg["name"])[:64], addr=addr,
                    port=int(msg["port"]), version=str(msg.get("version", "?")),
                    last_seen=time.monotonic(),
                )
            except OSError:
                if self._stop.is_set():
                    return
                continue
            except (ValueError, KeyError, TypeError, AttributeError):
                continue  # not a beacon of ours
            with self._lock:
                self._peers[peer.id] = peer

    # Speed test server

    def _open_tcp(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("", self.port))
        except OSError:
            sock.bind(("", 0))  # port taken (e.g. another instance on this PC): use any free one
        sock.listen(4)
        return sock

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._tcp.accept()
            except OSError:
                if self._stop.is_set():
                    return
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket):
        with conn:
            try:
                conn.settimeout(IO_TIMEOUT_S)
                _tune(conn)
                header = _recv_line(conn)
                mode = header.get("mode")
                seconds = min(float(header.get("seconds", 5)), MAX_TEST_SECONDS)
                if not hmac.compare_digest(str(header.get("secret", "")).encode(), self.secret.encode()):
                    _send_line(conn, {"ok": False, "error": "wrong lan_secret"})
                    return
                if mode not in ("download", "upload") or seconds <= 0:
                    _send_line(conn, {"ok": False, "error": "bad request"})
                    return
                if not self._busy.acquire(blocking=False):
                    _send_line(conn, {"ok": False, "error": "busy with another test"})
                    return
                try:
                    _send_line(conn, {"ok": True})
                    if mode == "download":
                        _send_for(conn, seconds)
                    else:
                        nbytes, elapsed = _recv_until_eof(conn, seconds + IO_TIMEOUT_S)
                        _send_line(conn, {"bytes": nbytes, "seconds": elapsed})
                finally:
                    self._busy.release()
            except (OSError, ValueError, AttributeError):
                pass  # client went away or sent garbage


def _request(peer: Peer, mode: str, seconds: float, secret: str) -> socket.socket:
    sock = socket.create_connection((peer.addr, peer.port), timeout=IO_TIMEOUT_S)
    try:
        _tune(sock)
        _send_line(sock, {"mode": mode, "seconds": seconds, "secret": secret})
        reply = _recv_line(sock)
        if not reply.get("ok"):
            raise ConnectionError(reply.get("error", "refused"))
        return sock
    except BaseException:
        sock.close()
        raise


def speed_test(peer: Peer, seconds: float, secret: str) -> SpeedResult:
    """Measures download (peer -> us) and then upload (us -> peer). Raises OSError/ValueError."""
    seconds = min(seconds, MAX_TEST_SECONDS)
    with _request(peer, "download", seconds, secret) as sock:
        nbytes, elapsed = _recv_until_eof(sock, seconds + IO_TIMEOUT_S)
    down = _mbps(nbytes, elapsed)
    with _request(peer, "upload", seconds, secret) as sock:
        _send_for(sock, seconds)
        sock.shutdown(socket.SHUT_WR)
        reply = _recv_line(sock)
    up = _mbps(int(reply["bytes"]), float(reply["seconds"]))
    return SpeedResult(down, up)


def _main():
    """Headless node, to test against a tray instance or diagnose discovery on a network."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Ping Tray LAN node without the tray icon.")
    parser.add_argument("--name", default=f"{socket.gethostname()}-cli", help="name shown to the peers")
    parser.add_argument("--port", type=int, default=50505, help="lan_port (default: 50505)")
    parser.add_argument("--secret", default="", help="lan_secret")
    parser.add_argument("--test", metavar="PEER", help="run a speed test against PEER (name or IP) and exit")
    parser.add_argument("--seconds", type=float, default=5, help="seconds per direction (default: 5)")
    args = parser.parse_args()

    node = LanNode(args.name, args.port, args.secret, "cli")
    node.start()
    if node.error:
        sys.exit(node.error)
    print(f"{args.name}: discovery on UDP {args.port}, speed tests on TCP {node.tcp_port}. Ctrl+C to quit.", flush=True)
    try:
        if args.test:
            wanted = args.test.lower()
            deadline = time.monotonic() + PEER_TIMEOUT_S
            while True:
                match = [p for p in node.peers() if wanted in (p.name.lower(), p.addr)]
                if match:
                    break
                if time.monotonic() > deadline:
                    names = ", ".join(f"{p.name} ({p.addr})" for p in node.peers()) or "none"
                    sys.exit(f"Peer {args.test!r} not found. Peers seen: {names}")
                time.sleep(0.5)
            peer = match[0]
            print(f"Testing {peer.name} ({peer.addr}:{peer.port}), {args.seconds:g} s per direction...", flush=True)
            try:
                result = speed_test(peer, args.seconds, args.secret)
            except (OSError, ValueError, KeyError) as e:
                sys.exit(f"Test failed: {e}")
            print(f"Down: {result.down_mbps:.1f} Mbps · Up: {result.up_mbps:.1f} Mbps")
            return
        seen: list[tuple[str, str, int]] = []
        while True:  # print the peer list whenever it changes
            current = [(p.name, p.addr, p.port) for p in node.peers()]
            if current != seen:
                seen = current
                print(time.strftime("%H:%M:%S"), "peers:",
                      ", ".join(f"{n} ({a}:{p})" for n, a, p in current) or "none", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        node.stop()


if __name__ == "__main__":
    _main()
