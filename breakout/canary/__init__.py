import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class CanaryHit:
    def __init__(self, tech, nonce, proto="http", detail=None):
        self.tech = tech
        self.nonce = nonce
        self.proto = proto
        self.detail = detail or {}
        self.ts = time.time()

    def as_dict(self):
        return {"tech": self.tech, "nonce": self.nonce, "proto": self.proto,
                "detail": self.detail, "ts": self.ts}


class _Handler(BaseHTTPRequestHandler):
    canary = None

    def do_GET(self):
        self._record()

    def do_HEAD(self):
        self._record()

    def _record(self):
        # authority-confusion probes reach us in absolute form —
        # `GET http://allowed.example\@canary:port/hit/..` — where the tricked
        # authority is everything up to the first slash and the real /hit/ path
        # follows. Drop the scheme+authority so a client that actually connected
        # is credited, whatever parser differential smuggled it here.
        path = self.path
        if "://" in path:
            rest = path.split("://", 1)[1]
            slash = rest.find("/")
            path = rest[slash:] if slash != -1 else "/"
        parts = path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "redirect":
            # redirect trampoline: 302 to the hit path; the client that
            # follows it proves egress past first-hop-only filters
            self.send_response(302)
            self.send_header("Location", f"/hit/{parts[1]}/{parts[2]}")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        detail = {"host": self.headers.get("Host", "")}
        if self.headers.get("Upgrade"):
            detail["upgrade"] = self.headers.get("Upgrade")
        if self.headers.get("X-Breakout-Evil-Host"):
            detail["evil_host"] = self.headers.get("X-Breakout-Evil-Host")
        if self.headers.get("X-Breakout-Injected"):
            detail["injected_header"] = self.headers.get("X-Breakout-Injected")
        if len(parts) == 3 and parts[0] == "hit":
            self.canary.record(parts[1], parts[2], "http", detail)
        body = b"breakout-canary"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command == "GET":
            self.wfile.write(body)

    def log_message(self, *args):
        pass


class _V6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True

    def server_bind(self):
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        except OSError:
            pass
        super().server_bind()


class Canary:
    def __init__(self, abstract_name="breakout-canary"):
        self.hits = []
        self.lock = threading.Lock()
        self._rebind_seen = {}       # qname -> times queried (TTL-flip counter)
        self.abstract_name = abstract_name
        h = type("H", (_Handler,), {"canary": self})
        self.httpd = ThreadingHTTPServer(("0.0.0.0", 0), h)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.v6_ok = False
        self.abstract_ok = False
        self._threads = [threading.Thread(target=self.httpd.serve_forever, daemon=True)]
        self._http_threads = [self._threads[0]]
        self.httpd6 = None
        self._abstract_srv = None
        try:
            v6 = _V6Server(("::", self.port), h)
            v6.daemon_threads = True
            self.httpd6 = v6
            t6 = threading.Thread(target=v6.serve_forever, daemon=True)
            self._threads.append(t6)
            self._http_threads.append(t6)
            self.v6_ok = True
        except OSError:
            pass
        if os.name == "posix":
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.bind("\0" + abstract_name)
                s.listen(8)
                self._abstract_srv = s
                self.abstract_ok = True
                self._threads.append(threading.Thread(target=self._serve_abstract,
                                                      args=(s,), daemon=True))
            except OSError:
                pass
        # tiny UDP DNS responder: answers any A query, and for a `<nonce>.rebind`
        # name flips its answer after the first lookup (a benign decoy IP first,
        # loopback after) — the DNS-rebinding TTL flip, self-contained and local.
        self._dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._dns.bind(("0.0.0.0", 0))
        self.dns_port = self._dns.getsockname()[1]
        self._threads.append(threading.Thread(target=self._serve_dns, daemon=True))

    def _serve_abstract(self, srv):
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            data = b""
            while len(data) < 4096:
                chunk = conn.recv(256)
                if not chunk:
                    break
                data += chunk
            conn.close()
            parts = data.decode("utf-8", "replace").split()
            if len(parts) >= 2:
                self.record(parts[0], parts[1], "unix-abstract", {})

    def _serve_dns(self):
        while True:
            try:
                data, addr = self._dns.recvfrom(512)
            except OSError:
                return
            resp = self._dns_response(data)
            if resp:
                try:
                    self._dns.sendto(resp, addr)
                except OSError:
                    pass

    def _rebind_ip(self, qname):
        """First lookup of a *.rebind name answers a benign decoy IP; every
        lookup after answers loopback — the allowlist passes, then the address
        flips under it. Any other name always resolves to loopback."""
        if qname.endswith("rebind"):
            with self.lock:
                n = self._rebind_seen.get(qname, 0)
                self._rebind_seen[qname] = n + 1
            return "203.0.113.9" if n == 0 else "127.0.0.1"   # TEST-NET-3 decoy
        return "127.0.0.1"

    def _dns_response(self, data):
        if len(data) < 12:
            return None
        i, labels = 12, []
        while i < len(data):
            n = data[i]
            if n == 0:
                i += 1
                break
            labels.append(data[i + 1:i + 1 + n])
            i += n + 1
        qname = b".".join(labels).decode("ascii", "replace").lower()
        question = data[12:i + 4]                              # qname + qtype + qclass
        octets = bytes(int(o) for o in self._rebind_ip(qname).split("."))
        header = data[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04" + octets
        return header + question + answer

    def record(self, tech, nonce, proto, detail):
        with self.lock:
            self.hits.append(CanaryHit(tech, nonce, proto, detail))

    def saw(self, tech, nonce, after=0.0):
        with self.lock:
            return any(h.tech == tech and h.nonce == nonce and h.ts >= after
                       for h in self.hits)

    def hits_for(self, tech, nonce, after=0.0):
        with self.lock:
            return [h.as_dict() for h in self.hits
                    if h.tech == tech and h.nonce == nonce and h.ts >= after]

    def start(self):
        for t in self._threads:
            t.start()
        self._started = True

    def stop(self):
        if getattr(self, "_started", False):
            self.httpd.shutdown()
            if self.httpd6:
                self.httpd6.shutdown()
            for t in self._http_threads:
                t.join(timeout=1)
        self.httpd.server_close()
        if self.httpd6:
            self.httpd6.server_close()
        if self._abstract_srv:
            self._abstract_srv.close()
        self._dns.close()

    def info(self):
        return {"port": self.port, "ipv6": self.v6_ok, "abstract": self.abstract_ok,
                "abstract_name": self.abstract_name if self.abstract_ok else None,
                "dns_port": self.dns_port}
