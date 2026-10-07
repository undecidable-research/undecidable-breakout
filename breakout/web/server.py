"""HTTP layer: routing, content negotiation, static assets, report files.

`handle()` is a pure function (path + Accept header in, Response out) so it is
tested without sockets; `serve()` wraps it in a stdlib ThreadingHTTPServer.
Read-only by construction: GET and HEAD only.
"""
import json
import sys
import traceback
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from . import views

STATIC = Path(__file__).with_name("static")
FONT = Path(__file__).resolve().parent.parent / "reporting" / "archivo-latin-wght-normal.woff2"

PAGE_CSP = ("default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
            "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'")
# report.html carries its own inline <style> and base64 font; nothing may execute.
FILE_CSP = "default-src 'none'; style-src 'unsafe-inline'; font-src data:; img-src data:; sandbox"
FILE_TYPES = {".json": "application/json; charset=utf-8",
              ".html": "text/html; charset=utf-8",
              ".sarif": "application/json; charset=utf-8",
              ".xml": "application/xml; charset=utf-8"}


@dataclass
class Response:
    status: int
    content_type: str
    body: bytes
    headers: dict = field(default_factory=dict)


def _css():
    from ..reporting import _CSS
    return _CSS + (STATIC / "app.css").read_text(encoding="utf-8")


def _assets():
    return {
        "/assets/app.css": lambda: ("text/css; charset=utf-8", _css().encode()),
        "/assets/app.js": lambda: ("text/javascript; charset=utf-8",
                                   (STATIC / "app.js").read_bytes()),
        "/assets/mark.svg": lambda: ("image/svg+xml", (STATIC / "mark.svg").read_bytes()),
        "/favicon.ico": lambda: ("image/svg+xml", (STATIC / "mark.svg").read_bytes()),
        "/assets/archivo.woff2": lambda: ("font/woff2", FONT.read_bytes()),
    }


def wants_json(query, accept):
    fmt = (query.get("format") or [""])[-1].lower()
    if fmt in ("json", "html"):
        return fmt == "json"
    a = (accept or "").lower()
    return "application/json" in a and "text/html" not in a


def _json(status, data, extra=None):
    body = json.dumps(data, indent=2, ensure_ascii=False, default=str).encode()
    return Response(status, "application/json; charset=utf-8", body,
                    {"Cache-Control": "no-store", **(extra or {})})


def _file(site, rel):
    root = site.reports.root
    try:
        p = (root / rel).resolve()
    except (OSError, ValueError):
        return None
    if root not in p.parents or not p.is_file() or p.suffix not in FILE_TYPES:
        return None
    return Response(200, FILE_TYPES[p.suffix], p.read_bytes(),
                    {"Cache-Control": "no-store", "Content-Security-Policy": FILE_CSP})


def handle(site, raw_path, accept=""):
    url = urlsplit(raw_path)
    path = unquote(url.path) or "/"
    query = parse_qs(url.query, keep_blank_values=True)
    if "\x00" in path or "\\" in path:
        return _json(400, {"error": "bad path", "status": 400})

    asset = _assets().get(path)
    if asset:
        ctype, body = asset()
        return Response(200, ctype, body, {"Cache-Control": "public, max-age=300"})
    if path == "/llms.txt":
        return Response(200, "text/plain; charset=utf-8", views.llms_txt(site).encode(),
                        {"Cache-Control": "no-store"})
    if path == "/openapi.json":
        return _json(200, views.openapi(site))
    if path.startswith("/files/"):
        r = _file(site, path[len("/files/"):])
        return r or _json(404, {"error": f"no report artifact at {path}", "status": 404})

    as_json = wants_json(query, accept)
    page_path = path
    if path == "/api" or path.startswith("/api/"):
        as_json = True
        page_path = path[len("/api"):] or "/"
        if page_path in ("/", ""):
            return _json(200, views.api_index(site, views.Req(path=path, query=query)),
                         {"Link": '</agents>; rel="describedby"; type="text/html"'})

    page = views.route(site, page_path, query)
    html_url = page_path + (f"?{url.query}" if url.query else "")
    api_url = views.api_path(page_path)
    if url.query:
        api_url += ("&" if "?" in api_url else "?") + url.query
    if as_json:
        return _json(page.status, page.data,
                     {"Link": f'<{html_url}>; rel="alternate"; type="text/html"',
                      "Vary": "Accept"})
    qs = "&".join(p for p in url.query.split("&") if p and not p.startswith("format="))
    html = views.layout(page, page_path, qs)
    return Response(page.status, "text/html; charset=utf-8", html.encode(), {
        "Cache-Control": "no-store", "Vary": "Accept",
        "Content-Security-Policy": PAGE_CSP,
        "Link": (f'<{api_url}>; rel="alternate"; type="application/json", '
                 '</llms.txt>; rel="help"; type="text/plain"')})


class Handler(BaseHTTPRequestHandler):
    server_version = "undecidable-breakout"
    sys_version = ""
    site = None

    def _reply(self, r, send_body=True):
        self.send_response(r.status)
        self.send_header("Content-Type", r.content_type)
        self.send_header("Content-Length", str(len(r.body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in r.headers.items():
            self.send_header(k, v)
        self.end_headers()
        if send_body:
            self.wfile.write(r.body)

    def _get(self, send_body):
        try:
            r = handle(self.site, self.path, self.headers.get("Accept", ""))
        except Exception:  # never leak a traceback to the client
            traceback.print_exc()
            r = _json(500, {"error": "internal error; see the server log", "status": 500})
        self._reply(r, send_body)

    def do_GET(self):
        self._get(True)

    def do_HEAD(self):
        self._get(False)

    def _refuse(self):
        self._reply(_json(405, {
            "error": "read-only: this frontend never executes probes. "
                     "GET /api/compose for the argv, then run it yourself.",
            "status": 405, "allow": ["GET", "HEAD"]}, {"Allow": "GET, HEAD"}))

    do_POST = do_PUT = do_PATCH = do_DELETE = _refuse

    def log_message(self, fmt, *args):
        sys.stderr.write(f"serve: {self.address_string()} {fmt % args}\n")


def make_server(site, host="127.0.0.1", port=8000):
    handler = type("BoundHandler", (Handler,), {"site": site})
    srv = ThreadingHTTPServer((host, port), handler)
    srv.daemon_threads = True
    return srv


def serve(host="127.0.0.1", port=8000, reports_dir="reports", techniques_dir=None,
          leaderboard_json=None):
    site = views.Site(reports_dir, techniques_dir, leaderboard_json)
    srv = make_server(site, host, port)
    shown = "127.0.0.1" if host in ("0.0.0.0", "") else host
    print(f"undecidable-breakout frontend: http://{shown}:{srv.server_address[1]}/  "
          f"(reports: {site.reports.root}, read-only)", flush=True)
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"  note: bound to {host}; anyone who can reach this port can read "
              f"the reports", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
