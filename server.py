"""TrustLens HTTP server (stdlib only). Run: python server.py  (PORT env var supported)."""
import json
import os
import re
import threading
import time
import traceback
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from trustlens import intel
from trustlens.certcheck import check_certificate
from trustlens.urlintel import analyze_url, parse_target
from trustlens.websec import assess_web, host_class

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")
CATEGORIES = {"phishing", "fake-job", "payment-scam", "malware", "impersonation", "other"}
CACHE_TTL, CACHE_MAX = 300, 500
_hits = defaultdict(list)
_cache = {}
_busy = threading.BoundedSemaphore(int(os.environ.get("MAX_CONCURRENT_SCANS", 8)))
_ratelock = threading.Lock()


def rate_limited(bucket, ip, limit=30, window=60):
    now = time.time()
    key = (bucket, ip)
    with _ratelock:
        if len(_hits) > 5000:  # bound memory
            for k in [k for k, v in _hits.items() if not v or now - v[-1] > window]:
                del _hits[k]
        _hits[key] = [t for t in _hits[key] if now - t < window]
        _hits[key].append(now)
        return len(_hits[key]) > limit


def label(score):
    return "Dangerous" if score >= 60 else "Suspicious" if score >= 30 else "Likely Safe"


def active_scan(t):
    """Certificate + web checks, cached briefly so repeat scans/reports stay fast and cheap."""
    key = t["url"]
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < CACHE_TTL:
        return hit[1], hit[2]
    host = t["host"]
    cls = host_class(host)
    if cls != "public":
        msg = ("Domain does not resolve (no DNS record) - active checks skipped." if cls == "nxdomain"
               else "Private/internal address - active checks skipped.")
        cert = {"findings": [], "score": 0, "error": msg}
        web = {"findings": [], "score": 0, "error": msg}
    else:
        cert_port = t["port"] if t["port"] in (443, 8443) else 443
        cert = check_certificate(host, cert_port, ct=not t["is_ip"])
        web = assess_web(t["url"])
    if len(_cache) >= CACHE_MAX:
        _cache.clear()
    _cache[key] = (time.time(), cert, web)
    return cert, web


def full_scan(raw):
    t = parse_target(raw)  # ValueError -> 400
    lex = analyze_url(raw)
    res = {"url": t["url"], "host": t["host"], "lexical": lex}
    res["community"] = intel.lookup(t["host"])
    res["certificate"], res["web"] = active_scan(t)
    cert_s, web_s, lex_s = res["certificate"].get("score", 0), res["web"].get("score", 0), lex["score"]
    # Weighted fusion, but any single strong signal dominates
    risk = 0.45 * lex_s + 0.25 * cert_s + 0.30 * web_s
    risk = max(risk, 0.9 * lex_s, 0.8 * cert_s, 0.8 * web_s)
    comm = res["community"]
    if comm["malicious_reports"] >= 3:
        risk = max(risk, 70 + min(30, comm["score"] / 4))
    elif comm["malicious_reports"] and comm["score"] > 50:
        risk += 15
    elif comm["safe_reports"] >= 3 and not comm["malicious_reports"]:
        risk -= 10
    res["risk"] = int(max(0, min(100, round(risk))))
    res["label"] = label(res["risk"])
    # Flag when most evidence could not be collected, so "Likely Safe" is not over-trusted
    res["limited"] = bool(res["certificate"].get("error") and res["web"].get("error"))
    intel.record_scan(t["host"], res["risk"], res["label"])
    return res


class H(BaseHTTPRequestHandler):
    server_version = "TrustLens"
    timeout = 30

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json", head=False):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", ORIGIN)
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store" if ctype == "application/json" else "public, max-age=300")
        self.end_headers()
        if not head:
            self.wfile.write(data)

    def _ip(self):
        return self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()[:64]

    def _guard(self, fn):
        try:
            fn()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            traceback.print_exc()
            try:
                self._send(500, {"error": "Internal error while processing the request."})
            except Exception:
                pass

    def do_OPTIONS(self):
        self._send(204, b"")

    def do_HEAD(self):
        self._guard(lambda: self._route_get(head=True))

    def do_GET(self):
        self._guard(self._route_get)

    def do_POST(self):
        self._guard(self._route_post)

    def _route_get(self, head=False):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        path = u.path.rstrip("/") or "/"
        if path in ("/", "/index.html"):
            try:
                with open(os.path.join(STATIC, "index.html"), "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8", head)
            except OSError:
                return self._send(404, {"error": "UI not found"}, head=head)
        if path == "/api/health":
            return self._send(200, {"ok": True}, head=head)
        if path == "/api/feed":
            return self._send(200, intel.feed(), head=head)
        if path == "/api/scan":
            if rate_limited("scan", self._ip()):
                return self._send(429, {"error": "Too many scans. Please wait a minute and try again."})
            try:
                t = parse_target((q.get("url") or [""])[0])
            except ValueError as e:
                return self._send(400, {"error": str(e)})
            if not _busy.acquire(timeout=5):
                return self._send(503, {"error": "Server is busy. Please retry in a few seconds."})
            try:
                return self._send(200, full_scan(t["url"]))
            finally:
                _busy.release()
        self._send(404, {"error": "Not found"}, head=head)

    def _route_post(self):
        if urlparse(self.path).path.rstrip("/") != "/api/report":
            return self._send(404, {"error": "Not found"})
        if rate_limited("report", self._ip(), 10):
            return self._send(429, {"error": "Too many reports. Please wait a minute."})
        try:
            n = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._send(411, {"error": "Content-Length required."})
        if n < 0 or n > 10_000:
            return self._send(413, {"error": "Request body too large."})
        try:
            d = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(d, dict):
                raise ValueError
            t = parse_target(str(d.get("url", "")))
            verdict = d.get("verdict", "malicious")
            if verdict not in ("malicious", "safe"):
                raise ValueError("verdict must be 'malicious' or 'safe'.")
        except (ValueError, UnicodeDecodeError) as e:
            return self._send(400, {"error": str(e) if str(e) else "Invalid report."})
        cat = str(d.get("category", "other")).strip().lower()
        cat = cat if cat in CATEGORIES else "other"
        comment = re.sub(r"[\x00-\x1f]", " ", str(d.get("comment", "")))[:300]
        intel.add_report(t["host"], t["url"], cat, comment, verdict, self._ip())
        self._send(200, {"ok": True, "community": intel.lookup(t["host"])})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"TrustLens on http://0.0.0.0:{port}")
    srv = ThreadingHTTPServer(("0.0.0.0", port), H)
    srv.daemon_threads = True
    srv.serve_forever()
