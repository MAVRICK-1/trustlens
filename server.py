"""TrustLens HTTP server (stdlib only). Run: python server.py  (PORT env var supported)."""
import json
import os
import re
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from trustlens import intel
from trustlens.certcheck import check_certificate
from trustlens.urlintel import analyze_url, normalize
from trustlens.websec import assess_web, is_public_host

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")
HOST_RE = re.compile(r"^[a-z0-9.-]{1,253}$")
_hits = defaultdict(list)


def rate_limited(ip, limit=30, window=60):
    now = time.time()
    _hits[ip] = [t for t in _hits[ip] if now - t < window]
    _hits[ip].append(now)
    return len(_hits[ip]) > limit


def label(score):
    return "Dangerous" if score >= 60 else "Suspicious" if score >= 30 else "Likely Safe"


def full_scan(raw):
    url = analyze_url(raw)
    host = url["host"]
    res = {"url": url["url"], "host": host, "lexical": url}
    if not host:
        res.update(risk=100, label="Dangerous")
        return res
    res["community"] = intel.lookup(host)
    public = is_public_host(host)
    skipped = {"findings": [], "score": 0, "error": "Not a public host; active scan skipped."}
    res["certificate"] = check_certificate(host, ct=True) if public else dict(skipped)
    res["web"] = assess_web(url["url"]) if public else dict(skipped)
    cert_s, web_s = res["certificate"].get("score", 0), res["web"].get("score", 0)
    # Weighted fusion, but any single strong signal dominates
    risk = 0.45 * url["score"] + 0.25 * cert_s + 0.30 * web_s
    risk = max(risk, 0.9 * url["score"], 0.8 * cert_s, 0.8 * web_s)
    comm = res["community"]
    if comm["malicious_reports"] >= 3:
        risk = max(risk, 70 + min(30, comm["score"] / 4))
    elif comm["malicious_reports"] and comm["score"] > 50:
        risk += 15
    elif comm["safe_reports"] >= 3 and not comm["malicious_reports"]:
        risk -= 10
    res["risk"] = int(max(0, min(100, round(risk))))
    res["label"] = label(res["risk"])
    intel.record_scan(host, res["risk"], res["label"])
    return res


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", ORIGIN)
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self._send(204, b"")

    def _ip(self):
        return self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            with open(os.path.join(STATIC, "index.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if u.path == "/api/feed":
            return self._send(200, intel.feed())
        if u.path == "/api/health":
            return self._send(200, {"ok": True})
        if u.path == "/api/scan":
            if rate_limited(self._ip()):
                return self._send(429, {"error": "Rate limit exceeded"})
            raw = (q.get("url") or [""])[0]
            if not raw or len(raw) > 2000:
                return self._send(400, {"error": "Provide ?url= (max 2000 chars)"})
            return self._send(200, full_scan(raw))
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if urlparse(self.path).path != "/api/report":
            return self._send(404, {"error": "not found"})
        if rate_limited(self._ip(), 10):
            return self._send(429, {"error": "Rate limit exceeded"})
        try:
            n = int(self.headers.get("Content-Length", 0))
            d = json.loads(self.rfile.read(min(n, 10_000)))
            url = normalize(str(d["url"]))
            host = (urlparse(url).hostname or "").lower()
            verdict = d.get("verdict", "malicious")
            if not HOST_RE.match(host) or verdict not in ("malicious", "safe"):
                raise ValueError
        except (ValueError, KeyError, TypeError):
            return self._send(400, {"error": "Invalid report"})
        intel.add_report(host, url, str(d.get("category", "phishing")), str(d.get("comment", "")), verdict, self._ip())
        self._send(200, {"ok": True, "community": intel.lookup(host)})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"TrustLens on http://0.0.0.0:{port}")
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
