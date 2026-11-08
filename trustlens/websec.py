"""Web application security posture and page-content phishing analysis."""
import ipaddress
import re
import socket
import urllib.error
import urllib.request
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from .urlintel import registered_domain

MAX_BYTES = 400_000
SEV = {"critical": 45, "high": 25, "medium": 10, "low": 3}


def is_public_host(host):
    """SSRF guard: only scan hosts that resolve exclusively to public IPs."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        return False
    return bool(infos) and all(ipaddress.ip_address(i[4][0]).is_global for i in infos)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class _Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self.title, self._t, self.scripts, self.iframes = [], "", False, [], []
        self.meta_refresh = None
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "title":
            self._t = True
        elif tag == "form":
            self._form = {"action": a.get("action") or "", "password": False}
            self.forms.append(self._form)
        elif tag == "input" and (a.get("type") or "").lower() == "password" and self._form is not None:
            self._form["password"] = True
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "iframe":
            style = (a.get("style") or "").replace(" ", "")
            self.iframes.append({"src": a.get("src") or "", "hidden": "display:none" in style or a.get("width") == "0"})
        elif tag == "meta" and (a.get("http-equiv") or "").lower() == "refresh":
            self.meta_refresh = a.get("content")

    def handle_endtag(self, tag):
        if tag == "title":
            self._t = False
        elif tag == "form":
            self._form = None

    def handle_data(self, d):
        if self._t:
            self.title += d


def assess_web(url, timeout=8):
    findings = []

    def add(sev, title, detail):
        findings.append({"severity": sev, "title": title, "detail": detail})

    out = {"url": url, "findings": findings, "redirects": []}
    start_host = urlparse(url).hostname or ""
    cur, resp, body = url, None, b""
    opener = urllib.request.build_opener(_NoRedirect)
    for _ in range(6):
        host = urlparse(cur).hostname
        if urlparse(cur).scheme not in ("http", "https") or not host or not is_public_host(host):
            out["error"] = "Target is not a public, resolvable http(s) host (blocked for safety)."
            out["score"] = 0
            return out
        req = urllib.request.Request(cur, headers={"User-Agent": "Mozilla/5.0 TrustLens-Scanner/1.0"})
        try:
            resp = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            resp = e
        except Exception as e:
            out["error"] = f"Fetch failed: {str(e)[:150]}"
            out["score"] = 0
            return out
        if resp.status in (301, 302, 303, 307, 308) and resp.headers.get("Location"):
            nxt = urljoin(cur, resp.headers["Location"])
            out["redirects"].append({"from": cur, "to": nxt, "status": resp.status})
            cur = nxt
            continue
        body = resp.read(MAX_BYTES)
        break
    else:
        add("medium", "Redirect loop / too many redirects", "Gave up after 6 hops.")
    if resp is None:
        out["score"] = 0
        return out
    out["final_url"], out["status"] = cur, resp.status
    h = {k.lower(): v for k, v in resp.headers.items()}
    out["server"] = h.get("server")
    final_host = urlparse(cur).hostname or ""

    if registered_domain(final_host) != registered_domain(start_host):
        add("high", "Redirects to a different domain", f"{start_host} -> {final_host}")
    if len(out["redirects"]) >= 4:
        add("medium", "Long redirect chain", f"{len(out['redirects'])} hops.")
    if cur.startswith("https"):
        if "strict-transport-security" not in h:
            add("medium", "Missing HSTS", "Strict-Transport-Security header absent.")
    else:
        add("high", "Site served over plain HTTP", "No transport encryption.")
    csp = h.get("content-security-policy")
    if not csp:
        add("medium", "Missing Content-Security-Policy", "Increases XSS impact.")
    elif "unsafe-inline" in csp:
        add("low", "CSP allows unsafe-inline", "")
    if "x-frame-options" not in h and "frame-ancestors" not in (csp or ""):
        add("low", "Clickjacking protection missing", "No X-Frame-Options / frame-ancestors.")
    if h.get("x-content-type-options", "").lower() != "nosniff":
        add("low", "Missing X-Content-Type-Options: nosniff", "")
    if "referrer-policy" not in h:
        add("low", "Missing Referrer-Policy", "")
    if re.search(r"\d+\.\d+", h.get("server", "")) or "x-powered-by" in h:
        add("low", "Technology/version disclosure", f"Server: {h.get('server')}, X-Powered-By: {h.get('x-powered-by')}")
    for c in resp.headers.get_all("Set-Cookie") or []:
        cl = c.lower()
        miss = [n for n, k in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite")) if k not in cl]
        if miss:
            add("low", f"Cookie '{c.split('=')[0]}' missing {', '.join(miss)}", "")
    if h.get("access-control-allow-origin") == "*" and h.get("access-control-allow-credentials", "").lower() == "true":
        add("high", "Permissive CORS with credentials", "")

    text = body.decode("utf-8", "replace")
    pg = _Page()
    try:
        pg.feed(text)
    except Exception:
        pass
    out["title"] = pg.title.strip()[:150]
    for f in pg.forms:
        if not f["password"]:
            continue
        act = urljoin(cur, f["action"]) if f["action"] else cur
        ah = urlparse(act).hostname or ""
        if urlparse(act).scheme != "https":
            add("high", "Password form submits over HTTP", act[:120])
        if registered_domain(ah) != registered_domain(final_host):
            add("critical", "Login form posts to a different domain", f"{final_host} -> {ah} (credential-harvesting pattern)")
    for i in pg.iframes:
        if i["hidden"]:
            add("medium", "Hidden iframe", i["src"][:100])
    if pg.meta_refresh:
        add("medium", "Meta-refresh redirect", pg.meta_refresh[:100])
    if re.search(r"eval\(\s*(atob|unescape)|document\.write\(\s*unescape|String\.fromCharCode\([^)]{80,}", text):
        add("high", "Obfuscated JavaScript", "eval/atob/fromCharCode patterns used by malicious pages.")
    if re.search(r"(registration|processing|security)\s+fee|send\s+(otp|cvv)|enter\s+your\s+(pin|cvv|otp)", text, re.I):
        add("high", "Scam language on page", "Requests fees/OTP/CVV - typical of fake recruitment/payment scams.")
    ext = {urlparse(urljoin(cur, s)).hostname for s in pg.scripts} - {None, final_host}
    if len(ext) > 8:
        add("low", "Many third-party script origins", f"{len(ext)} external hosts.")
    out["score"] = min(100, sum(SEV[f["severity"]] for f in findings))
    return out
