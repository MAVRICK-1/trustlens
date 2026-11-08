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


ALLOWED_PORTS = (None, 80, 443, 8080, 8443)


def host_class(host):
    """'public', 'private' (internal/reserved address) or 'nxdomain' (does not resolve)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return "nxdomain"
    if not infos:
        return "nxdomain"
    return "public" if all(ipaddress.ip_address(i[4][0]).is_global for i in infos) else "private"


def is_public_host(host):
    """SSRF guard: only scan hosts that resolve exclusively to public IPs."""
    return host_class(host) == "public"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class _Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self.title, self._t, self.scripts, self.iframes = [], "", False, [], []
        self.meta_refresh = None
        self.meta, self.links = {}, []
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
        elif tag == "meta":
            key = (a.get("name") or a.get("property") or "").lower()
            if key in ("description", "og:description", "og:site_name", "og:title", "generator") and a.get("content"):
                self.meta.setdefault(key, a["content"].strip()[:300])
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "html" and a.get("lang"):
            self.meta["lang"] = a["lang"][:12]

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

    out = {"url": url, "findings": findings, "redirects": [], "score": 0}
    start_host = urlparse(url).hostname or ""
    cur, resp, body = url, None, b""
    opener = urllib.request.build_opener(_NoRedirect)
    for hop in range(6):
        pc = urlparse(cur)
        try:
            port = pc.port
        except ValueError:
            port = -1
        if hop > 0:  # redirect targets are attacker-controlled: flag instead of silently failing
            if pc.scheme not in ("http", "https"):
                add("high", "Redirects to a non-web scheme", cur[:100])
                break
            if not pc.hostname or host_class(pc.hostname) == "private":
                add("high", "Redirects to an internal/private address", (pc.hostname or "")[:100])
                break
        if pc.scheme not in ("http", "https") or not pc.hostname:
            out["error"] = "Only public http(s) targets can be scanned."
            return out
        if port not in ALLOWED_PORTS:
            out["error"] = f"Port {port} is not scanned (only 80, 443, 8080, 8443)."
            return out
        hc = host_class(pc.hostname)
        if hc != "public":
            out["error"] = ("Domain does not resolve (no DNS record)." if hc == "nxdomain"
                            else "Target resolves to a private/internal address; scan blocked.")
            return out
        req = urllib.request.Request(cur, headers={"User-Agent": "Mozilla/5.0 (compatible; TrustLens-Scanner/1.0)",
                                                   "Accept": "text/html,*/*;q=0.8", "Accept-Encoding": "identity"})
        try:
            resp = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            resp = e
        except Exception as e:
            reason = getattr(e, "reason", e)
            out["error"] = f"Could not fetch the page: {str(reason)[:150]}"
            return out
        if resp.status in (301, 302, 303, 307, 308) and resp.headers.get("Location"):
            nxt = urljoin(cur, resp.headers["Location"])
            out["redirects"].append({"from": cur, "to": nxt, "status": resp.status})
            cur = nxt
            continue
        try:
            body = resp.read(MAX_BYTES)
        except Exception:
            body = b""
        break
    else:
        add("medium", "Redirect loop / too many redirects", "Gave up after 6 hops.")
    if resp is None or not hasattr(resp, "status"):
        return out
    if resp.status in (301, 302, 303, 307, 308) and not body and out["redirects"]:
        out["final_url"], out["status"] = cur, resp.status
        out["score"] = min(100, sum(SEV[f["severity"]] for f in findings))
        return out
    out["final_url"], out["status"] = cur, resp.status
    h = {k.lower(): v for k, v in resp.headers.items()}
    out["server"] = h.get("server")
    final_host = urlparse(cur).hostname or ""
    if resp.status in (401, 403, 429, 503) or (resp.status >= 400 and "cloudflare" in h.get("server", "").lower()):
        out["note"] = f"The site returned HTTP {resp.status}, likely blocking automated scanners. Page-content checks may be incomplete."
    elif resp.status >= 400:
        out["note"] = f"The site returned HTTP {resp.status}."
    ctype = h.get("content-type", "").lower()
    cdisp = h.get("content-disposition", "").lower()
    if "attachment" in cdisp or re.search(r"application/(x-msdownload|x-msi|octet-stream|x-sh|java-archive|vnd\.android)", ctype):
        add("high", "Link triggers a file download", f"{ctype or 'attachment'} {cdisp[:60]}")

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

    text = body.decode("utf-8", "replace") if ("html" in ctype or not ctype) else ""
    if ctype and "html" not in ctype:
        out["note"] = (out.get("note", "") + f" Non-HTML content ({ctype.split(';')[0]}); page-content checks skipped.").strip()
    pg = _Page()
    try:
        pg.feed(text)
    except Exception:
        pass
    out["title"] = pg.title.strip()[:150]
    ext_links = {urlparse(urljoin(cur, l)).hostname for l in pg.links if l.startswith(("http", "//"))} - {None, final_host}
    out["overview"] = {
        "description": pg.meta.get("description") or pg.meta.get("og:description"),
        "site_name": pg.meta.get("og:site_name"), "generator": pg.meta.get("generator"), "lang": pg.meta.get("lang"),
        "forms": len(pg.forms), "login_forms": sum(1 for f in pg.forms if f["password"]),
        "links": len(pg.links), "external_domains": len(ext_links), "scripts": len(pg.scripts),
        "content_type": ctype.split(";")[0] or None, "bytes_read": len(body),
    }
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
