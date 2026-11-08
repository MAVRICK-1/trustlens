"""Lexical / heuristic URL threat analysis."""
import ipaddress
import math
import re
from urllib.parse import urlparse

NON_WEB_SCHEMES = {"javascript", "data", "mailto", "file", "ftp", "tel", "vbscript", "blob", "about", "ws", "wss", "sms"}

BRANDS = {
    "paypal": "paypal.com", "google": "google.com", "microsoft": "microsoft.com",
    "apple": "apple.com", "amazon": "amazon.com", "facebook": "facebook.com",
    "instagram": "instagram.com", "netflix": "netflix.com", "sbi": "sbi.co.in",
    "hdfcbank": "hdfcbank.com", "icicibank": "icicibank.com", "paytm": "paytm.com",
    "phonepe": "phonepe.com", "irctc": "irctc.co.in", "linkedin": "linkedin.com",
    "github": "github.com", "dropbox": "dropbox.com", "whatsapp": "whatsapp.com",
    "uidai": "uidai.gov.in", "incometax": "incometax.gov.in", "emudhra": "emudhra.com",
}
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click",
                   "work", "support", "country", "kim", "loan", "rest", "icu", "cyou"}
KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "banking",
            "confirm", "wallet", "payment", "suspend", "unlock", "recover", "password",
            "kyc", "otp", "refund", "reward", "claim", "gift", "invoice", "job-offer",
            "recruit", "hiring", "registration-fee", "lottery", "free"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
              "ow.ly", "shorturl.at"}


def normalize(url):
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url
    p = urlparse(url)
    fixed = re.sub(r"\.(?=(:\d+)?$)", "", p.netloc)  # FQDN trailing dot breaks TLS name matching
    return p._replace(netloc=fixed).geturl() if fixed != p.netloc else url


def registered_domain(host):
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "gov", "ac", "net"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def entropy(s):
    if not s:
        return 0.0
    return -sum(c / len(s) * math.log2(c / len(s)) for c in (s.count(x) for x in set(s)))


def levenshtein(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def deleet(s):
    return s.translate(str.maketrans("0134578", "oleastb")).replace("rn", "m").replace("vv", "w")


def parse_target(raw):
    """Validate and decompose user input. Raises ValueError with a user-facing message."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Enter a URL to scan.")
    if len(raw) > 2000:
        raise ValueError("URL is too long (max 2000 characters).")
    if re.search(r"[\s\x00-\x1f]", raw):
        raise ValueError("URL must not contain spaces or control characters.")
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):(?!\d+(/|$))", raw)
    if m and m.group(1).lower() not in ("http", "https") and (
            "://" in raw or m.group(1).lower() in NON_WEB_SCHEMES):
        raise ValueError(f"Only http and https links can be scanned (got '{m.group(1)}:').")
    url = normalize(raw)
    p = urlparse(url)
    try:
        port = p.port
        orig_host = (p.hostname or "").rstrip(".")
    except ValueError:
        raise ValueError("URL has an invalid port or host.")
    if not orig_host:
        raise ValueError("No hostname found in the URL.")
    try:
        host = orig_host.lower().encode("idna").decode("ascii") if not _is_ip(orig_host) else orig_host.lower()
    except UnicodeError:
        raise ValueError("Hostname is not a valid domain name.")
    if len(host) > 253 or (not _is_ip(host) and not re.fullmatch(r"[a-z0-9._-]+", host)):
        raise ValueError("Hostname is not a valid domain name.")
    return {"url": url, "parsed": p, "host": host, "orig_host": orig_host, "port": port,
            "is_ip": _is_ip(host), "is_idn": host != orig_host.lower()}


def _is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def analyze_url(raw):
    try:
        t = parse_target(raw)
    except ValueError as e:
        return {"url": raw, "host": "", "score": 0, "findings": [], "error": str(e)}
    url, p, host = t["url"], t["parsed"], t["host"]
    findings = []

    def add(points, title, detail):
        findings.append({"points": points, "title": title, "detail": detail})

    if p.scheme != "https":
        add(15, "Not using HTTPS", "Traffic and credentials can be intercepted.")
    if t["is_ip"] or re.fullmatch(r"(0x[0-9a-f]+|\d+)", host):
        add(30, "IP address as host", "Legitimate services rarely use raw IPs.")
    if "@" in p.netloc:
        add(25, "Credentials in URL", "'user@host' trick can hide the real destination.")
    if t["is_idn"] or "xn--" in host:
        add(25, "Punycode / IDN domain", "May be a homograph attack using look-alike Unicode characters.")

    reg = host if t["is_ip"] else registered_domain(host)
    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        add(15, f"High-abuse TLD (.{tld})", "This TLD is disproportionately used for abuse.")
    if host in SHORTENERS:
        add(15, "URL shortener", "Destination is hidden; resolve before trusting.")
    depth = 0 if t["is_ip"] else host.count(".") - reg.count(".")
    if depth >= 3:
        add(15, "Excessive subdomains", f"{depth} subdomain levels in '{host}'.")
    if host.count("-") >= 3:
        add(10, "Many hyphens in host", "Common in throw-away phishing domains.")
    if len(url) > 100:
        add(8, "Very long URL", f"{len(url)} characters.")
    if not t["is_ip"] and entropy(reg.split(".")[0]) > 3.6 and len(reg) > 14:
        add(10, "Random-looking domain", "High-entropy name suggests generated domain.")

    # Brand impersonation (skipped for raw IPs)
    label_text = deleet(host)
    for brand, legit in ({} if t["is_ip"] else BRANDS).items():
        if reg == legit or reg.endswith("." + legit):
            break
        if brand in label_text:
            add(35, f"Impersonates '{brand}'", f"Contains brand name but is not {legit}.")
            break
        core = reg.split(".")[0]
        if len(brand) >= 5 and 0 < levenshtein(deleet(core), brand) <= 1:
            add(35, f"Typosquat of '{brand}'", f"'{core}' is one edit from '{brand}'.")
            break

    kws = [k for k in KEYWORDS if k in (host + p.path).lower()]
    if kws:
        add(min(5 * len(kws), 20), "Phishing keywords", ", ".join(kws))
    if re.search(r"https?(://|%3a%2f%2f)", p.path + "?" + p.query, re.I):
        add(15, "Embedded URL / open redirect", "Another URL is present in path or query.")
    if t["port"] and t["port"] not in (80, 443):
        add(10, "Unusual port", f"Port {t['port']}.")

    score = min(100, sum(f["points"] for f in findings))
    return {"url": url, "host": host, "registered_domain": reg, "score": score, "findings": findings}
