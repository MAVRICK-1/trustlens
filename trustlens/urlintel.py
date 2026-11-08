"""Lexical / heuristic URL threat analysis."""
import math
import re
from urllib.parse import urlparse

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
        url = "http://" + url
    return url


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


def analyze_url(raw):
    url = normalize(raw)
    p = urlparse(url)
    host = (p.hostname or "").lower()
    findings = []

    def add(points, title, detail):
        findings.append({"points": points, "title": title, "detail": detail})

    if not host:
        return {"url": url, "host": "", "score": 100, "findings": [
            {"points": 100, "title": "Invalid URL", "detail": "No hostname found."}]}

    if p.scheme != "https":
        add(15, "Not using HTTPS", "Traffic and credentials can be intercepted.")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) or re.fullmatch(r"(0x[0-9a-f]+|\d+)", host):
        add(30, "IP address as host", "Legitimate services rarely use raw IPs.")
    if "@" in p.netloc:
        add(25, "Credentials in URL", "'user@host' trick can hide the real destination.")
    if "xn--" in host:
        add(25, "Punycode / IDN domain", "May be a homograph attack using look-alike Unicode characters.")
    if any(ord(c) > 127 for c in host):
        add(25, "Non-ASCII hostname", "Possible homograph attack.")

    reg = registered_domain(host)
    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        add(15, f"High-abuse TLD (.{tld})", "This TLD is disproportionately used for abuse.")
    if host in SHORTENERS:
        add(15, "URL shortener", "Destination is hidden; resolve before trusting.")
    depth = host.count(".") - reg.count(".")
    if depth >= 3:
        add(15, "Excessive subdomains", f"{depth} subdomain levels in '{host}'.")
    if host.count("-") >= 3:
        add(10, "Many hyphens in host", "Common in throw-away phishing domains.")
    if len(url) > 100:
        add(8, "Very long URL", f"{len(url)} characters.")
    if entropy(reg.split(".")[0]) > 3.6 and len(reg) > 14:
        add(10, "Random-looking domain", "High-entropy name suggests generated domain.")

    # Brand impersonation
    label_text = deleet(host)
    for brand, legit in BRANDS.items():
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
    if p.port and p.port not in (80, 443):
        add(10, "Unusual port", f"Port {p.port}.")

    score = min(100, sum(f["points"] for f in findings))
    return {"url": url, "host": host, "registered_domain": reg, "score": score, "findings": findings}
