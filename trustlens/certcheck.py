"""TLS certificate validation, trust-chain checks and Certificate Transparency lookup."""
import hashlib
import json
import re
import socket
import ssl
import subprocess
import urllib.request
from datetime import datetime, timezone

# CAs with publicly reported key-generation / issuance incidents: flagged for scrutiny
# (informational watchlist - not a claim that every certificate is invalid).
CA_WATCHLIST = {
    "emudhra": "eMudhra TLS certificate incident: weak CA key generation could allow forged certificates.",
    "diginotar": "DigiNotar was compromised in 2011 and is permanently distrusted.",
    "wosign": "WoSign/StartCom were distrusted for mis-issuance.",
    "startcom": "WoSign/StartCom were distrusted for mis-issuance.",
    "symantec": "Symantec legacy roots were distrusted by major browsers.",
    "cnnic": "CNNIC was distrusted after unauthorised intermediate issuance.",
}
SEV = {"critical": 50, "high": 30, "medium": 15, "low": 5}


def _name(rdn):
    return {k: v for t in rdn for k, v in t}


def _parse_time(s):
    return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _san_match(host, sans):
    host = host.lower()
    for s in sans:
        s = s.lower()
        if s == host or (s.startswith("*.") and "." in host and host.split(".", 1)[1] == s[2:]):
            return True
    return False


def crt_sh(domain, timeout=8):
    """Certificate Transparency lookup via crt.sh (best effort)."""
    try:
        req = urllib.request.Request(f"https://crt.sh/?q={domain}&output=json",
                                     headers={"User-Agent": "TrustLens/1.0"})
        data = json.load(urllib.request.urlopen(req, timeout=timeout))
        issuers = {}
        for e in data:
            n = e.get("issuer_name", "?")
            issuers[n] = issuers.get(n, 0) + 1
        return {"available": True, "total": len(data), "issuers": issuers}
    except Exception as e:
        return {"available": False, "error": str(e)[:120]}


def _handshake(host, port, timeout, verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as s:
        with ctx.wrap_socket(s, server_hostname=host) as t:
            return t.getpeercert(), t.getpeercert(binary_form=True), t.version(), t.cipher()[0]


def _openssl_text(der):
    try:
        return subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-text"],
                              input=der, capture_output=True, timeout=5).stdout.decode()
    except Exception:
        return ""


def _decode_unverified(der, txt):
    """Build a getpeercert()-like dict from openssl text when verification failed."""
    def f(pat):
        m = re.search(pat, txt)
        return m.group(1).strip() if m else None
    cn = lambda line: {"commonName": (re.search(r"CN\s*=\s*([^,\n]+)", line or "") or [None, None])[1],
                       "organizationName": (re.search(r"O\s*=\s*([^,\n]+)", line or "") or [None, None])[1]}
    s, i = cn(f(r"Subject:(.*)")), cn(f(r"Issuer:(.*)"))
    rd = lambda d: tuple(((k, v),) for k, v in d.items() if v)
    sans = re.findall(r"DNS:([^,\s]+)", txt) + re.findall(r"IP Address:([^,\s]+)", txt)
    return {"subject": rd(s), "issuer": rd(i), "subjectAltName": tuple(("DNS", d) for d in sans),
            "notBefore": f(r"Not Before:\s*(.*)"), "notAfter": f(r"Not After\s*:\s*(.*)"),
            "serialNumber": f(r"Serial Number:\s*\n?\s*([0-9a-f:]+)")}


def _key_info(txt):
    info = {}
    m = re.search(r"Public Key Algorithm: (\S+)", txt)
    b = re.search(r"Public-Key: \((\d+) bit\)", txt)
    e = re.search(r"Exponent: (\d+)", txt)
    s = re.search(r"Signature Algorithm: (\S+)", txt)
    if m:
        info["type"] = "RSA" if "rsa" in m.group(1).lower() else "EC"
    if b:
        info["bits"] = int(b.group(1))
    if e:
        info["exponent"] = int(e.group(1))
    if s:
        n = s.group(1).lower()
        info["sig_hash"] = next((h for h in ("md5", "sha1", "sha256", "sha384", "sha512") if h in n), n)
    return info


def check_certificate(host, port=443, ct=False, timeout=8):
    findings = []

    def add(sev, title, detail):
        findings.append({"severity": sev, "title": title, "detail": detail})

    out = {"host": host, "port": port, "findings": findings}
    verified, err = True, None
    try:
        cert, der, proto, cipher = _handshake(host, port, timeout, True)
    except ssl.SSLCertVerificationError as e:
        verified, err = False, e.verify_message
    except (OSError, ssl.SSLError, UnicodeError, ValueError) as e:
        out["error"] = f"No HTTPS/TLS service reachable on port {port}: {str(e)[:120]}"
        add("high", "TLS unavailable", "The site does not offer a working HTTPS connection.")
        out["score"] = SEV["high"]
        return out
    if not verified:
        try:
            _, der, proto, cipher = _handshake(host, port, timeout, False)
        except Exception as e:
            out["error"] = str(e)
            return out
    txt = _openssl_text(der)
    if not verified:
        cert = _decode_unverified(der, txt)
    out.update(chain_valid=verified, protocol=proto, cipher=cipher)
    if not verified:
        add("critical", "Certificate failed trust-chain validation", err or "unknown")

    subj, issuer = _name(cert.get("subject", ())), _name(cert.get("issuer", ()))
    sans = [v for k, v in cert.get("subjectAltName", ()) if k in ("DNS", "IP Address")]
    out.update(subject=subj.get("commonName"), issuer=issuer.get("organizationName") or issuer.get("commonName"),
               sans=sans[:20], sha256=hashlib.sha256(der).hexdigest())
    try:
        nb, na = _parse_time(cert["notBefore"]), _parse_time(cert["notAfter"])
        days_left, life = (na - datetime.now(timezone.utc)).days, (na - nb).days
        out.update(not_before=nb.isoformat(), not_after=na.isoformat(), days_left=days_left, lifetime_days=life)
        if days_left < 0:
            add("critical", "Certificate expired", f"Expired {-days_left} days ago.")
        elif days_left < 14:
            add("medium", "Expires soon", f"{days_left} days remaining.")
        if life > 398:
            add("low", "Validity exceeds 398 days", f"{life}-day lifetime violates browser policy.")
    except (KeyError, ValueError, TypeError):
        pass
    if sans and not _san_match(host, sans):
        add("critical", "Hostname mismatch", f"'{host}' is not covered by the certificate's SANs.")
    if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
        add("high", "Deprecated TLS version", proto)
    if subj and subj == issuer:
        add("high", "Self-signed certificate", "Issuer equals subject.")

    key = _key_info(txt)
    out["key"] = key
    if key.get("type") == "RSA" and key.get("bits", 4096) < 2048:
        add("critical", "Weak RSA key", f"{key['bits']}-bit RSA can be factored.")
    if key.get("type") == "RSA" and key.get("exponent") not in (None, 65537):
        add("low", "Unusual RSA public exponent", str(key["exponent"]))
    if key.get("sig_hash") in ("md5", "sha1"):
        add("high", "Weak signature hash", key["sig_hash"])

    blob = " ".join(str(v) for v in issuer.values()).lower()
    for ca, note in CA_WATCHLIST.items():
        if ca in blob:
            add("medium", f"Issuer on CA watchlist ({ca})", note + " Cross-check with Certificate Transparency.")
    if ct:
        out["ct"] = crt_sh(host)
        c = out["ct"]
        if c.get("available") and len(c["issuers"]) > 4:
            add("medium", "Many distinct issuers in CT logs", f"{len(c['issuers'])} issuers - check for unauthorised issuance.")
    out["score"] = min(100, sum(SEV[f["severity"]] for f in findings))
    return out
