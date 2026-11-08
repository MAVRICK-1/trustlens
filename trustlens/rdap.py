"""Domain registration age via RDAP (public, no API key). Newly registered domains are a strong phishing signal."""
import json
import re
import urllib.request
from datetime import datetime, timezone

from .urlintel import registered_domain


def domain_info(host, timeout=6):
    reg = registered_domain(host)
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z0-9-]{2,}", reg):
        return {"available": False}
    try:
        req = urllib.request.Request(f"https://rdap.org/domain/{reg}",
                                     headers={"User-Agent": "TrustLens/1.0", "Accept": "application/rdap+json"})
        data = json.load(urllib.request.urlopen(req, timeout=timeout))
    except Exception as e:
        return {"available": False, "domain": reg, "error": str(e)[:100]}
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    out = {"available": True, "domain": reg}
    if events.get("registration"):
        try:
            d = datetime.fromisoformat(events["registration"].replace("Z", "+00:00"))
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            out["registered"] = d.date().isoformat()
            out["age_days"] = max(0, (datetime.now(timezone.utc) - d).days)
        except ValueError:
            pass
    if events.get("expiration"):
        out["expires"] = events["expiration"][:10]
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for item in ent.get("vcardArray", [None, []])[1]:
                if item[0] == "fn":
                    out["registrar"] = str(item[3])[:80]
    return out
