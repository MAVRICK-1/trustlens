"""Collaborative threat intelligence store (SQLite)."""
import os
import sqlite3
import threading
import time

DB = os.environ.get("TRUSTLENS_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "intel.db"))
_lock = threading.Lock()


def _conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS reports(
        id INTEGER PRIMARY KEY, host TEXT NOT NULL, url TEXT, category TEXT, comment TEXT,
        verdict TEXT NOT NULL CHECK(verdict IN ('malicious','safe')), reporter TEXT, ts REAL)""")
    c.execute("CREATE INDEX IF NOT EXISTS ix_host ON reports(host)")
    c.execute("CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, host TEXT, risk INTEGER, label TEXT, ts REAL)")
    return c


def add_report(host, url, category, comment, verdict, reporter):
    with _lock:
        c = _conn()
        with c:
            # one vote per reporter per host (latest wins) limits ballot stuffing
            c.execute("DELETE FROM reports WHERE host=? AND reporter=?", (host, reporter))
            c.execute("INSERT INTO reports(host,url,category,comment,verdict,reporter,ts) VALUES(?,?,?,?,?,?,?)",
                      (host, url[:500], category[:40], comment[:500], verdict, reporter[:64], time.time()))
        c.close()


def lookup(host):
    with _lock:
        c = _conn()
        rows = c.execute("SELECT category,comment,verdict,ts FROM reports WHERE host=? ORDER BY ts DESC", (host,)).fetchall()
        c.close()
    mal = [r for r in rows if r["verdict"] == "malicious"]
    safe = [r for r in rows if r["verdict"] == "safe"]
    w = len(mal) * 1.5
    score = 0 if not rows else round(100 * w / (w + len(safe) + 1))
    cats = {}
    for r in mal:
        cats[r["category"]] = cats.get(r["category"], 0) + 1
    return {"malicious_reports": len(mal), "safe_reports": len(safe), "score": score, "categories": cats,
            "recent": [dict(r) for r in rows[:5]]}


def record_scan(host, risk, label):
    with _lock:
        c = _conn()
        with c:
            c.execute("INSERT INTO scans(host,risk,label,ts) VALUES(?,?,?,?)", (host, risk, label, time.time()))
        c.close()


def feed(limit=20):
    with _lock:
        c = _conn()
        rows = c.execute("""SELECT host, COUNT(*) n, MAX(ts) last, GROUP_CONCAT(DISTINCT category) cats
            FROM reports WHERE verdict='malicious' GROUP BY host ORDER BY n DESC, last DESC LIMIT ?""", (limit,)).fetchall()
        st = c.execute("SELECT COUNT(*) n, SUM(label='Dangerous') d, SUM(label='Suspicious') s FROM scans").fetchone()
        c.close()
    return {"top_threats": [dict(r) for r in rows], "scans": st["n"], "dangerous": st["d"] or 0, "suspicious": st["s"] or 0}
