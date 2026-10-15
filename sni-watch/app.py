#!/usr/bin/env python3
"""Selected-client adult SNI watch. Stdlib only. Reads Xray access.log, never MITM."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None  # type: ignore

CFG_PATH = Path(os.environ.get("SNI_WATCH_CFG", "/etc/sni-watch/config.env"))
IRAN_TZ = ZoneInfo("Asia/Tehran") if ZoneInfo else None
ACCESS_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)?"
    r".*?accepted (?P<net>tcp|udp):(?P<dest>\[[^\]]+\]|[^:\s]+):(?P<port>\d+)"
    r".*?(?:email: (?P<email>\S+))?\s*$"
)
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._@+-]{1,128}$")
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)
PBKDF_ITERS = 200_000
LOGIN_WINDOW = 60.0
LOGIN_MAX = 12

_lock = threading.RLock()
_cfg: dict[str, str] = {}
_adult: set[str] = set()
_watch: dict[str, dict] = {}
_watch_rows: list[dict] = []
_coalesce: dict[tuple[str, str], tuple[float, int]] = {}
_login_hits: dict[str, list[float]] = {}
_started = time.time()
_collector_paused = threading.Event()


def _parse_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = ln.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def load_cfg() -> dict[str, str]:
    d = {
        "LISTEN": "127.0.0.1:8787",
        "ACCESS_LOG": "/var/log/xray/sni-access.log",
        "ACCESS_LOGS": "/var/log/xray/sni-access.log,/var/log/xray/access.log",
        "DB_PATH": "/var/lib/sni-watch/watch.db",
        "DOMAINS_FILE": "/usr/local/lib/sni-watch/adult-domains.txt",
        "EXTRA_DOMAINS": "/etc/sni-watch/extra-domains.txt",
        "AUTH_USER": "watch",
        "COALESCE_SEC": "120",
        "COOKIE_NAME": "sniwatch",
        "USERMAP": "/etc/sni-watch/usermap.json",
        "PANEL_STATUS": "/etc/sni-watch/panel-status.json",
        "RETENTION_DAYS": "2",
    }
    d.update(_parse_env(CFG_PATH))
    return d


def _load_domains() -> set[str]:
    names: set[str] = set()
    for path in (
        Path(_cfg.get("DOMAINS_FILE") or ""),
        Path(_cfg.get("EXTRA_DOMAINS") or ""),
    ):
        if not path.exists():
            continue
        for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
            s = ln.strip().lower().rstrip(".")
            if not s or s.startswith("#"):
                continue
            names.add(s)
    return names


def db() -> sqlite3.Connection:
    path = Path(_cfg["DB_PATH"])
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=8000")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS watchlist (
            email TEXT PRIMARY KEY,
            label TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            created REAL NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            log_ts TEXT NOT NULL,
            email TEXT NOT NULL,
            domain TEXT NOT NULL,
            src TEXT NOT NULL DEFAULT '',
            count INTEGER NOT NULL DEFAULT 1
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS hits_ts ON hits(ts DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS hits_email_ts ON hits(email, ts DESC)")
    cols = {row[1] for row in conn.execute("PRAGMA table_info(watchlist)").fetchall()}
    if "aliases" not in cols:
        conn.execute(
            "ALTER TABLE watchlist ADD COLUMN aliases TEXT NOT NULL DEFAULT ''"
        )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL DEFAULT '')"
    )
    return conn


def retention_sec() -> float:
    try:
        days = float(_cfg.get("RETENTION_DAYS") or 2)
    except ValueError:
        days = 2.0
    return max(0.25, days) * 86400


def meta_get(key: str, default: str = "") -> str:
    conn = db()
    try:
        row = conn.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
        return str(row["v"]) if row else default
    finally:
        conn.close()


def meta_set(key: str, value: str) -> None:
    conn = db()
    try:
        conn.execute(
            "INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (key, value),
        )
    finally:
        conn.close()


def collector_paused() -> bool:
    return _collector_paused.is_set()


def set_collector_paused(paused: bool) -> None:
    if paused:
        _collector_paused.set()
    else:
        _collector_paused.clear()
    meta_set("collector_paused", "1" if paused else "0")


def fmt_when_iran(ts: float) -> str:
    """Human time in Asia/Tehran: امروز/دیروز + ساعت."""
    if IRAN_TZ is not None:
        now = datetime.now(IRAN_TZ)
        dt = datetime.fromtimestamp(float(ts), IRAN_TZ)
    else:
        # Fallback: fixed +03:30 offset
        offset = timedelta(hours=3, minutes=30)
        now = datetime.utcnow() + offset
        dt = datetime.utcfromtimestamp(float(ts)) + offset
    clock = f"{dt.hour:02d}:{dt.minute:02d}"
    delta_days = (now.date() - dt.date()).days
    if delta_days == 0:
        return f"امروز {clock}"
    if delta_days == 1:
        return f"دیروز {clock}"
    if 2 <= delta_days <= 6:
        return f"{delta_days} روز پیش {clock}"
    return f"{dt.year}/{dt.month:02d}/{dt.day:02d} {clock}"


def iran_day_start_ts() -> float:
    if IRAN_TZ is not None:
        now = datetime.now(IRAN_TZ)
        start = datetime(now.year, now.month, now.day, tzinfo=IRAN_TZ)
        return start.timestamp()
    offset = timedelta(hours=3, minutes=30)
    now = datetime.utcnow() + offset
    start = datetime(now.year, now.month, now.day) - offset
    return start.timestamp()


def clear_hits() -> int:
    conn = db()
    try:
        n = conn.execute("SELECT COUNT(*) FROM hits").fetchone()[0]
        conn.execute("DELETE FROM hits")
    finally:
        conn.close()
    with _lock:
        _coalesce.clear()
    return int(n)


def _usermap() -> dict[str, str]:
    path = Path(_cfg.get("USERMAP") or "/etc/sni-watch/usermap.json")
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    out: dict[str, str] = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            ks, vs = str(k).strip().lower(), str(v).strip().lower()
            if EMAIL_RE.match(ks) and EMAIL_RE.match(vs):
                out[ks] = vs
    return out


def _panel_status() -> dict[str, dict]:
    path = Path(_cfg.get("PANEL_STATUS") or "/etc/sni-watch/panel-status.json")
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict] = {}
    for k, v in raw.items():
        if isinstance(v, dict):
            out[str(k).strip().lower()] = v
    return out


def _status_meta(status: str) -> tuple[str, str]:
    s = (status or "?").strip().lower()
    mapping = {
        "active": ("فعال", "st-active"),
        "limited": ("لیمیت", "st-limited"),
        "disabled": ("خاموش", "st-disabled"),
        "expired": ("منقضی", "st-expired"),
        "on_hold": ("نگهداری", "st-hold"),
        "missing": ("حذف‌شده از پنل", "st-missing"),
        "unknown": ("نامشخص", "st-unknown"),
    }
    return mapping.get(s, (status or "نامشخص", "st-unknown"))


def _watch_panel_uid(email: str, label: str, aliases: str) -> str:
    umap = _usermap()
    seeds = [email, label, *(a.strip() for a in (aliases or "").split(","))]
    for s in seeds:
        sl = str(s or "").strip().lower()
        if not sl:
            continue
        if sl in umap:
            return str(umap[sl])
        if sl.isdigit():
            return sl
    return ""


def _enrich_client(email: str, label: str, enabled: bool, aliases: str) -> dict:
    uid = _watch_panel_uid(email, label, aliases)
    st_map = _panel_status()
    info = st_map.get(uid) if uid else None
    if info is None and email:
        for v in st_map.values():
            if isinstance(v, dict) and str(v.get("watch_email") or "").lower() == email.lower():
                info = v
                break
    if info is None:
        # No status file yet → unknown; if we have aliases/id but no status entry, treat as missing
        raw_status = "missing" if (uid or st_map) else "unknown"
    else:
        raw_status = str(info.get("status") or "?").lower()
    label_fa, css = _status_meta(raw_status)
    return {
        "email": email,
        "label": label,
        "enabled": enabled,
        "aliases": aliases,
        "panel_id": uid,
        "panel_status": raw_status,
        "status_label": label_fa,
        "status_class": css,
        "attention": raw_status in {"limited", "missing", "expired", "disabled"},
    }


def _alias_set(email: str, aliases: str, label: str) -> list[str]:
    umap = _usermap()
    seen: set[str] = set()
    seeds = [
        email,
        label,
        *(a.strip() for a in (aliases or "").split(",")),
    ]
    for s in list(seeds):
        mapped = umap.get(str(s or "").strip().lower(), "")
        if mapped:
            seeds.append(mapped)
    # Any panel name/id/uuid that resolves to the same Xray email.
    targets = {str(x).strip().lower() for x in seeds if str(x).strip()}
    for k, v in umap.items():
        ks, vs = str(k).strip().lower(), str(v).strip().lower()
        if ks in targets or vs in targets:
            targets.add(ks)
            targets.add(vs)
    keys: list[str] = []
    for s in sorted(targets):
        if not s or not EMAIL_RE.match(s) or s in seen:
            continue
        seen.add(s)
        keys.append(s)
    return keys


def log_paths() -> list[Path]:
    raw = _cfg.get("ACCESS_LOGS") or _cfg.get("ACCESS_LOG") or ""
    out: list[Path] = []
    seen: set[str] = set()
    for part in raw.split(","):
        p = part.strip()
        if not p or p in seen:
            continue
        seen.add(p)
        out.append(Path(p))
    return out or [Path("/var/log/xray/sni-access.log")]


def refresh_watch() -> None:
    global _watch, _watch_rows
    conn = db()
    rows = conn.execute(
        "SELECT email, label, enabled, aliases FROM watchlist"
    ).fetchall()
    conn.close()
    by_key: dict[str, dict] = {}
    unique: list[dict] = []
    for r in rows:
        email = str(r["email"]).lower()
        meta = {
            "email": email,
            "label": r["label"] or r["email"],
            "enabled": bool(r["enabled"]),
        }
        unique.append(meta)
        for key in _alias_set(email, r["aliases"] or "", r["label"] or ""):
            by_key[key] = meta
    _watch = by_key
    _watch_rows = unique


def is_adult(host: str) -> bool:
    host = host.lower().rstrip(".")
    if not host or IPV4_RE.match(host) or ":" in host:
        return False
    parts = host.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in _adult:
            return True
    return False


def parse_line(line: str) -> dict | None:
    m = ACCESS_RE.search(line.strip())
    if not m:
        return None
    email = (m.group("email") or "").strip().rstrip(",")
    dest = (m.group("dest") or "").strip().strip("[]").lower().rstrip(".")
    if not email or not dest:
        return None
    if IPV4_RE.match(dest) or dest.startswith("::") or dest.count(":") >= 2:
        return None
    src = ""
    sm = re.search(r"from (?:tcp:|udp:)?(\d{1,3}(?:\.\d{1,3}){3}):\d+", line)
    if sm:
        src = sm.group(1)
    return {
        "log_ts": m.group("ts"),
        "email": email,
        "domain": dest,
        "src": src,
    }


def record_hit(ev: dict) -> None:
    email = ev["email"].lower()
    with _lock:
        meta = _watch.get(email)
        if not meta or not meta["enabled"]:
            return
        if not is_adult(ev["domain"]):
            return
        now = time.time()
        window = float(_cfg.get("COALESCE_SEC") or 120)
        stored = meta["email"]
        key = (stored, ev["domain"])
        prev = _coalesce.get(key)
        conn = db()
        try:
            if prev and now - prev[0] < window:
                conn.execute(
                    "UPDATE hits SET count = count + 1, ts = ?, log_ts = ?, src = ? WHERE id = ?",
                    (now, ev["log_ts"], ev["src"], prev[1]),
                )
                _coalesce[key] = (now, prev[1])
            else:
                cur = conn.execute(
                    "INSERT INTO hits(ts, log_ts, email, domain, src, count) VALUES (?,?,?,?,?,1)",
                    (now, ev["log_ts"], stored, ev["domain"], ev["src"]),
                )
                _coalesce[key] = (now, int(cur.lastrowid))
        finally:
            conn.close()


def prune_hits() -> None:
    cutoff = time.time() - retention_sec()
    conn = db()
    try:
        conn.execute("DELETE FROM hits WHERE ts < ?", (cutoff,))
    finally:
        conn.close()


def follow_log() -> None:
    states: dict[str, tuple[int, int, bool]] = {}
    last_prune = 0.0
    last_refresh = 0.0
    replay = (_cfg.get("REPLAY_LOG") or "").strip() in {"1", "true", "yes"}
    while True:
        now = time.time()
        if collector_paused():
            for path in log_paths():
                try:
                    st = path.stat()
                    states[str(path)] = (st.st_size, st.st_ino, True)
                except FileNotFoundError:
                    states[str(path)] = (0, -1, False)
            if now - last_prune > 600:
                prune_hits()
                last_prune = now
            time.sleep(1.5)
            continue
        for path in log_paths():
            key = str(path)
            pos, inode, primed = states.get(key, (0, -1, False))
            try:
                st = path.stat()
            except FileNotFoundError:
                states[key] = (0, -1, False)
                continue
            if not primed and not replay:
                states[key] = (st.st_size, st.st_ino, True)
                continue
            if st.st_ino != inode or st.st_size < pos:
                pos = 0
                inode = st.st_ino
            try:
                with path.open("r", encoding="utf-8", errors="replace") as f:
                    f.seek(pos)
                    while True:
                        line = f.readline()
                        if not line:
                            break
                        ev = parse_line(line)
                        if ev:
                            record_hit(ev)
                    pos = f.tell()
            except OSError:
                continue
            states[key] = (pos, inode, True)
        if now - last_refresh > 5:
            refresh_watch()
            last_refresh = now
        if now - last_prune > 600:
            prune_hits()
            last_prune = now
        time.sleep(0.4)


def verify_password(password: str) -> bool:
    raw = _cfg.get("AUTH_HASH") or ""
    parts = raw.split("$")
    if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
        return False
    try:
        iters = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expect = bytes.fromhex(parts[3])
    except ValueError:
        return False
    got = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
    return hmac.compare_digest(got, expect)


def make_session() -> str:
    exp = str(int(time.time()) + 7 * 24 * 3600)
    user = _cfg.get("AUTH_USER") or "watch"
    msg = f"{exp}:{user}".encode()
    sig = hmac.new(
        (_cfg.get("SESSION_SECRET") or "").encode(), msg, hashlib.sha256
    ).hexdigest()
    return f"{exp}:{sig}"


def valid_session(token: str) -> bool:
    if not token or ":" not in token:
        return False
    exp_s, sig = token.split(":", 1)
    try:
        exp = int(exp_s)
    except ValueError:
        return False
    if exp < int(time.time()):
        return False
    user = _cfg.get("AUTH_USER") or "watch"
    msg = f"{exp}:{user}".encode()
    expect = hmac.new(
        (_cfg.get("SESSION_SECRET") or "").encode(), msg, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(sig, expect)


def login_allowed(ip: str) -> bool:
    now = time.time()
    hits = [t for t in _login_hits.get(ip, []) if now - t < LOGIN_WINDOW]
    _login_hits[ip] = hits
    if len(hits) >= LOGIN_MAX:
        return False
    hits.append(now)
    _login_hits[ip] = hits
    return True


def json_bytes(obj: object, code: int = 200) -> tuple[int, bytes, str]:
    return code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8"


LOGIN_HTML = """<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>دیده‌بان</title>
<style>
:root { --bg:#0b1220; --card:#152036; --line:#243656; --txt:#e8eef9; --mut:#8aa0c2; --acc:#fb7185; --ok:#34d399; }
* { box-sizing:border-box; }
body { margin:0; min-height:100vh; font-family:Tahoma,Vazirmatn,sans-serif; background:radial-gradient(1200px 500px at 80% -10%, #1e3a5f 0%, var(--bg) 55%); color:var(--txt); display:flex; align-items:center; justify-content:center; }
form { width:min(420px,92vw); background:var(--card); border:1px solid var(--line); border-radius:18px; padding:28px 24px 22px; box-shadow:0 20px 50px #0007; }
h1 { margin:0 0 6px; font-size:22px; }
p { margin:0 0 18px; color:var(--mut); font-size:13px; }
label { display:block; font-size:12px; color:var(--mut); margin:12px 0 6px; }
input { width:100%; padding:11px 12px; border-radius:10px; border:1px solid var(--line); background:#0d1728; color:var(--txt); font-size:15px; }
button { width:100%; margin-top:18px; padding:12px; border:0; border-radius:11px; background:linear-gradient(180deg,#fb7185,#e11d48); color:#fff; font-weight:700; cursor:pointer; }
.err { background:#3f1d2a; color:#fecdd3; padding:8px 10px; border-radius:8px; margin-bottom:12px; font-size:13px; }
</style>
</head>
<body>
<form method="post" action="login">
<h1>دیده‌بان</h1>
<p>فقط کلاینت‌هایی که خودتان انتخاب کنید. محتوای صفحات ذخیره نمی‌شود.</p>
ERR
<label>نام کاربری</label>
<input name="user" autocomplete="username" required>
<label>رمز</label>
<input name="pass" type="password" autocomplete="current-password" required>
<button type="submit">ورود</button>
</form>
</body>
</html>
"""

APP_HTML = """<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>دیده‌بان</title>
<style>
:root { --bg:#0b1220; --card:#121c2f; --line:#243656; --txt:#e8eef9; --mut:#8aa0c2; --acc:#fb7185; --ok:#34d399; --side:#0e1728; }
* { box-sizing:border-box; }
body { margin:0; font-family:Tahoma,Vazirmatn,sans-serif; background:var(--bg); color:var(--txt); }
.shell { display:grid; grid-template-columns:240px 1fr; min-height:100vh; }
aside.menu { background:var(--side); border-left:1px solid var(--line); padding:18px 12px; position:sticky; top:0; height:100vh; }
.brand { font-weight:800; padding:8px 12px 16px; font-size:16px; }
.brand span { display:block; color:var(--mut); font-weight:400; font-size:11px; margin-top:4px; }
.mi { display:block; padding:10px 12px; border-radius:10px; color:var(--txt); text-decoration:none; margin-bottom:6px; }
.mi:hover { background:#18263d; }
.mi.active { background:#1d4ed8; color:#fff; }
.work { min-width:0; }
header { display:flex; justify-content:space-between; align-items:center; gap:16px; padding:16px 22px; border-bottom:1px solid var(--line); position:sticky; top:0; background:#0b1220ee; backdrop-filter:blur(8px); z-index:2; }
.actions { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
h1 { margin:0; font-size:18px; }
.sub { color:var(--mut); font-size:12px; margin-top:3px; }
.banner { margin:0 16px; margin-top:12px; padding:10px 14px; border-radius:12px; background:#3f2a12; color:#fdba74; font-size:13px; display:none; }
.banner.on { display:block; }
.grid { display:grid; grid-template-columns:minmax(28rem, 0.92fr) minmax(0, 1.15fr); gap:16px; padding:16px; align-items:start; }
@media (max-width:1100px) { .shell { grid-template-columns:1fr; } aside.menu { height:auto; position:relative; display:flex; gap:8px; align-items:center; } .brand { padding:4px 8px; } .grid { grid-template-columns:1fr; } }
.card { background:var(--card); border:1px solid var(--line); border-radius:16px; padding:16px 18px; }
h2 { margin:0 0 10px; font-size:15px; }
label, .hint { display:block; color:var(--mut); font-size:12px; margin:8px 0 4px; line-height:1.6; }
input, select { width:100%; padding:9px 10px; border-radius:9px; border:1px solid var(--line); background:#0d1728; color:var(--txt); }
.row { display:flex; gap:8px; }
.row > * { flex:1; }
button { border:0; border-radius:9px; padding:9px 12px; cursor:pointer; font-weight:700; font-family:inherit; }
.btn { background:#1d4ed8; color:#fff; }
.danger { background:#7f1d1d; color:#fecaca; }
.warn { background:#7c2d12; color:#fed7aa; }
.ghost { background:transparent; color:var(--mut); border:1px solid var(--line); }
.item { display:flex; justify-content:space-between; gap:12px; align-items:flex-start; padding:12px 0; border-bottom:1px solid #1c2a44; }
.item:last-child { border:0; }
.item .id { word-break:break-all; }
.pill { font-size:11px; padding:3px 9px; border-radius:999px; white-space:nowrap; font-weight:700; }
.on { background:#064e3b; color:var(--ok); }
.off { background:#3f1d2a; color:#fda4af; }
.st-active { background:#064e3b; color:#6ee7b7; }
.st-limited { background:#7c2d12; color:#fdba74; border:1px solid #ea580c; }
.st-disabled { background:#1e293b; color:#94a3b8; }
.st-expired { background:#7f1d1d; color:#fecaca; }
.st-hold { background:#312e81; color:#c7d2fe; }
.st-missing { background:#450a0a; color:#fda4af; border:1px solid #f87171; }
.st-unknown { background:#334155; color:#e2e8f0; }
.item.row-limited { background:linear-gradient(90deg, #7c2d1222, transparent); border-radius:10px; padding-right:8px; }
.item.row-missing { background:linear-gradient(90deg, #7f1d1d33, transparent); border-radius:10px; padding-right:8px; }
.item .name-missing { color:#fda4af; text-decoration:line-through; }
.hit { display:grid; grid-template-columns:1fr auto; gap:12px; padding:12px 0; border-bottom:1px solid #1c2a44; font-size:13px; align-items:start; }
.hit:last-child { border:0; }
.dom { color:var(--acc); font-weight:700; word-break:break-all; }
.mut { color:var(--mut); }
.empty { color:var(--mut); padding:24px 8px; text-align:center; }
.time { text-align:left; color:var(--mut); white-space:nowrap; }
.cnt { display:inline-block; margin-top:4px; font-size:11px; padding:2px 8px; border-radius:999px; background:#1e293b; color:#cbd5e1; }
.docs { padding:20px 28px 48px; max-width:900px; line-height:1.85; }
.docs h1 { font-size:22px; margin-bottom:8px; }
.docs h2 { font-size:17px; margin:28px 0 10px; padding-top:8px; border-top:1px solid var(--line); }
.docs h3 { font-size:14px; margin:18px 0 6px; color:#cbd5e1; }
.docs p, .docs li { color:#dbe4f3; font-size:14px; }
.docs ul, .docs ol { padding-right:20px; }
.docs code, .docs pre { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12px; }
.docs code { background:#0d1728; padding:1px 6px; border-radius:6px; }
.docs pre { background:#0d1728; border:1px solid var(--line); border-radius:12px; padding:14px; overflow:auto; direction:ltr; text-align:left; }
.docs table { width:100%; border-collapse:collapse; font-size:13px; margin:10px 0 16px; }
.docs th, .docs td { border:1px solid var(--line); padding:8px 10px; text-align:right; vertical-align:top; }
.docs th { background:#152036; color:var(--mut); font-weight:700; }
.docs td path, .docs .path { direction:ltr; text-align:left; unicode-bidi:embed; }
</style>
</head>
<body>
<div class="shell">
<aside class="menu">
  <div class="brand">دیده‌بان<span>کلاینت‌های انتخابی</span></div>
  <a class="mi" id="nav-watch" href=".">گزارش‌ها</a>
  <a class="mi" id="nav-docs" href="docs">مستندات</a>
</aside>
<div class="work">
<div id="page-watch">
<header>
  <div>
    <h1>گزارش بازدید</h1>
    <div class="sub">فقط دامنه مقصد از لاگ Xray — بدون محتوای صفحه</div>
  </div>
  <div class="actions">
    <button class="warn" id="pause" type="button">توقف جمع‌آوری</button>
    <button class="danger" id="clear" type="button">پاکسازی گزارش‌ها</button>
    <form method="post" action="logout"><button class="ghost" type="submit">خروج</button></form>
  </div>
</header>
<div class="banner" id="banner">جمع‌آوری متوقف است؛ لاگ خوانده نمی‌شود تا دوباره شروع کنید.</div>
<div class="grid">
  <section class="card">
    <h2>کلاینت‌های تحت نظر</h2>
    <p class="hint">نام پنل، id یا UUID وی‌لس. Xray در لاگ UUID را نمی‌نویسد؛ email همان id عددی است.</p>
    <div class="row">
      <input id="email" placeholder="RoOtIt یا UUID یا 4">
      <input id="label" placeholder="نام، مثلاً لپ‌تاپ من">
    </div>
    <div class="row" style="margin-top:8px">
      <button class="btn" id="add" type="button">افزودن / به‌روز</button>
    </div>
    <div id="watch"></div>
  </section>
  <section class="card">
    <div class="row">
      <div>
        <h2>رویدادها</h2>
        <div class="sub" id="stats"></div>
      </div>
      <select id="filter" style="max-width:240px"><option value="">همه کلاینت‌ها</option></select>
    </div>
    <div id="hits"></div>
  </section>
</div>
</div>
<article class="docs" id="page-docs" hidden>
<header>
  <div>
    <h1>مستندات نصب و فایل‌ها</h1>
    <div class="sub">sni-watch — بستهٔ مستقل، قابل نصب روی سرور Xray دیگر</div>
  </div>
  <form method="post" action="logout"><button class="ghost" type="submit">خروج</button></form>
</header>
<h2>این ابزار چیست</h2>
<p>دیده‌بان فقط برای <b>سیستم‌های خودتان</b> است. محتوای HTTPS خوانده نمی‌شود. از لاگ Xray فقط hostname مقصد (SNI) برداشته می‌شود و با فهرست دامنه‌های بزرگسال مقایسه می‌گردد. فقط کلاینت‌هایی که در صفحهٔ گزارش‌ها اضافه کنید ذخیره می‌شوند.</p>
<p>باید روی همان ماشینی نصب شود که کلاینت به آن وصل می‌شود و در لاگ فیلد <code>email:</code> دارد. در استک دوهاب این <b>رلهٔ ایران</b> است، نه Exit (آنجا همه چیز <code>backhaul-xhttp</code> است).</p>

<h2>نصب روی سرور جدید</h2>
<p>پیش‌نیاز: پایتون ۳.۱۰+، systemd، و Xray با <code>access.log</code> که در هر خط <code>email:</code> کاربر را دارد.</p>
<ol>
<li>پوشهٔ بسته را از مخزن کپی کنید: <code>scripts/sni-watch/</code></li>
<li>روی سرور ورود (همان‌جا که کلاینت وصل می‌شود) اجرا کنید:</li>
</ol>
<pre>cd sni-watch
sudo AUTH_USER=watch AUTH_PASS='رمز-دلخواه' ./install.sh</pre>
<p>اگر <code>AUTH_PASS</code> ندهید، رمز ساخته می‌شود و در <code>/etc/sni-watch/admin.pass</code> (mode 600) نوشته می‌شود.</p>
<p>پیش‌فرض به <code>127.0.0.1:8787</code> گوش می‌دهد. برای دسترسی مستقیم از بیرون:</p>
<pre>sudo LISTEN=0.0.0.0:8787 AUTH_USER=watch AUTH_PASS='...' ACCESS_LOG=/var/log/xray/access.log ./install.sh</pre>
<p>بعد پورت را در فایروال همان سرور باز کنید. لاگ پیش‌فرض نصب مستقل: <code>/var/log/xray/access.log</code>.</p>
<p>متغیرهای اختیاری نصب: <code>AUTH_USER</code>، <code>AUTH_PASS</code>، <code>LISTEN</code>، <code>ACCESS_LOG</code>.</p>

<h2>فایل‌های داخل بسته (مخزن)</h2>
<table>
<tr><th>مسیر در vpn-infra</th><th>نقش</th></tr>
<tr><td class="path">scripts/sni-watch/app.py</td><td>جمع‌آور لاگ + صفحهٔ وب</td></tr>
<tr><td class="path">scripts/sni-watch/install.sh</td><td>نصب مستقل روی یک سرور</td></tr>
<tr><td class="path">scripts/sni-watch/adult-domains.txt</td><td>فهرست دامنهٔ بزرگسال</td></tr>
<tr><td class="path">scripts/sni-watch/sni-watch.service</td><td>واحد systemd</td></tr>
<tr><td class="path">scripts/sni-watch/resolve_watchlist.py</td><td>نام/UUID پنل → id عددی (روی Exit)</td></tr>
<tr><td class="path">scripts/sni-watch/xray-stdin-wrap.sh</td><td>برگرداندن access لاگ SNI در نود ایران</td></tr>
<tr><td class="path">scripts/sni-watch/ensure_xray_wrap.sh</td><td>نصب مجدد wrap اگر کانتینر عوض شد</td></tr>
<tr><td class="path">configs/sni-watch/sni-watch-tunnel.service</td><td>تونل SSH از Exit به ایران:8787</td></tr>
<tr><td class="path">configs/sni-watch/sni-watch-resolve.timer</td><td>هر دقیقه resolve نام‌ها</td></tr>
<tr><td class="path">configs/sni-watch/sni-xray-wrap.timer</td><td>پایدار ماندن wrap روی ایران</td></tr>
<tr><td class="path">docs/sni-watch.md</td><td>همین راهنما در مخزن</td></tr>
</table>

<h2>محل فایل‌ها بعد از نصب (روی سرور ورود / ایران)</h2>
<table>
<tr><th>مسیر</th><th>نقش</th></tr>
<tr><td class="path">/usr/local/lib/sni-watch/app.py</td><td>برنامه</td></tr>
<tr><td class="path">/usr/local/lib/sni-watch/adult-domains.txt</td><td>فهرست دامنه</td></tr>
<tr><td class="path">/etc/sni-watch/config.env</td><td>تنظیمات (mode 600)</td></tr>
<tr><td class="path">/etc/sni-watch/admin.user</td><td>نام کاربری صفحه</td></tr>
<tr><td class="path">/etc/sni-watch/admin.pass</td><td>رمز صفحه</td></tr>
<tr><td class="path">/etc/sni-watch/extra-domains.txt</td><td>دامنه‌های اضافه</td></tr>
<tr><td class="path">/etc/sni-watch/usermap.json</td><td>نگاشت نام و UUID به id</td></tr>
<tr><td class="path">/var/lib/sni-watch/watch.db</td><td>کلاینت‌ها و گزارش‌ها (SQLite)</td></tr>
<tr><td class="path">/var/log/xray/sni-access.log</td><td>لاگ SNI (این استک)</td></tr>
<tr><td class="path">/var/log/xray/access.log</td><td>لاگ نود / Xray</td></tr>
<tr><td class="path">/etc/systemd/system/sni-watch.service</td><td>سرویس</td></tr>
<tr><td class="path">/usr/local/sbin/ensure_xray_wrap.sh</td><td>نگه داشتن wrap</td></tr>
<tr><td class="path">/var/lib/pg-node/xray-wrap/</td><td>کپی wrap برای بعد از recreate کانتینر</td></tr>
</table>

<h2>این استک دوهاب (ایران + Exit)</h2>
<ul>
<li>سرویس روی ایران: <code>sni-watch.service</code> → <code>127.0.0.1:8787</code></li>
<li>تونل از Exit: <code>sni-watch-tunnel.service</code></li>
<li>صفحه: <code>https://panel.jetengine.ir:2096/watch/</code> (همان TLS پنل؛ لاگین جدا از PasarGuard)</li>
<li>مستندات: <code>https://panel.jetengine.ir:2096/watch/docs</code></li>
<li>روی Exit: <code>sni-watch-resolve.timer</code> نام/UUID دیده‌بان را به id پنل وصل می‌کند</li>
<li>رمز عملیاتی Exit: <code>/root/.vpn-secrets/sni-watch.env</code></li>
</ul>
<p>Node در پنل PasarGuard باید <b>disabled</b> بماند؛ Xray از مسیر iran-sync بالا است. تیک Restart Nodes را نزنید.</p>

<h2>استفاده از صفحه</h2>
<ul>
<li>کلاینت: نام کاربری پنل، id عددی، یا UUID وی‌لس. Xray در لاگ UUID را نمی‌نویسد؛ <code>email:</code> همان id است.</li>
<li>توقف جمع‌آوری: خواندن لاگ قطع می‌شود تا CPU درگیر نباشد؛ صفحه می‌ماند.</li>
<li>پاکسازی: حذف گزارش‌های فعلی. نگهداری خودکار <b>۲ روز</b> است.</li>
<li>خاموش روی هر کلاینت: فقط همان نفر از دیده‌بان خارج می‌شود.</li>
</ul>
<p>دامنهٔ اضافه: <code>/etc/sni-watch/extra-domains.txt</code> سپس <code>systemctl restart sni-watch</code>.</p>

<h2>دستورهای سرویس</h2>
<pre>systemctl status sni-watch
systemctl restart sni-watch
# روی Exit:
systemctl status sni-watch-tunnel sni-watch-resolve.timer</pre>

<h2>محدودیت و عیب‌یابی</h2>
<ul>
<li>اگر در لاگ فقط IP باشد (بدون دامنه) تشخیص سایت ممکن نیست.</li>
<li>DNS به <code>1.1.1.1</code> نام سایت را نشان نمی‌دهد؛ اتصال TLS بعدی اگر sniff شود کافی است.</li>
<li>HTTP3/QUIC گاهی فقط IP می‌ماند.</li>
<li>لاگ SNI را با <code>mv</code> عوض نکنید؛ Xray به inode قبلی می‌نویسد. در صورت نیاز سرویس Xray را از نو بالا بیاورید تا فایل را دوباره باز کند.</li>
</ul>
</article>
</div>
</div>
<script>
const $ = (id) => document.getElementById(id);
const isDocs = /(?:^|\\/)docs$/.test(location.pathname.replace(/\\/+$/,''));
$('page-docs').hidden = !isDocs;
$('page-watch').hidden = isDocs;
$('nav-docs').classList.toggle('active', isDocs);
$('nav-watch').classList.toggle('active', !isDocs);
document.title = isDocs ? 'مستندات دیده‌بان' : 'دیده‌بان';
if (isDocs) {
  // docs only
} else {
let paused = false;
function esc(s){ return String(s||'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
async function api(path, body){
  const opt = body ? {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify(body)} : {};
  const r = await fetch(path, opt);
  if (r.status === 401) { location.reload(); return null; }
  return r.json();
}
function setPaused(v){
  paused = !!v;
  $('banner').classList.toggle('on', paused);
  $('pause').textContent = paused ? 'ادامه جمع‌آوری' : 'توقف جمع‌آوری';
  $('pause').className = paused ? 'btn' : 'warn';
}
function renderWatch(list){
  const box = $('watch');
  const sel = $('filter');
  const cur = sel.value;
  sel.innerHTML = '<option value="">همه کلاینت‌ها</option>' + list.map(w =>
    `<option value="${esc(w.email)}">${esc(w.label)} (${esc(w.email)})</option>`).join('');
  sel.value = cur;
  if (!list.length){ box.innerHTML = '<div class="empty">هنوز کسی انتخاب نشده.</div>'; return; }
  const attn = list.filter(w => w.attention).length;
  const head = attn
    ? `<p class="hint" style="color:#fdba74">⚠ ${attn} نفر لیمیت/حذف‌شده/مشکل‌دار — بهتر است از دیده‌بان حذف شوند.</p>`
    : '';
  box.innerHTML = head + list.map(w => {
    const rowCls = ['item', w.panel_status==='limited'?'row-limited':'', (w.panel_status==='missing'||w.panel_status==='expired')?'row-missing':''].filter(Boolean).join(' ');
    const nameCls = (w.panel_status==='missing') ? 'name-missing' : '';
    const pid = w.panel_id ? ('id=' + w.panel_id + ' · ') : '';
    return `<div class="${rowCls}">
    <div><b class="${nameCls}">${esc(w.label)}</b><div class="mut id">${pid}${esc(w.email)}${w.aliases ? '<br>' + esc(w.aliases) : ''}</div></div>
    <div class="row" style="flex:0 0 auto;align-items:center">
      <span class="pill ${esc(w.status_class || 'st-unknown')}">${esc(w.status_label || '?')}</span>
      <span class="pill ${w.enabled?'on':'off'}">${w.enabled?'دیده‌بان روشن':'دیده‌بان خاموش'}</span>
      <button class="ghost" data-act="toggle" data-email="${esc(w.email)}" data-on="${w.enabled?0:1}">${w.enabled?'خاموش':'روشن'}</button>
      <button class="danger" data-act="del" data-email="${esc(w.email)}">حذف</button>
    </div></div>`;
  }).join('');
  box.querySelectorAll('button[data-act]').forEach(btn => {
    btn.onclick = () => {
      const email = btn.getAttribute('data-email') || '';
      if (btn.getAttribute('data-act') === 'del') delw(email);
      else toggle(email, btn.getAttribute('data-on') === '1');
    };
  });
}
function renderHits(rows, stats){
  const days = stats.retention_days || 2;
  $('stats').textContent = stats.watched + ' کلاینت فعال · ' + stats.today + ' امروز · ' + stats.total + ' در ' + days + ' روز';
  const f = $('filter').value;
  const show = f ? rows.filter(h => h.email === f) : rows;
  if (!show.length){ $('hits').innerHTML = '<div class="empty">هنوز رویدادی برای این انتخاب نیست.</div>'; return; }
  $('hits').innerHTML = show.map(h => `<div class="hit">
    <div>
      <div class="dom">${esc(h.domain)}</div>
      <div class="mut">${esc(h.label)} · ${esc(h.email)}${h.src?' · '+esc(h.src):''}</div>
    </div>
    <div class="time">${esc(h.when_h || h.log_ts)}<div class="cnt">${h.count>1? (h.count+' بار') : '۱ بار'}</div></div>
  </div>`).join('');
}
async function refresh(){
  const [w, h] = await Promise.all([api('api/watchlist'), api('api/hits')]);
  if (!w || !h) return;
  if (h.stats && typeof h.stats.paused === 'boolean') setPaused(h.stats.paused);
  renderWatch(w.clients);
  renderHits(h.hits, h.stats);
}
$('add').onclick = async () => {
  const email = $('email').value.trim();
  const label = $('label').value.trim();
  if (!email) return;
  await api('api/watchlist', {email, label});
  $('email').value = ''; $('label').value = '';
  refresh();
};
$('pause').onclick = async () => {
  await api('api/collector', {paused: !paused});
  refresh();
};
$('clear').onclick = async () => {
  if (!confirm('همه گزارش‌های فعلی حذف شوند؟')) return;
  await api('api/hits/clear', {});
  refresh();
};
async function toggle(email, enabled){ await api('api/watchlist/toggle', {email, enabled: !!enabled}); refresh(); }
async function delw(email){ if (!confirm('حذف این کلاینت از دیده‌بان؟')) return; await api('api/watchlist/delete', {email}); refresh(); }
$('filter').onchange = refresh;
refresh();
setInterval(refresh, 4000);
}
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "sni-watch/1"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return

    def _cookie(self) -> str:
        raw = self.headers.get("Cookie") or ""
        name = _cfg.get("COOKIE_NAME") or "sniwatch"
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    def _authed(self) -> bool:
        return valid_session(self._cookie())

    def _secure(self) -> bool:
        xf = (self.headers.get("X-Forwarded-Proto") or "").lower()
        return xf == "https"

    def _send(self, code: int, body: bytes, ctype: str, extra: list[tuple[str, str]] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in extra or []:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n > 1_000_000:
            return {}
        raw = self.rfile.read(n) if n else b"{}"
        try:
            obj = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            return {}
        return obj if isinstance(obj, dict) else {}

    def _read_form(self) -> dict[str, str]:
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        q = parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
        return {k: (v[-1] if v else "") for k, v in q.items()}

    def _set_cookie_header(self, token: str, clear: bool = False) -> tuple[str, str]:
        name = _cfg.get("COOKIE_NAME") or "sniwatch"
        flags = "HttpOnly; SameSite=Strict; Path=/"
        if self._secure():
            flags += "; Secure"
        if clear:
            return "Set-Cookie", f"{name}=; Max-Age=0; {flags}"
        return "Set-Cookie", f"{name}={token}; Max-Age={7*24*3600}; {flags}"

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path in ("/", "/index.html", "/docs"):
            if not self._authed():
                body = LOGIN_HTML.replace("ERR", "").encode("utf-8")
                self._send(200, body, "text/html; charset=utf-8")
                return
            self._send(200, APP_HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if not self._authed():
            self._send(*json_bytes({"error": "auth"}, 401))
            return
        if path == "/api/watchlist":
            self._api_watchlist()
            return
        if path == "/api/hits":
            self._api_hits()
            return
        self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path == "/login":
            self._login()
            return
        if path == "/logout":
            self._send(
                302,
                b"",
                "text/plain",
                [self._set_cookie_header("", clear=True), ("Location", ".")],
            )
            return
        if not self._authed():
            self._send(*json_bytes({"error": "auth"}, 401))
            return
        if path == "/api/watchlist":
            self._api_watch_add()
            return
        if path == "/api/watchlist/toggle":
            self._api_watch_toggle()
            return
        if path == "/api/watchlist/delete":
            self._api_watch_delete()
            return
        if path == "/api/collector":
            self._api_collector()
            return
        if path == "/api/hits/clear":
            self._api_hits_clear()
            return
        self._send(404, b"not found", "text/plain")

    def _login(self) -> None:
        ip = self.client_address[0]
        ctype = (self.headers.get("Content-Type") or "").lower()
        if "json" in ctype:
            data = self._read_json()
        else:
            data = self._read_form()
        user = (data.get("user") or "").strip()
        password = data.get("pass") or data.get("password") or ""
        ok_user = hmac.compare_digest(user, _cfg.get("AUTH_USER") or "watch")
        if not login_allowed(ip) or not ok_user or not verify_password(password):
            html = LOGIN_HTML.replace(
                "ERR", '<div class="err">ورود نامعتبر است. دوباره تلاش کنید.</div>'
            )
            self._send(401, html.encode("utf-8"), "text/html; charset=utf-8")
            return
        token = make_session()
        self._send(
            302,
            b"",
            "text/plain",
            [self._set_cookie_header(token), ("Location", ".")],
        )

    def _api_watchlist(self) -> None:
        refresh_watch()
        conn = db()
        try:
            rows = conn.execute(
                "SELECT email, label, enabled, aliases FROM watchlist ORDER BY email"
            ).fetchall()
        finally:
            conn.close()
        clients = []
        for row in rows:
            email = str(row["email"]).lower()
            aliases = ",".join(
                k for k in _alias_set(email, row["aliases"] or "", row["label"] or "") if k != email
            )
            clients.append(
                _enrich_client(
                    email,
                    row["label"] or row["email"],
                    bool(row["enabled"]),
                    aliases,
                )
            )
        # attention first so limited/deleted stand out
        clients.sort(key=lambda c: (0 if c.get("attention") else 1, c.get("label") or ""))
        self._send(*json_bytes({"clients": clients}))

    def _api_watch_add(self) -> None:
        data = self._read_json()
        email = (data.get("email") or "").strip().lower()
        label = (data.get("label") or "").strip()[:80]
        if not EMAIL_RE.match(email):
            self._send(*json_bytes({"error": "bad_email"}, 400))
            return
        if not label:
            label = email
        conn = db()
        try:
            conn.execute(
                "INSERT INTO watchlist(email,label,enabled,created,aliases) VALUES(?,?,1,?,?) "
                "ON CONFLICT(email) DO UPDATE SET label=excluded.label",
                (email, label, time.time(), ""),
            )
            mapped = _usermap().get(email) or _usermap().get(label.lower())
            extra = ",".join(
                k for k in _alias_set(email, "", label) if k != email
            )
            if extra:
                conn.execute(
                    "UPDATE watchlist SET aliases=? WHERE email=?",
                    (extra, email),
                )
            elif mapped and mapped != email:
                conn.execute(
                    "UPDATE watchlist SET aliases=? WHERE email=?",
                    (mapped, email),
                )
        finally:
            conn.close()
        refresh_watch()
        self._send(*json_bytes({"ok": True}))

    def _api_watch_toggle(self) -> None:
        data = self._read_json()
        email = (data.get("email") or "").strip().lower()
        enabled = 1 if data.get("enabled") else 0
        conn = db()
        try:
            conn.execute("UPDATE watchlist SET enabled=? WHERE email=?", (enabled, email))
        finally:
            conn.close()
        refresh_watch()
        self._send(*json_bytes({"ok": True}))

    def _api_watch_delete(self) -> None:
        data = self._read_json()
        email = (data.get("email") or "").strip().lower()
        conn = db()
        try:
            conn.execute("DELETE FROM watchlist WHERE email=?", (email,))
        finally:
            conn.close()
        refresh_watch()
        self._send(*json_bytes({"ok": True}))

    def _api_collector(self) -> None:
        data = self._read_json()
        if "paused" in data:
            set_collector_paused(bool(data.get("paused")))
        self._send(*json_bytes({"ok": True, "paused": collector_paused()}))

    def _api_hits_clear(self) -> None:
        n = clear_hits()
        self._send(*json_bytes({"ok": True, "deleted": n}))

    def _api_hits(self) -> None:
        refresh_watch()
        conn = db()
        try:
            rows = conn.execute(
                "SELECT ts, log_ts, email, domain, src, count FROM hits ORDER BY ts DESC LIMIT 400"
            ).fetchall()
            day0 = iran_day_start_ts()
            today = conn.execute(
                "SELECT COUNT(*) FROM hits WHERE ts >= ?", (day0,)
            ).fetchone()[0]
            total = conn.execute("SELECT COUNT(*) FROM hits").fetchone()[0]
        finally:
            conn.close()
        hits = []
        for r in rows:
            email = r["email"]
            meta = _watch.get(email) or next(
                (row for row in _watch_rows if row["email"] == email), {}
            )
            hits.append(
                {
                    "ts": r["ts"],
                    "log_ts": r["log_ts"],
                    "when_h": fmt_when_iran(float(r["ts"])),
                    "email": email,
                    "label": meta.get("label") or email,
                    "domain": r["domain"],
                    "src": r["src"],
                    "count": r["count"],
                }
            )
        watched = sum(1 for row in _watch_rows if row["enabled"])
        self._send(
            *json_bytes(
                {
                    "hits": hits,
                    "stats": {
                        "watched": watched,
                        "today": today,
                        "total": total,
                        "uptime_sec": int(time.time() - _started),
                        "paused": collector_paused(),
                        "retention_days": float(_cfg.get("RETENTION_DAYS") or 2),
                    },
                }
            )
        )


def main() -> None:
    global _cfg, _adult
    _cfg = load_cfg()
    if not _cfg.get("AUTH_HASH") or not _cfg.get("SESSION_SECRET"):
        raise SystemExit("missing AUTH_HASH or SESSION_SECRET in config")
    _adult = _load_domains()
    Path(_cfg["DB_PATH"]).parent.mkdir(parents=True, exist_ok=True)
    db().close()
    if meta_get("collector_paused") == "1":
        _collector_paused.set()
    prune_hits()
    refresh_watch()
    t = threading.Thread(target=follow_log, name="sni-tail", daemon=True)
    t.start()
    listen = _cfg.get("LISTEN") or "127.0.0.1:8787"
    host, _, port_s = listen.rpartition(":")
    httpd = ThreadingHTTPServer((host or "127.0.0.1", int(port_s)), Handler)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
