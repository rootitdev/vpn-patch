#!/usr/bin/env python3
"""Web UI for instagram-multiplier on Exit. Stdlib only. Separate login from PasarGuard."""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import importlib.util
import json
import os
import re
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.machinery import SourceFileLoader
from pathlib import Path
from urllib.parse import parse_qs, urlparse

CFG_PATH = Path(os.environ.get("IG_WEB_CFG", "/etc/ig-mult-web/config.env"))
ENV_FILE = Path("/etc/vpn-monitor/instagram-multiplier.env")
ENV_LOCK = Path("/etc/vpn-monitor/.instagram-multiplier-env.lock")
PBKDF_ITERS = 200_000
LOGIN_WINDOW = 60.0
LOGIN_MAX = 12
DOM_RE = re.compile(
    r"^(geosite|full|domain|keyword|regexp|ext):[A-Za-z0-9._*:/?+-]+$"
)
CLI_CANDIDATES = (
    Path("/root/vpn-infra/scripts/instagram-multiplier"),
    Path("/usr/local/sbin/instagram-multiplier"),
)

_lock = threading.RLock()
_export_lock = threading.Lock()
_cfg: dict[str, str] = {}
_login_hits: dict[str, list[float]] = {}
_cli = None


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
        "LISTEN": "127.0.0.1:8788",
        "AUTH_USER": "ig",
        "COOKIE_NAME": "igmult",
    }
    d.update(_parse_env(CFG_PATH))
    return d


def load_cli():
    global _cli
    if _cli is not None:
        return _cli
    path = next((p for p in CLI_CANDIDATES if p.exists()), None)
    if path is None:
        raise SystemExit("instagram-multiplier CLI not found")
    loader = SourceFileLoader("igmult_cli", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise SystemExit("could not load instagram-multiplier")
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    _cli = mod
    return mod


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
    user = _cfg.get("AUTH_USER") or "ig"
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
    user = _cfg.get("AUTH_USER") or "ig"
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


def cli_err(exc: BaseException) -> str:
    return str(exc).strip() or exc.__class__.__name__


def pack_user(uid: int, info: dict | None, st, mult: float, paused: bool = False) -> dict:
    cli = load_cli()
    ig = st.ig if st else 0
    raw = st.raw if st else 0
    weighted = st.weighted if st else 0
    extra = cli.ig_extra_bytes(ig, mult) if hasattr(cli, "ig_extra_bytes") else max(0, weighted - raw)
    in_panel = bool(info and info.get("username"))
    raw_status = (info or {}).get("status") or ("missing" if not in_panel else "?")
    if not in_panel:
        raw_status = "missing"
    label, css = status_meta(raw_status)
    if paused:
        label = f"{label} · متوقف"
    return {
        "id": uid,
        "username": (info or {}).get("username") or "",
        "status": raw_status,
        "status_label": label,
        "status_class": css,
        "paused": bool(paused),
        "tag": cli.tag_for(uid),
        "ig": ig,
        "ig_h": cli.format_bytes(ig),
        "extra": extra,
        "extra_h": cli.format_bytes(extra),
        "weighted": weighted,
        "weighted_h": cli.format_bytes(weighted),
        "raw": raw,
        "raw_h": cli.format_bytes(raw),
        "in_panel": in_panel,
    }


def status_meta(status: str) -> tuple[str, str]:
    s = (status or "?").strip().lower()
    mapping = {
        "active": ("فعال", "st-active"),
        "limited": ("لیمیت", "st-limited"),
        "disabled": ("خاموش", "st-disabled"),
        "expired": ("منقضی", "st-expired"),
        "on_hold": ("نگهداری", "st-hold"),
        "missing": ("حذف‌شده از پنل", "st-missing"),
    }
    return mapping.get(s, (status or "نامشخص", "st-unknown"))


def today_stats_map(ids: list[int]) -> dict[int, object]:
    cli = load_cli()
    today = datetime.now().strftime("%Y-%m-%d")
    if not ids or not cli.STATS_LOG.exists():
        return {}
    return cli.aggregate_ig_stats(cli.STATS_LOG, ids, dates={today})


def list_payload() -> dict:
    cli = load_cli()
    settings = cli.load_settings()
    ids = cli.current_ids()
    paused = set(cli.read_paused()) if hasattr(cli, "read_paused") else set()
    info = cli.names_by_id(ids) if ids else {}
    agg = today_stats_map(ids)
    users = [
        pack_user(uid, info.get(uid), agg.get(uid), settings.multiplier, uid in paused)
        for uid in ids
    ]
    return {
        "users": users,
        "count": len(users),
        "multiplier": settings.multiplier,
        "today": datetime.now().strftime("%Y-%m-%d"),
        "paused_count": sum(1 for u in users if u["paused"]),
    }


def stats_payload(days: int) -> dict:
    cli = load_cli()
    settings = cli.load_settings()
    # Membership list (includes paused) for display; billing uses settings.user_ids
    ids = cli.current_ids()
    paused = set(cli.read_paused()) if hasattr(cli, "read_paused") else set()
    n = max(1, min(int(days), 90))
    end = datetime.now().date()
    dates = cli.date_span(end, n)
    label = (
        f"امروز ({end.isoformat()})"
        if n == 1
        else f"{n} روز اخیر ({min(dates)} → {max(dates)})"
    )
    agg = {}
    log_ok = cli.STATS_LOG.exists()
    if ids and log_ok:
        agg = cli.aggregate_ig_stats(cli.STATS_LOG, ids, dates=dates)
    info = cli.names_by_id(ids) if ids else {}
    rows = [
        pack_user(uid, info.get(uid), agg.get(uid), settings.multiplier, uid in paused)
        for uid in ids
    ]
    tot = {
        "ig": sum(r["ig"] for r in rows if not r["paused"]),
        "extra": sum(r["extra"] for r in rows if not r["paused"]),
        "weighted": sum(r["weighted"] for r in rows if not r["paused"]),
        "raw": sum(r["raw"] for r in rows if not r["paused"]),
    }
    active = sum(1 for r in rows if r["ig"] and not r["paused"])
    return {
        "days": n,
        "label": label,
        "multiplier": settings.multiplier,
        "log_ok": log_ok,
        "log_path": str(cli.STATS_LOG),
        "users": rows,
        "totals": {
            **tot,
            "ig_h": cli.format_bytes(tot["ig"]),
            "extra_h": cli.format_bytes(tot["extra"]),
            "weighted_h": cli.format_bytes(tot["weighted"]),
            "raw_h": cli.format_bytes(tot["raw"]),
        },
        "active": active,
        "idle": len(rows) - active,
    }


def settings_payload() -> dict:
    cli = load_cli()
    st = cli.load_settings()
    users = cli.USERS_FILE
    return {
        "multiplier": st.multiplier,
        "domains": list(st.domains),
        "domains_text": ",".join(st.domains),
        "user_count": len(st.user_ids),
        "users_file": str(users),
        "env_file": str(ENV_FILE),
        "users_mtime": users.stat().st_mtime if users.exists() else None,
        "env_mtime": ENV_FILE.stat().st_mtime if ENV_FILE.exists() else None,
        "stats_log": str(cli.STATS_LOG),
        "stats_ok": cli.STATS_LOG.exists(),
    }


def parse_domains(raw: str) -> list[str]:
    parts = [x.strip() for x in raw.replace("\n", ",").split(",") if x.strip()]
    if not parts:
        raise ValueError("لیست دامنه خالی است.")
    if len(parts) > 80:
        raise ValueError("بیش از ۸۰ دامنه مجاز نیست.")
    bad = [p for p in parts if not DOM_RE.match(p)]
    if bad:
        raise ValueError("دامنه نامعتبر: " + ", ".join(bad[:5]))
    seen: list[str] = []
    have: set[str] = set()
    for p in parts:
        if p in have:
            continue
        have.add(p)
        seen.append(p)
    return seen


def save_env(multiplier: float, domains: list[str]) -> None:
    ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    fh = open(ENV_LOCK, "a+")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX)
        existing = ENV_FILE.read_text() if ENV_FILE.exists() else ""
        lines = existing.splitlines() if existing else [
            "# Multiplier for selected users: Instagram + pornhub/xnxx/xvideos (+ CDNs)."
        ]
        seen_m = seen_d = False
        out: list[str] = []
        for ln in lines:
            s = ln.strip()
            if s.startswith("INSTAGRAM_MULTIPLIER="):
                out.append(f"INSTAGRAM_MULTIPLIER={multiplier:g}")
                seen_m = True
            elif s.startswith("INSTAGRAM_DOMAINS="):
                out.append("INSTAGRAM_DOMAINS=" + ",".join(domains))
                seen_d = True
            else:
                out.append(ln)
        if not seen_m:
            out.append(f"INSTAGRAM_MULTIPLIER={multiplier:g}")
        if not seen_d:
            out.append("INSTAGRAM_DOMAINS=" + ",".join(domains))
        text = "\n".join(out) + "\n"
        tmp = ENV_FILE.with_suffix(".env.tmp")
        tmp.write_text(text)
        tmp.chmod(0o600)
        tmp.replace(ENV_FILE)
    finally:
        fh.close()


def run_export() -> str:
    cli = load_cli()
    if not _export_lock.acquire(blocking=False):
        raise cli.CliError("یک export دیگر در حال اجراست. کمی صبر کنید.")
    try:
        return cli.export_now() or "export انجام شد."
    finally:
        _export_lock.release()


def resolve_add(q: str) -> dict:
    cli = load_cli()
    name = (q or "").strip()
    if not name:
        raise cli.CliError("نام کاربری را بنویسید.")
    if name.isdigit():
        uid = int(name)
        info = cli.names_by_id([uid])
        if uid not in info:
            raise cli.CliError(f"id={uid} در پنل پیدا نشد.")
        return info[uid]
    return cli.lookup(name)


def resolve_remove(q: str) -> dict:
    cli = load_cli()
    name = (q or "").strip()
    if not name:
        raise cli.CliError("نام کاربری یا id را بنویسید.")
    if name.isdigit():
        uid = int(name)
        info = cli.names_by_id([uid])
        if uid in info:
            return info[uid]
        return {"id": uid, "username": "", "status": "missing"}
    return cli.lookup(name)


LOGIN_HTML = """<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ضریب اینستا</title>
<style>
:root { --bg:#0b1220; --card:#152036; --line:#243656; --txt:#e8eef9; --mut:#8aa0c2; }
* { box-sizing:border-box; }
body { margin:0; min-height:100vh; font-family:Tahoma,Vazirmatn,sans-serif; background:radial-gradient(1200px 500px at 20% -10%, #134e4a 0%, var(--bg) 55%); color:var(--txt); display:flex; align-items:center; justify-content:center; }
form { width:min(420px,92vw); background:var(--card); border:1px solid var(--line); border-radius:18px; padding:28px 24px 22px; box-shadow:0 20px 50px #0007; }
h1 { margin:0 0 6px; font-size:22px; }
p { margin:0 0 18px; color:var(--mut); font-size:13px; line-height:1.7; }
label { display:block; font-size:12px; color:var(--mut); margin:12px 0 6px; }
input { width:100%; padding:11px 12px; border-radius:10px; border:1px solid var(--line); background:#0d1728; color:var(--txt); font-size:15px; }
button { width:100%; margin-top:18px; padding:12px; border:0; border-radius:11px; background:linear-gradient(180deg,#2dd4bf,#0f766e); color:#042f2e; font-weight:800; cursor:pointer; }
.err { background:#3f1d2a; color:#fecdd3; padding:8px 10px; border-radius:8px; margin-bottom:12px; font-size:13px; }
</style>
</head>
<body>
<form method="post" action="login">
<h1>ضریب اینستا</h1>
<p>مدیریت کاربران و ضریب حجم. این صفحه لاگین پنل PasarGuard نیست.</p>
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
<title>ضریب اینستا</title>
<style>
:root { --bg:#0b1220; --card:#121c2f; --line:#243656; --txt:#e8eef9; --mut:#8aa0c2; --acc:#2dd4bf; --ok:#34d399; --side:#0e1728; }
* { box-sizing:border-box; }
body { margin:0; font-family:Tahoma,Vazirmatn,sans-serif; background:var(--bg); color:var(--txt); }
.shell { display:grid; grid-template-columns:240px 1fr; min-height:100vh; }
aside.menu { background:var(--side); border-left:1px solid var(--line); padding:18px 12px; position:sticky; top:0; height:100vh; }
.brand { font-weight:800; padding:8px 12px 16px; font-size:16px; }
.brand span { display:block; color:var(--mut); font-weight:400; font-size:11px; margin-top:4px; }
.mi { display:block; padding:10px 12px; border-radius:10px; color:var(--txt); text-decoration:none; margin-bottom:6px; }
.mi:hover { background:#18263d; }
.mi.active { background:#0f766e; color:#ecfdf5; }
.work { min-width:0; }
header { display:flex; justify-content:space-between; align-items:center; gap:16px; padding:16px 22px; border-bottom:1px solid var(--line); position:sticky; top:0; background:#0b1220ee; backdrop-filter:blur(8px); z-index:2; }
.actions { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
h1 { margin:0; font-size:18px; }
.sub { color:var(--mut); font-size:12px; margin-top:3px; }
.flash { margin:12px 16px 0; padding:10px 14px; border-radius:12px; font-size:13px; display:none; }
.flash.on { display:block; }
.flash.ok { background:#064e3b; color:#a7f3d0; }
.flash.err { background:#3f1d2a; color:#fecdd3; }
.flash.warn { background:#3f2a12; color:#fdba74; }
.pad { padding:16px; display:grid; gap:16px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:16px; padding:16px 18px; }
h2 { margin:0 0 10px; font-size:15px; }
label, .hint { display:block; color:var(--mut); font-size:12px; margin:8px 0 4px; line-height:1.7; }
input, select, textarea { width:100%; padding:9px 10px; border-radius:9px; border:1px solid var(--line); background:#0d1728; color:var(--txt); font-family:inherit; }
textarea { min-height:120px; direction:ltr; text-align:left; font-size:12px; }
.row { display:flex; gap:8px; }
.row > * { flex:1; }
button { border:0; border-radius:9px; padding:9px 12px; cursor:pointer; font-weight:700; font-family:inherit; }
.btn { background:#0f766e; color:#ecfdf5; }
.danger { background:#7f1d1d; color:#fecaca; }
.ghost { background:transparent; color:var(--mut); border:1px solid var(--line); }
.item { display:flex; justify-content:space-between; gap:12px; align-items:flex-start; padding:12px 0; border-bottom:1px solid #1c2a44; }
.item:last-child { border:0; }
.pill { font-size:11px; padding:3px 9px; border-radius:999px; white-space:nowrap; font-weight:700; }
.st-active { background:#064e3b; color:#6ee7b7; }
.st-limited { background:#7c2d12; color:#fdba74; border:1px solid #ea580c; }
.st-disabled { background:#1e293b; color:#94a3b8; }
.st-expired { background:#7f1d1d; color:#fecaca; }
.st-hold { background:#312e81; color:#c7d2fe; }
.st-missing { background:#450a0a; color:#fda4af; border:1px solid #f87171; }
.st-unknown { background:#334155; color:#e2e8f0; }
.st-paused { background:#422006; color:#fde68a; border:1px solid #ca8a04; }
.item.row-limited { background:linear-gradient(90deg, #7c2d1222, transparent); border-radius:10px; padding-right:8px; }
.item.row-missing { background:linear-gradient(90deg, #7f1d1d33, transparent); border-radius:10px; padding-right:8px; opacity:0.92; }
.item.row-paused { opacity:0.72; }
.item .name-missing { color:#fda4af; text-decoration:line-through; }
.warn-btn { background:#92400e; color:#ffedd5; }
.mut { color:var(--mut); }
.empty { color:var(--mut); padding:24px 8px; text-align:center; }
.kpi { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; }
.kpi div { background:#0d1728; border:1px solid var(--line); border-radius:12px; padding:12px; }
.kpi b { display:block; font-size:18px; margin-top:4px; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th, td { border-bottom:1px solid #1c2a44; padding:8px 6px; text-align:right; }
th { color:var(--mut); font-weight:700; }
.num { font-variant-numeric:tabular-nums; white-space:nowrap; }
.docs { padding:20px 28px 48px; max-width:900px; line-height:1.85; }
.docs h1 { font-size:22px; margin-bottom:8px; }
.docs h2 { font-size:17px; margin:28px 0 10px; padding-top:8px; border-top:1px solid var(--line); }
.docs p, .docs li { color:#dbe4f3; font-size:14px; }
.docs ul, .docs ol { padding-right:20px; }
.docs code, .docs pre { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12px; }
.docs code { background:#0d1728; padding:1px 6px; border-radius:6px; }
.docs pre { background:#0d1728; border:1px solid var(--line); border-radius:12px; padding:14px; overflow:auto; direction:ltr; text-align:left; }
.docs table { width:100%; border-collapse:collapse; font-size:13px; margin:10px 0 16px; }
.docs th, .docs td { border:1px solid var(--line); padding:8px 10px; text-align:right; vertical-align:top; }
.callout { background:#042f2e; border:1px solid #134e4a; border-radius:14px; padding:14px 16px; }
@media (max-width:1100px) {
  .shell { grid-template-columns:1fr; }
  aside.menu { height:auto; position:relative; display:flex; flex-wrap:wrap; gap:8px; align-items:center; }
  .kpi { grid-template-columns:1fr 1fr; }
}
</style>
</head>
<body>
<div class="shell">
<aside class="menu">
  <div class="brand">ضریب اینستا<span>حسابداری حجم، نه فیلترشکن جدا</span></div>
  <a class="mi" id="nav-users" href=".">کاربران</a>
  <a class="mi" id="nav-stats" href="stats">آمار</a>
  <a class="mi" id="nav-settings" href="settings">تنظیمات</a>
  <a class="mi" id="nav-docs" href="docs">مستندات</a>
</aside>
<div class="work">
<div id="flash" class="flash"></div>

<div id="page-users">
<header>
  <div>
    <h1>کاربران ضریب</h1>
    <div class="sub" id="users-sub">نام کاربری پنل را اضافه کنید؛ بعد قوانین روی ایران اعمال می‌شود.</div>
  </div>
  <div class="actions">
    <button class="btn" id="export" type="button">اعمال روی ایران</button>
    <form method="post" action="logout"><button class="ghost" type="submit">خروج</button></form>
  </div>
</header>
<div class="pad">
  <section class="card">
    <h2>افزودن</h2>
    <p class="hint">همان نام کاربری PasarGuard. مسیر وی‌پی‌ان عوض نمی‌شود؛ فقط حجم اینستا/سایت‌های لیست‌شده با ضریب جدا شمرده می‌شود.</p>
    <div class="row">
      <input id="username" placeholder="مثلاً RoOtIt" autocomplete="off">
      <button class="btn" id="add" type="button" style="flex:0 0 auto">افزودن و اعمال</button>
    </div>
  </section>
  <section class="card">
    <h2>لیست فعلی</h2>
    <p class="hint" id="today-hint">حجم امروز از لاگ آمار Exit</p>
    <div id="users"></div>
  </section>
</div>
</div>

<div id="page-stats" hidden>
<header>
  <div>
    <h1>آمار ضریب</h1>
    <div class="sub" id="stats-sub">ضریب‌شده = اینستاگرام + دامنه‌های تنظیم‌شده</div>
  </div>
  <div class="actions">
    <select id="days" style="max-width:160px">
      <option value="1">امروز</option>
      <option value="7">۷ روز</option>
      <option value="30">۳۰ روز</option>
    </select>
    <form method="post" action="logout"><button class="ghost" type="submit">خروج</button></form>
  </div>
</header>
<div class="pad">
  <div class="kpi" id="kpi"></div>
  <section class="card"><div id="stats-table"></div></section>
</div>
</div>

<div id="page-settings" hidden>
<header>
  <div>
    <h1>تنظیمات</h1>
    <div class="sub">ضریب فقط روی Exit اعمال می‌شود. تغییر دامنه نیاز به اعمال روی ایران دارد.</div>
  </div>
  <form method="post" action="logout"><button class="ghost" type="submit">خروج</button></form>
</header>
<div class="pad">
  <section class="card">
    <h2>ضریب و دامنه‌ها</h2>
    <label>ضریب حجم (مثلاً 1.5 یا 3)</label>
    <input id="mult" type="number" min="1" max="10" step="0.1">
    <p class="hint">تغییر ضریب از دور بعدی ingest روی used_traffic اثر می‌گذارد؛ export لازم نیست.</p>
    <label>دامنه‌های Xray (با کاما؛ پیشوند geosite/full/domain)</label>
    <textarea id="domains" spellcheck="false"></textarea>
    <p class="hint">همین لیست هم اینستا است هم سایت‌هایی مثل pornhub/xnxx/xvideos اگر در فایل زنده باشند. مسیر اینترنت همان بک‌هال فعلی است.</p>
    <div class="row" style="margin-top:12px">
      <button class="btn" id="save-mult" type="button">ذخیره ضریب</button>
      <button class="btn" id="save-dom" type="button">ذخیره دامنه و اعمال</button>
    </div>
    <p class="hint" id="paths"></p>
  </section>
</div>
</div>

<article class="docs" id="page-docs" hidden>
<header>
  <div>
    <h1>مستندات و ریسک فیلتر</h1>
    <div class="sub">instagram-multiplier — حسابداری حجم روی استک دوهاب</div>
  </div>
  <form method="post" action="logout"><button class="ghost" type="submit">خروج</button></form>
</header>

<div class="callout">
<p><b>ریسک فیلتر شدن اینستاگرام را این اسکریپت زیاد نمی‌کند.</b> مسیر سیم همان بک‌هال فعلی است. outbound اضافه فقط یک کلون از همان خروجی آلمان است؛ پروتکل، پورت یا Reality جدید ساخته نمی‌شود. DPI داخل ایران SNI اینستا را از کلاینت نمی‌بیند چون داخل تونل وی‌لس است. اینستاگرام هم فقط IP خروج را می‌بیند؛ ضریب فقط در پنل شما روی حجم حساب می‌شود. فیلتر اینستا در ایران جدا است و این ابزار آن را دور نمی‌زند و امضای تازه‌ای هم به DPI نمی‌دهد.</p>
</div>

<h2>این ابزار چیست</h2>
<p>ربات اینستاگرام نیست. برای چند کاربر انتخاب‌شده، ترافیک دامنه‌های تنظیم‌شده (اینستاگرام و در پیکربندی فعلی چند CDN بزرگسال) روی هستهٔ ایران به outbound جدا <code>CAT-instagram-u&lt;id&gt;</code> می‌رود. همان بک‌هال کلون می‌شود. روی Exit، ingest حجم آن outbound را با ضریب به <code>used_traffic</code> اضافه می‌کند. بقیهٔ کاربران دست‌نخورده می‌مانند.</p>

<h2>چه چیزی ریسک است و چه چیزی نیست</h2>
<ul>
<li><b>فیلتر ایران / اینستاگرام:</b> اضافه نمی‌شود. کلاینت همان وی‌پی‌ان قبلی را دارد.</li>
<li><b>بن شدن اکانت اینستا:</b> این اسکریپت به اینستاگرام وصل نمی‌شود و لاگین/پست نمی‌سازد.</li>
<li><b>حسابداری:</b> اگر دامنه در لیست نباشد، آن CDN ضریب نمی‌گیرد (کم‌شماری)، نه قطع دسترسی.</li>
<li><b>هستهٔ ایران:</b> هر کاربر یک rule اضافه می‌کند. برای چند نفر ناچیز است؛ برای ده‌ها نفر جدول routing شلوغ‌تر می‌شود.</li>
<li><b>اعمال روی ایران:</b> همان <code>iran-sync-export</code> است. هسته را با قوانین جدید می‌فرستد؛ نود پنل را Enable نکنید.</li>
</ul>

<h2>صفحه وب</h2>
<ul>
<li>آدرس: <code>https://panel.jetengine.ir:2096/ig/</code> — همان TLS پنل، لاگین جدا</li>
<li>سرویس Exit: <code>ig-mult-web</code> روی <code>127.0.0.1:8788</code></li>
<li>کاربران / آمار / تنظیمات همان کار CLI را می‌کنند: <code>add</code> <code>remove</code> <code>list</code> <code>stats</code> به‌علاوه ویرایش ضریب و دامنه</li>
</ul>

<h2>فایل‌های زنده (Exit)</h2>
<table>
<tr><th>مسیر</th><th>نقش</th></tr>
<tr><td><code>/etc/vpn-monitor/instagram-multiplier-users.txt</code></td><td>idهای پنل (mode 600)</td></tr>
<tr><td><code>/etc/vpn-monitor/instagram-multiplier.env</code></td><td>ضریب و دامنه</td></tr>
<tr><td><code>/var/log/vpn-path/stats.log</code></td><td>آمار <code>u&lt;id&gt;_raw / _ig / _w</code></td></tr>
<tr><td><code>/etc/ig-mult-web/config.env</code></td><td>لاگین صفحه</td></tr>
<tr><td><code>/usr/local/sbin/instagram-multiplier</code></td><td>همان CLI</td></tr>
</table>

<h2>CLI</h2>
<pre>instagram-multiplier add &lt;username&gt;
instagram-multiplier remove &lt;username&gt;
instagram-multiplier list
instagram-multiplier stats
instagram-multiplier stats --days 7</pre>
<p>نصب مجدد UI: <code>sudo AUTH_USER=ig AUTH_PASS='...' /root/vpn-infra/scripts/ig-mult-web/install.sh</code></p>
</article>
</div>
</div>
<script>
const $ = (id) => document.getElementById(id);
const segs = location.pathname.replace(/\\/+$/,'').split('/').filter(Boolean);
const leaf = segs[segs.length-1] || '';
const page = (leaf === 'stats' || leaf === 'settings' || leaf === 'docs') ? leaf : 'users';
['users','stats','settings','docs'].forEach(p => {
  const el = $('page-' + p);
  if (el) el.hidden = p !== page;
  const nav = $('nav-' + p);
  if (nav) nav.classList.toggle('active', p === page);
});
document.title = {users:'ضریب اینستا', stats:'آمار ضریب', settings:'تنظیمات ضریب', docs:'مستندات ضریب'}[page];

function esc(s){ return String(s||'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function flash(msg, kind){
  const el = $('flash');
  el.className = 'flash on ' + (kind || 'ok');
  el.textContent = msg || '';
}
function busy(on){
  document.body.style.cursor = on ? 'wait' : '';
}
async function api(path, body){
  const opt = body !== undefined ? {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify(body)} : {};
  const r = await fetch(path, opt);
  if (r.status === 401) { location.reload(); return null; }
  const data = await r.json().catch(() => ({error:'جواب نامعتبر'}));
  if (!r.ok) throw new Error(data.error || ('خطا ' + r.status));
  return data;
}

async function loadUsers(){
  const d = await api('api/users');
  if (!d) return;
  $('users-sub').textContent = d.count + ' کاربر · ضریب ' + d.multiplier + '× · متوقف ' + (d.paused_count||0) + ' · حجم ستون‌ها برای ' + d.today;
  const box = $('users');
  if (!d.users.length){ box.innerHTML = '<div class="empty">لیست خالی است.</div>'; return; }
  box.innerHTML = d.users.map(u => {
    const rowCls = [
      'item',
      u.status === 'limited' ? 'row-limited' : '',
      !u.in_panel ? 'row-missing' : '',
      u.paused ? 'row-paused' : '',
    ].filter(Boolean).join(' ');
    const nameCls = u.in_panel ? '' : 'name-missing';
    const title = u.in_panel ? '' : 'این id در پنل پیدا نشد (حذف یا جابه‌جا شده)';
    const pauseLabel = u.paused ? 'ازسرگیری' : 'توقف';
    const pauseCls = u.paused ? 'btn' : 'warn-btn';
    return `<div class="${rowCls}" title="${esc(title)}">
    <div>
      <b class="${nameCls}">${esc(u.username || ('id ' + u.id))}</b>
      <div class="mut">id=${u.id} · ${esc(u.tag)} · امروز ضریب‌شده ${esc(u.ig_h)} · اضافه ${esc(u.extra_h)}${u.paused?' · ضریب فعلاً اعمال نمی‌شود':''}</div>
    </div>
    <div class="row" style="flex:0 0 auto;align-items:center">
      <span class="pill ${esc(u.status_class)}">${esc(u.status_label)}</span>
      ${u.paused ? '<span class="pill st-paused">متوقف</span>' : ''}
      <button class="${pauseCls}" data-pause="${u.id}" data-paused="${u.paused ? '1' : '0'}">${pauseLabel}</button>
      <button class="danger" data-del="${esc(u.username || String(u.id))}">حذف</button>
    </div>
  </div>`;
  }).join('');
  box.querySelectorAll('button[data-del]').forEach(btn => {
    btn.onclick = () => removeUser(btn.getAttribute('data-del') || '');
  });
  box.querySelectorAll('button[data-pause]').forEach(btn => {
    btn.onclick = () => togglePause(btn.getAttribute('data-pause') || '', btn.getAttribute('data-paused') === '1');
  });
}
async function togglePause(id, isPaused){
  const next = !isPaused;
  const msg = next
    ? 'توقف موقت ضریب برای id=' + id + '؟ از لیست حذف نمی‌شود؛ فقط CAT/ضریب قطع می‌شود.'
    : 'از سرگیری ضریب برای id=' + id + '؟';
  if (!confirm(msg)) return;
  busy(true); flash(next ? 'در حال توقف و اعمال…' : 'در حال ازسرگیری و اعمال…', 'warn');
  try {
    const d = await api('api/users/pause', {id: Number(id), paused: next});
    flash(d.message || 'انجام شد.', 'ok');
    await loadUsers();
  } catch (e) { flash(e.message, 'err'); }
  busy(false);
}
async function addUser(){
  const username = $('username').value.trim();
  if (!username) return;
  busy(true); flash('در حال افزودن و اعمال روی ایران…', 'warn');
  try {
    const d = await api('api/users/add', {username});
    $('username').value = '';
    flash(d.message || 'اضافه شد.', d.changed ? 'ok' : 'warn');
    await loadUsers();
  } catch (e) { flash(e.message, 'err'); }
  busy(false);
}
async function removeUser(username){
  if (!confirm('حذف «' + username + '» از ضریب؟ قوانین ایران هم به‌روز می‌شود.')) return;
  busy(true); flash('در حال حذف و اعمال…', 'warn');
  try {
    const d = await api('api/users/remove', {username});
    flash(d.message || 'حذف شد.', 'ok');
    await loadUsers();
  } catch (e) { flash(e.message, 'err'); }
  busy(false);
}
async function doExport(){
  busy(true); flash('در حال اعمال روی ایران…', 'warn');
  try {
    const d = await api('api/export', {});
    flash(d.message || 'اعمال شد.', 'ok');
  } catch (e) { flash(e.message, 'err'); }
  busy(false);
}

async function loadStats(){
  const days = $('days').value || '1';
  const d = await api('api/stats?days=' + days);
  if (!d) return;
  $('stats-sub').textContent = d.label + ' · ضریب ' + d.multiplier + '×' + (d.log_ok ? '' : ' · لاگ آمار پیدا نشد');
  $('kpi').innerHTML = [
    ['کاربر فعال', d.active + '/' + d.users.length],
    ['ضریب‌شده', d.totals.ig_h],
    ['اضافه ضریب', d.totals.extra_h],
    ['کل شارژ', d.totals.weighted_h],
  ].map(([k,v]) => `<div><span class="mut">${k}</span><b>${esc(v)}</b></div>`).join('');
  if (!d.users.length){ $('stats-table').innerHTML = '<div class="empty">کسی در لیست نیست.</div>'; return; }
    $('stats-table').innerHTML = `<table>
    <thead><tr><th>کاربر</th><th>وضعیت</th><th>ضریب‌شده</th><th>اضافه</th><th>کل شارژ</th><th>کل واقعی</th></tr></thead>
    <tbody>${d.users.map(u => `<tr class="${u.paused?'row-paused':(!u.in_panel?'row-missing':(u.status==='limited'?'row-limited':''))}">
      <td><b class="${u.in_panel?'':'name-missing'}">${esc(u.username || ('id '+u.id))}</b><div class="mut">id=${u.id}${u.paused?' · متوقف':''}</div></td>
      <td><span class="pill ${esc(u.status_class)}">${esc(u.status_label)}</span></td>
      <td class="num">${esc(u.ig_h)}</td>
      <td class="num">${esc(u.extra_h)}</td>
      <td class="num">${esc(u.weighted_h)}</td>
      <td class="num">${esc(u.raw_h)}</td>
    </tr>`).join('')}
    <tr><th>جمع</th><th></th><th class="num">${esc(d.totals.ig_h)}</th><th class="num">${esc(d.totals.extra_h)}</th><th class="num">${esc(d.totals.weighted_h)}</th><th class="num">${esc(d.totals.raw_h)}</th></tr>
    </tbody></table>
    <p class="hint">ضریب‌شده = اینستا + دامنه‌های لیست. اضافه ≈ ضریب‌شده × (ضریب−۱). کل واقعی بدون ضریب است. کاربران متوقف در جمع ضریب حساب نمی‌شوند.</p>`;
}

async function loadSettings(){
  const d = await api('api/settings');
  if (!d) return;
  $('mult').value = d.multiplier;
  $('domains').value = d.domains.join('\\n');
  $('paths').textContent = 'فایل زنده: ' + d.env_file + ' · کاربران: ' + d.user_count + ' نفر';
}
async function saveSettings(kind){
  const multiplier = parseFloat($('mult').value);
  const domains = $('domains').value;
  busy(true);
  flash(kind === 'domains' ? 'ذخیره دامنه و اعمال روی ایران…' : 'ذخیره ضریب…', 'warn');
  try {
    const d = await api('api/settings', {multiplier, domains, apply_domains: kind === 'domains'});
    flash(d.message || 'ذخیره شد.', 'ok');
    await loadSettings();
  } catch (e) { flash(e.message, 'err'); }
  busy(false);
}

if (page === 'users') {
  $('add').onclick = addUser;
  $('username').addEventListener('keydown', e => { if (e.key === 'Enter') addUser(); });
  $('export').onclick = doExport;
  loadUsers();
} else if (page === 'stats') {
  $('days').onchange = loadStats;
  loadStats();
} else if (page === 'settings') {
  $('save-mult').onclick = () => saveSettings('mult');
  $('save-dom').onclick = () => saveSettings('domains');
  loadSettings();
}
</script>
</body>
</html>
"""


PAGES = {"/", "/index.html", "/docs", "/stats", "/settings"}


class Handler(BaseHTTPRequestHandler):
    server_version = "ig-mult-web/1"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return

    def _cookie(self) -> str:
        raw = self.headers.get("Cookie") or ""
        name = _cfg.get("COOKIE_NAME") or "igmult"
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    def _authed(self) -> bool:
        return valid_session(self._cookie())

    def _secure(self) -> bool:
        return (self.headers.get("X-Forwarded-Proto") or "").lower() == "https"

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
        if n > 200_000:
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
        name = _cfg.get("COOKIE_NAME") or "igmult"
        flags = "HttpOnly; SameSite=Strict; Path=/"
        if self._secure():
            flags += "; Secure"
        if clear:
            return "Set-Cookie", f"{name}=; Max-Age=0; {flags}"
        return "Set-Cookie", f"{name}={token}; Max-Age={7 * 24 * 3600}; {flags}"

    def _ok(self, obj: dict, code: int = 200) -> None:
        self._send(*json_bytes(obj, code))

    def _fail(self, msg: str, code: int = 400) -> None:
        self._send(*json_bytes({"error": msg}, code))

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path in PAGES:
            if not self._authed():
                self._send(200, LOGIN_HTML.replace("ERR", "").encode("utf-8"), "text/html; charset=utf-8")
                return
            self._send(200, APP_HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if not self._authed():
            self._send(*json_bytes({"error": "auth"}, 401))
            return
        q = parse_qs(parsed.query)
        if path == "/api/users":
            try:
                self._ok(list_payload())
            except Exception as e:  # noqa: BLE001
                self._fail(cli_err(e), 500)
            return
        if path == "/api/stats":
            try:
                days = int((q.get("days") or ["1"])[0] or "1")
            except ValueError:
                days = 1
            try:
                self._ok(stats_payload(days))
            except Exception as e:  # noqa: BLE001
                self._fail(cli_err(e), 500)
            return
        if path == "/api/settings":
            try:
                self._ok(settings_payload())
            except Exception as e:  # noqa: BLE001
                self._fail(cli_err(e), 500)
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
        if path == "/api/users/add":
            self._add()
            return
        if path == "/api/users/remove":
            self._remove()
            return
        if path == "/api/users/pause":
            self._pause()
            return
        if path == "/api/export":
            self._export()
            return
        if path == "/api/settings":
            self._save_settings()
            return
        self._send(404, b"not found", "text/plain")

    def _login(self) -> None:
        ip = self.client_address[0]
        ctype = (self.headers.get("Content-Type") or "").lower()
        data = self._read_json() if "json" in ctype else self._read_form()
        user = (data.get("user") or "").strip()
        password = data.get("pass") or data.get("password") or ""
        ok_user = hmac.compare_digest(user, _cfg.get("AUTH_USER") or "ig")
        if not login_allowed(ip) or not ok_user or not verify_password(password):
            html = LOGIN_HTML.replace(
                "ERR", '<div class="err">ورود نامعتبر است. دوباره تلاش کنید.</div>'
            )
            self._send(401, html.encode("utf-8"), "text/html; charset=utf-8")
            return
        self._send(
            302,
            b"",
            "text/plain",
            [self._set_cookie_header(make_session()), ("Location", ".")],
        )

    def _add(self) -> None:
        cli = load_cli()
        data = self._read_json()
        try:
            u = resolve_add(str(data.get("username") or data.get("user") or ""))
            uid = int(u["id"])
            changed = cli.add_id(uid, u["username"])
            if not changed:
                self._ok(
                    {
                        "ok": True,
                        "changed": False,
                        "message": f"«{u['username']}» از قبل در لیست است (id={uid}).",
                    }
                )
                return
            last = run_export()
            self._ok(
                {
                    "ok": True,
                    "changed": True,
                    "message": f"اضافه شد: {u['username']} (id={uid}). {last}",
                }
            )
        except cli.CliError as e:
            self._fail(str(e), 400)
        except Exception as e:  # noqa: BLE001
            self._fail(cli_err(e), 500)

    def _remove(self) -> None:
        cli = load_cli()
        data = self._read_json()
        try:
            u = resolve_remove(str(data.get("username") or data.get("id") or ""))
            uid = int(u["id"])
            name = u.get("username") or str(uid)
            if not cli.remove_id(uid):
                self._ok(
                    {
                        "ok": True,
                        "changed": False,
                        "message": f"«{name}» در لیست ضریب نبود (id={uid}).",
                    }
                )
                return
            last = run_export()
            self._ok(
                {
                    "ok": True,
                    "changed": True,
                    "message": f"حذف شد: {name} (id={uid}). {last}",
                }
            )
        except cli.CliError as e:
            self._fail(str(e), 400)
        except Exception as e:  # noqa: BLE001
            self._fail(cli_err(e), 500)

    def _pause(self) -> None:
        cli = load_cli()
        data = self._read_json()
        try:
            uid = int(data.get("id") or data.get("user_id") or 0)
            paused = bool(data.get("paused"))
            if uid < 1:
                self._fail("id نامعتبر است.")
                return
            info = cli.names_by_id([uid]).get(uid) or {}
            name = info.get("username") or str(uid)
            if not cli.set_paused(uid, paused):
                self._ok(
                    {
                        "ok": True,
                        "changed": False,
                        "message": f"«{name}» از قبل {'متوقف' if paused else 'فعال'} بود.",
                    }
                )
                return
            last = run_export()
            verb = "متوقف شد" if paused else "از سر گرفته شد"
            self._ok(
                {
                    "ok": True,
                    "changed": True,
                    "message": f"{verb}: {name} (id={uid}). {last}",
                }
            )
        except cli.CliError as e:
            self._fail(str(e), 400)
        except Exception as e:  # noqa: BLE001
            self._fail(cli_err(e), 500)

    def _export(self) -> None:
        cli = load_cli()
        try:
            last = run_export()
            self._ok({"ok": True, "message": last})
        except cli.CliError as e:
            self._fail(str(e), 500)
        except Exception as e:  # noqa: BLE001
            self._fail(cli_err(e), 500)

    def _save_settings(self) -> None:
        cli = load_cli()
        data = self._read_json()
        try:
            cur = cli.load_settings()
            if "multiplier" in data and data["multiplier"] not in (None, ""):
                mult = float(data["multiplier"])
            else:
                mult = cur.multiplier
            if mult < 1.0 or mult > 10.0:
                self._fail("ضریب باید بین ۱ و ۱۰ باشد.")
                return
            if "domains" in data and data["domains"] not in (None, ""):
                domains = parse_domains(str(data["domains"]))
            else:
                domains = list(cur.domains)
            save_env(mult, domains)
            apply_dom = bool(data.get("apply_domains"))
            msg = f"ذخیره شد. ضریب {mult:g}×، {len(domains)} دامنه."
            if apply_dom:
                last = run_export()
                msg += " " + last
            else:
                msg += " ضریب از دور بعدی آمار اعمال می‌شود."
            self._ok({"ok": True, "message": msg, **settings_payload()})
        except ValueError as e:
            self._fail(str(e), 400)
        except cli.CliError as e:
            self._fail(str(e), 400)
        except Exception as e:  # noqa: BLE001
            self._fail(cli_err(e), 500)


def main() -> None:
    global _cfg
    _cfg = load_cfg()
    if not _cfg.get("AUTH_HASH") or not _cfg.get("SESSION_SECRET"):
        raise SystemExit("missing AUTH_HASH or SESSION_SECRET in config")
    load_cli()
    listen = _cfg.get("LISTEN") or "127.0.0.1:8788"
    host, _, port_s = listen.rpartition(":")
    httpd = ThreadingHTTPServer((host or "127.0.0.1", int(port_s)), Handler)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
