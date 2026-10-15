#!/usr/bin/env python3
"""Web UI for vpn-path (Iran backhaul selector) on Exit. Stdlib only. Separate login from PasarGuard."""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import statistics
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

SCRIPTS = Path(os.environ.get("VPN_SCRIPTS", "/root/vpn-infra/scripts"))
sys.path.insert(0, str(SCRIPTS))

import vpn_failover  # noqa: E402
from vpn_path_lib import (  # noqa: E402
    append_history,
    get_core,
    load_env,
    publish,
    put_selector,
    read_history,
    read_mode,
    write_mode,
)
from vpn_paths import FAIL_STREAK, FAILBACK_STREAK, MAP, PRIORITY, WATCH_ONLY  # noqa: E402

CFG_PATH = Path(os.environ.get("PATH_WEB_CFG", "/etc/path-web/config.env"))
MANUAL_LOG = Path("/var/log/vpn-path/manual.log")
LOGIN_WINDOW = 60.0
LOGIN_MAX = 12
LOCK_WAIT_SEC = 90

PATH_INFO = {
    "TO-AMS-DIRECT": ("Direct (TLS 9443)", "مستقیم به IP آلمان. کمترین تأخیر؛ شناسایی‌پذیرتر از CDN."),
    "TO-AMS-XHTTP": ("XHTTP grey", "XHTTP روی xhttp.jahanynegar.ir (DNS خاکستری به Exit)."),
    "TO-AMS-GCORE": ("Gcore CDN", "XHTTP از لبهٔ Gcore (standby.pantherpart.com) → Exit. اگر 503/SSL بود هنوز روی لبه فعال نشده."),
    "TO-AMS-BUNNY": ("Bunny CDN", "XHTTP از لبهٔ Bunny (bunny.classword.ir) → Exit. CDN آمادهٔ failover."),
    "TO-AMS-CF": ("CDN grey (ex-CF)", "XHTTP روی cdn.jetengine.ir (خاکستری). برچسب تاریخی CF."),
    "TO-AMS-CFORANGE": (
        "CF orange (canary)",
        "فقط مانیتور: cf-test.jetengine.ir نارنجی. در auto سوییچ نمی‌شود؛ اگر چند روز سالم بود برمی‌گردانیمش.",
    ),
}
TAG_KEY = {v[0]: k for k, v in MAP.items() if k != "auto"}

_cfg: dict[str, str] = {}
_login_hits: dict[str, list[float]] = {}
_op_lock = threading.Lock()


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
        "LISTEN": "127.0.0.1:8790",
        "AUTH_USER": "path",
        "COOKIE_NAME": "vpnpath",
    }
    d.update(_parse_env(CFG_PATH))
    return d


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
    user = _cfg.get("AUTH_USER") or "path"
    msg = f"{exp}:{user}".encode()
    sig = hmac.new((_cfg.get("SESSION_SECRET") or "").encode(), msg, hashlib.sha256).hexdigest()
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
    user = _cfg.get("AUTH_USER") or "path"
    msg = f"{exp}:{user}".encode()
    expect = hmac.new((_cfg.get("SESSION_SECRET") or "").encode(), msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expect)


def login_allowed(ip: str) -> bool:
    now = time.time()
    hits = [t for t in _login_hits.get(ip, []) if now - t < LOGIN_WINDOW]
    if len(hits) >= LOGIN_MAX:
        _login_hits[ip] = hits
        return False
    hits.append(now)
    _login_hits[ip] = hits
    return True


def json_bytes(obj: object, code: int = 200) -> tuple[int, bytes, str]:
    return code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8"


def err_text(exc: BaseException) -> str:
    return str(exc).strip() or exc.__class__.__name__


class failover_lock:
    """Hold the same flock as vpn_failover.py so a timer run cannot race a manual switch."""

    def __enter__(self):
        vpn_failover.LOCK.parent.mkdir(parents=True, exist_ok=True)
        self.fh = vpn_failover.LOCK.open("w")
        deadline = time.time() + LOCK_WAIT_SEC
        while True:
            try:
                fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.time() > deadline:
                    self.fh.close()
                    raise RuntimeError("تایمر failover مشغول است؛ چند ثانیه بعد دوباره امتحان کنید.")
                time.sleep(0.5)

    def __exit__(self, *exc):
        fcntl.flock(self.fh, fcntl.LOCK_UN)
        self.fh.close()
        return False


def tail_lines(path: Path, n: int) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()[-n:]
    except OSError:
        return []


def path_stats(history: list[dict], tag: str) -> dict:
    oks = [r["p"][tag][1] for r in history if tag in (r.get("p") or {}) and r["p"][tag][0]]
    total = sum(1 for r in history if tag in (r.get("p") or {}))
    fails = total - len(oks)
    out = {"samples": total, "fail_pct": round(100 * fails / total, 1) if total else 0}
    if oks:
        out["avg"] = round(statistics.mean(oks))
        out["min"] = min(oks)
        out["max"] = max(oks)
        out["jitter"] = round(statistics.pstdev(oks)) if len(oks) > 1 else 0
    return out


def status_payload() -> dict:
    env = load_env()
    b = get_core(env)["config"]["routing"]["balancers"][0]
    selector = list(b.get("selector") or [])
    mode = read_mode()
    try:
        health = json.loads(vpn_failover.HEALTH_CACHE.read_text())
    except (OSError, ValueError):
        health = {}
    try:
        fstate = json.loads(vpn_failover.STATE.read_text())
    except (OSError, ValueError):
        fstate = {}
    history = read_history(240)
    hpaths = health.get("paths") or {}
    paths = []
    for tag in list(PRIORITY) + list(WATCH_ONLY):
        title, desc = PATH_INFO.get(tag, (tag, ""))
        h = hpaths.get(tag) or {}
        item = {
            "tag": tag,
            "key": TAG_KEY.get(tag, ""),
            "title": title,
            "desc": desc,
            "ok": bool(h.get("ok")),
            "ms": h.get("ms"),
            "err": (h.get("err") or "")[:120],
            "live": selector == [tag],
            "watch_only": tag in WATCH_ONLY,
            "stats": path_stats(history, tag),
            "spark": [
                [r["p"][tag][0], r["p"][tag][1]] for r in history[-120:] if tag in (r.get("p") or {})
            ],
            "fail_streak": int((fstate.get("fail") or {}).get(tag) or 0),
        }
        if tag in WATCH_ONLY:
            item["edge"] = bool(h.get("edge")) if "edge" in h else None
            item["tunnel"] = bool(h.get("tunnel")) if "tunnel" in h else None
        paths.append(item)
    logs = sorted(
        tail_lines(vpn_failover.LOG, 40) + tail_lines(MANUAL_LOG, 20),
        key=lambda s: s[:20],
    )[-40:]
    ts = int(health.get("ts") or 0)
    return {
        "selector": selector,
        "fallback": b.get("fallbackTag"),
        "mode": mode,
        "inbound_ok": health.get("inbound_ok"),
        "inbound": health.get("inbound") or {},
        "health_ts": ts,
        "health_age": int(time.time()) - ts if ts else None,
        "history_span_min": round((history[-1]["ts"] - history[0]["ts"]) / 60) if len(history) > 1 else 0,
        "paths": paths,
        "logs": list(reversed(logs)),
        "fail_streak_limit": FAIL_STREAK,
        "failback_streak": FAILBACK_STREAK,
    }


def apply_choice(key: str, failover: bool) -> str:
    if key not in MAP:
        raise ValueError("مسیر نامعتبر است.")
    selector = MAP[key]
    with _op_lock, failover_lock():
        env = load_env()
        if key == "auto":
            write_mode("auto", by="web")
        else:
            write_mode("manual", selector[0], failover, by="web")
        put_selector(env, get_core(env), selector)
        MANUAL_LOG.parent.mkdir(parents=True, exist_ok=True)
        with MANUAL_LOG.open("a") as f:
            f.write(
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                + f" web {key} selector={','.join(selector)} failover={'on' if failover else 'off'}\n"
            )
        publish()
    if key == "auto":
        return "حالت خودکار فعال شد. تایمر failover تا چند ثانیه دیگر سالم‌ترین مسیر را بر اساس اولویت انتخاب می‌کند."
    title = PATH_INFO.get(selector[0], (selector[0],))[0]
    tail = "اگر قطع شود خودکار جابه‌جا می‌شود." if failover else "حتی اگر قطع شود عوض نمی‌شود."
    return f"مسیر روی {title} قفل شد و به ایران ارسال شد. {tail}"


def run_test() -> dict:
    with _op_lock, failover_lock():
        h = vpn_failover.fetch_health()
        vpn_failover.HEALTH_CACHE.write_text(json.dumps(h) + "\n")
        try:
            append_history(h)
        except OSError:
            pass
    return h


LOGIN_HTML = """<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>مسیر بک‌هال</title>
<style>
:root { --bg:#0b1220; --card:#152036; --line:#243656; --txt:#e8eef9; --mut:#8aa0c2; }
* { box-sizing:border-box; }
body { margin:0; min-height:100vh; font-family:Tahoma,Vazirmatn,sans-serif; background:radial-gradient(1200px 500px at 20% -10%, #1e3a8a 0%, var(--bg) 55%); color:var(--txt); display:flex; align-items:center; justify-content:center; }
form { width:min(420px,92vw); background:var(--card); border:1px solid var(--line); border-radius:18px; padding:28px 24px 22px; box-shadow:0 20px 50px #0007; }
h1 { margin:0 0 6px; font-size:22px; }
p { margin:0 0 18px; color:var(--mut); font-size:13px; line-height:1.7; }
label { display:block; font-size:12px; color:var(--mut); margin:12px 0 6px; }
input { width:100%; padding:11px 12px; border-radius:10px; border:1px solid var(--line); background:#0d1728; color:var(--txt); font-size:15px; }
button { width:100%; margin-top:18px; padding:12px; border:0; border-radius:11px; background:linear-gradient(180deg,#60a5fa,#1d4ed8); color:#eff6ff; font-weight:800; cursor:pointer; }
.err { background:#3f1d2a; color:#fecdd3; padding:8px 10px; border-radius:8px; margin-bottom:12px; font-size:13px; }
</style>
</head>
<body>
<form method="post" action="login">
<h1>مسیر بک‌هال</h1>
<p>انتخاب مسیر ایران → آلمان (vpn-path). این صفحه لاگین پنل PasarGuard نیست.</p>
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
<title>مسیر بک‌هال</title>
<style>
:root { --bg:#0b1220; --card:#121c2f; --line:#243656; --txt:#e8eef9; --mut:#8aa0c2; --acc:#60a5fa; }
* { box-sizing:border-box; }
body { margin:0; font-family:Tahoma,Vazirmatn,sans-serif; background:var(--bg); color:var(--txt); }
header { display:flex; justify-content:space-between; align-items:center; gap:16px; padding:16px 22px; border-bottom:1px solid var(--line); position:sticky; top:0; background:#0b1220ee; backdrop-filter:blur(8px); z-index:2; flex-wrap:wrap; }
h1 { margin:0; font-size:18px; }
.sub { color:var(--mut); font-size:12px; margin-top:3px; }
.actions { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
button { border:0; border-radius:9px; padding:9px 12px; cursor:pointer; font-weight:700; font-family:inherit; }
button:disabled { opacity:.5; cursor:wait; }
.btn { background:#1d4ed8; color:#eff6ff; }
.ok-btn { background:#0f766e; color:#ecfdf5; }
.ghost { background:transparent; color:var(--mut); border:1px solid var(--line); }
.flash { margin:12px 16px 0; padding:10px 14px; border-radius:12px; font-size:13px; display:none; }
.flash.on { display:block; }
.flash.ok { background:#064e3b; color:#a7f3d0; }
.flash.err { background:#3f1d2a; color:#fecdd3; }
.pad { padding:16px; display:grid; gap:16px; max-width:1200px; margin:0 auto; }
.card { background:var(--card); border:1px solid var(--line); border-radius:16px; padding:16px 18px; }
h2 { margin:0 0 10px; font-size:15px; }
.top { display:grid; grid-template-columns:2fr 1fr 1fr; gap:12px; }
.top div.box { background:#0d1728; border:1px solid var(--line); border-radius:12px; padding:12px 14px; }
.top b { display:block; font-size:19px; margin-top:6px; }
.mut { color:var(--mut); font-size:12px; line-height:1.8; }
.grid { display:grid; grid-template-columns:repeat(2,1fr); gap:14px; }
.path { background:#0d1728; border:1px solid var(--line); border-radius:14px; padding:14px; display:flex; flex-direction:column; gap:8px; }
.path.live { border-color:#3b82f6; box-shadow:0 0 0 1px #3b82f6 inset; }
.path .hd { display:flex; justify-content:space-between; align-items:center; gap:8px; }
.path .t { font-weight:800; font-size:15px; }
.pill { font-size:11px; padding:3px 9px; border-radius:999px; white-space:nowrap; font-weight:700; }
.p-ok { background:#064e3b; color:#6ee7b7; }
.p-fail { background:#7f1d1d; color:#fecaca; }
.p-live { background:#1e3a8a; color:#bfdbfe; }
.p-man { background:#422006; color:#fde68a; border:1px solid #ca8a04; }
.p-auto { background:#064e3b; color:#6ee7b7; }
.nums { display:grid; grid-template-columns:repeat(4,1fr); gap:6px; font-size:12px; }
.nums div { background:#0b1424; border-radius:8px; padding:6px 8px; }
.nums b { display:block; font-size:14px; font-variant-numeric:tabular-nums; }
svg.spark { width:100%; height:46px; background:#0b1424; border-radius:8px; }
.err-t { color:#fca5a5; font-size:11px; direction:ltr; text-align:left; word-break:break-all; }
.logs { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12px; direction:ltr; text-align:left; max-height:320px; overflow:auto; background:#0d1728; border-radius:10px; padding:10px; line-height:1.7; white-space:pre-wrap; }
.logs .sw { color:#93c5fd; } .logs .fl { color:#fca5a5; } .logs .al { color:#fdba74; }
label.chk { display:flex; gap:8px; align-items:center; font-size:13px; color:var(--txt); cursor:pointer; }
.docs p, .docs li { color:#dbe4f3; font-size:13px; line-height:1.9; }
.docs code { background:#0d1728; padding:1px 6px; border-radius:6px; font-size:12px; }
@media (max-width:900px) { .top, .grid { grid-template-columns:1fr; } .nums { grid-template-columns:1fr 1fr; } }
</style>
</head>
<body>
<header>
  <div>
    <h1>مسیر بک‌هال ایران → آلمان</h1>
    <div class="sub" id="sub">در حال بارگذاری…</div>
  </div>
  <div class="actions">
    <button class="ok-btn" id="btnAuto" onclick="choose('auto')">حالت خودکار</button>
    <button class="btn" id="btnTest" onclick="testNow()">تست الان</button>
    <button class="ghost" onclick="load()">تازه‌سازی</button>
    <form method="post" action="logout" style="margin:0"><button class="ghost" type="submit">خروج</button></form>
  </div>
</header>
<div class="flash" id="flash"></div>
<div class="pad">
  <div class="card">
    <div class="top">
      <div class="box"><span class="mut">مسیر زنده</span><b id="live">—</b><div class="mut" id="liveDesc"></div></div>
      <div class="box"><span class="mut">حالت</span><b id="mode">—</b><div class="mut" id="modeDesc"></div></div>
      <div class="box"><span class="mut">ورودی ایران (443 / 2053)</span><b id="inb">—</b><div class="mut" id="age"></div></div>
    </div>
    <div style="margin-top:12px">
      <label class="chk"><input type="checkbox" id="fo" checked> در حالت دستی، اگر مسیر قفل‌شده قطع شد خودکار به مسیر سالم برود (و به حالت خودکار برگردد)</label>
    </div>
  </div>

  <div class="card">
    <h2>مسیرها</h2>
    <div class="mut" id="span" style="margin-bottom:10px"></div>
    <div class="grid" id="paths"></div>
  </div>

  <div class="card">
    <h2>رویدادهای اخیر</h2>
    <div class="logs" id="logs"></div>
  </div>

  <div class="card docs">
    <h2>راهنما</h2>
    <ul>
      <li><b>حالت خودکار:</b> تایمر failover هر ~۱۵ ثانیه پروب می‌گیرد. اگر مسیر فعلی <span id="fs">۳</span> بار پشت‌سرهم خطا بدهد، به مسیر سالم بعدی می‌رود؛ و اگر مسیر با اولویت بالاتر <span id="fb">۵</span> بار سالم باشد، برمی‌گردد (اولویت: Direct ← XHTTP ← Gcore ← Bunny ← CF-grey).</li>
      <li><b>حالت دستی (قفل):</b> با دکمهٔ «انتخاب» روی هر کارت، مسیر قفل می‌شود و دیگر به CF برنمی‌گردد.</li>
      <li><b>میانگین / نوسان:</b> از تاریخچهٔ پروب‌های اخیر حساب می‌شود. نوسان بالا (jitter) یعنی پینگ موجی؛ همان چیزی که اینستاگرام را گیر می‌اندازد.</li>
      <li>پینگ این صفحه زمان یک درخواست HTTPS کامل از ایران از طریق همان مسیر است، نه ICMP؛ برای مقایسهٔ مسیرها با هم معتبر است.</li>
      <li>CLI معادل: <code>vpn-path direct</code> / <code>vpn-path direct --no-failover</code> / <code>vpn-path auto</code></li>
    </ul>
  </div>
</div>
<script>
let busy = false;
function fa(n) { return (n === null || n === undefined || n === '') ? '—' : Number(n).toLocaleString('fa-IR'); }
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function flash(msg, kind) {
  const el = document.getElementById('flash');
  el.className = 'flash on ' + (kind || 'ok');
  el.textContent = msg;
  clearTimeout(flash.t);
  flash.t = setTimeout(() => { el.className = 'flash'; }, 9000);
}
async function api(path, body) {
  const opt = body === undefined ? {} : { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) };
  const r = await fetch(path, opt);
  if (r.status === 401) { location.reload(); throw new Error('auth'); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
  return j;
}
function spark(points) {
  if (!points.length) return '<svg class="spark"></svg>';
  const w = 300, h = 46, n = points.length;
  const vals = points.filter(p => p[0]).map(p => p[1]);
  const max = Math.max(200, ...vals) * 1.1;
  const x = i => (n === 1 ? w / 2 : (i * w) / (n - 1));
  const y = v => h - 3 - (v / max) * (h - 6);
  let d = '', dots = '';
  points.forEach((p, i) => {
    if (p[0]) { d += (d && points[i - 1] && points[i - 1][0] ? 'L' : 'M') + x(i).toFixed(1) + ' ' + y(p[1]).toFixed(1) + ' '; }
    else { dots += '<rect x="' + (x(i) - 1).toFixed(1) + '" y="0" width="2" height="' + h + '" fill="#ef4444" opacity=".55"/>'; }
  });
  return '<svg class="spark" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none">' + dots +
    '<path d="' + d + '" fill="none" stroke="#60a5fa" stroke-width="1.6" vector-effect="non-scaling-stroke"/></svg>';
}
function render(s) {
  const m = s.mode || {};
  const live = (s.paths || []).find(p => p.live);
  document.getElementById('live').textContent = live ? live.title : (s.selector || []).join(' , ') || '—';
  document.getElementById('liveDesc').textContent = live ? live.desc : 'چند مسیر در selector؛ تایمر یکی را پین می‌کند.';
  const modeEl = document.getElementById('mode');
  if (m.mode === 'manual') {
    modeEl.innerHTML = '<span class="pill p-man">دستی (قفل)</span>';
    document.getElementById('modeDesc').textContent = 'failover در قطعی: ' + (m.failover ? 'روشن' : 'خاموش') + (m.by ? ' · توسط ' + m.by : '');
    document.getElementById('fo').checked = !!m.failover;
  } else {
    modeEl.innerHTML = '<span class="pill p-auto">خودکار</span>';
    document.getElementById('modeDesc').textContent = m.note ? ('آخرین تغییر: ' + m.note) : 'تایمر failover مسیر را انتخاب می‌کند.';
  }
  const inb = s.inbound || {};
  document.getElementById('inb').innerHTML = s.inbound_ok
    ? '<span class="pill p-ok">سالم</span>'
    : '<span class="pill p-fail">مشکل</span>';
  document.getElementById('age').textContent =
    'پروب ' + (s.health_age == null ? '—' : fa(s.health_age) + ' ثانیه پیش') +
    (inb.tcp443 ? ' · 443: ' + fa(inb.tcp443.ms) + 'ms' : '');
  document.getElementById('span').textContent =
    'آمار از ' + fa((s.paths[0] || {}).stats ? (s.paths[0].stats.samples) : 0) + ' پروب اخیر (~' + fa(s.history_span_min) + ' دقیقه). خط آبی = پینگ؛ نوار قرمز = خطا.';
  document.getElementById('fs').textContent = fa(s.fail_streak_limit);
  document.getElementById('fb').textContent = fa(s.failback_streak);
  document.getElementById('paths').innerHTML = (s.paths || []).map(p => {
    const st = p.stats || {};
    let pills = (p.live ? '<span class="pill p-live">زنده</span> ' : '') +
      (p.ok ? '<span class="pill p-ok">سالم</span>' : '<span class="pill p-fail">خطا</span>');
    if (p.watch_only) {
      pills = '<span class="pill p-man">canary</span> ' + pills;
      if (p.edge != null) pills += p.edge ? ' <span class="pill p-ok">edge</span>' : ' <span class="pill p-fail">edge</span>';
      if (p.tunnel != null) pills += p.tunnel ? ' <span class="pill p-ok">تونل</span>' : ' <span class="pill p-fail">تونل</span>';
    }
    return '<div class="path' + (p.live ? ' live' : '') + '">' +
      '<div class="hd"><span class="t">' + esc(p.title) + '</span><span>' + pills + '</span></div>' +
      '<div class="mut">' + esc(p.desc) + '</div>' +
      '<div class="nums">' +
        '<div>الان<b>' + fa(p.ms) + '</b></div>' +
        '<div>میانگین<b>' + fa(st.avg) + '</b></div>' +
        '<div>نوسان ±<b>' + fa(st.jitter) + '</b></div>' +
        '<div>خطا٪<b>' + fa(st.fail_pct) + '</b></div>' +
      '</div>' +
      spark(p.spark || []) +
      (p.ok || !p.err ? '' : '<div class="err-t">' + esc(p.err) + '</div>') +
      '<button class="' + (p.live && m.mode === 'manual' ? 'ghost' : 'btn') + '" onclick="choose(\\'' + p.key + '\\')">' +
        (p.live && m.mode === 'manual' ? 'قفل روی همین مسیر است' : 'انتخاب و قفل روی این مسیر') + '</button>' +
    '</div>';
  }).join('');
  document.getElementById('logs').innerHTML = (s.logs || []).map(l => {
    const c = /SWITCH|web |manual /.test(l) ? 'sw' : /ALERT/.test(l) ? 'al' : /FAIL/.test(l) ? 'fl' : '';
    return '<div class="' + c + '">' + esc(l) + '</div>';
  }).join('') || '<span class="mut">رویدادی نیست.</span>';
  document.getElementById('sub').textContent = 'selector: ' + (s.selector || []).join(', ') + ' · fallback: ' + (s.fallback || '—');
}
function setBusy(b) {
  busy = b;
  document.querySelectorAll('button').forEach(x => { if (x.type !== 'submit') x.disabled = b; });
}
async function load() {
  if (busy) return;
  try { render(await api('api/status')); } catch (e) { if (e.message !== 'auth') flash(e.message, 'err'); }
}
async function choose(key) {
  const fo = document.getElementById('fo').checked;
  const label = key === 'auto' ? 'حالت خودکار' : key;
  if (!confirm('تغییر مسیر به «' + label + '»؟ کاربران چند ثانیه ممکن است قطعی کوتاه ببینند.')) return;
  setBusy(true);
  flash('در حال اعمال و ارسال به ایران…', 'ok');
  try {
    const j = await api('api/set', { path: key, failover: fo });
    flash(j.message, 'ok');
  } catch (e) { flash(e.message, 'err'); }
  setBusy(false);
  load();
}
async function testNow() {
  setBusy(true);
  flash('در حال پروب همهٔ مسیرها از ایران…', 'ok');
  try { await api('api/test', {}); flash('پروب انجام شد.', 'ok'); } catch (e) { flash(e.message, 'err'); }
  setBusy(false);
  load();
}
load();
setInterval(load, 15000);
</script>
</body>
</html>
"""


PAGES = {"/", "/index.html"}


class Handler(BaseHTTPRequestHandler):
    server_version = "path-web/1"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return

    def _cookie(self) -> str:
        raw = self.headers.get("Cookie") or ""
        name = _cfg.get("COOKIE_NAME") or "vpnpath"
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
        if n > 20_000:
            return {}
        raw = self.rfile.read(n) if n else b"{}"
        try:
            obj = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            return {}
        return obj if isinstance(obj, dict) else {}

    def _read_form(self) -> dict[str, str]:
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(min(n, 20_000)) if n else b""
        q = parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
        return {k: (v[-1] if v else "") for k, v in q.items()}

    def _set_cookie_header(self, token: str, clear: bool = False) -> tuple[str, str]:
        name = _cfg.get("COOKIE_NAME") or "vpnpath"
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
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path in PAGES:
            page = APP_HTML if self._authed() else LOGIN_HTML.replace("ERR", "")
            self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
            return
        if not self._authed():
            self._fail("auth", 401)
            return
        if path == "/api/status":
            try:
                self._ok(status_payload())
            except Exception as e:  # noqa: BLE001
                self._fail(err_text(e), 500)
            return
        self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path == "/login":
            self._login()
            return
        if path == "/logout":
            self._send(302, b"", "text/plain", [self._set_cookie_header("", clear=True), ("Location", ".")])
            return
        if not self._authed():
            self._fail("auth", 401)
            return
        if path == "/api/set":
            data = self._read_json()
            try:
                msg = apply_choice(str(data.get("path") or ""), bool(data.get("failover", True)))
                self._ok({"ok": True, "message": msg})
            except ValueError as e:
                self._fail(str(e), 400)
            except Exception as e:  # noqa: BLE001
                self._fail(err_text(e), 500)
            return
        if path == "/api/test":
            try:
                h = run_test()
                self._ok({"ok": True, "health": h})
            except Exception as e:  # noqa: BLE001
                self._fail(err_text(e), 500)
            return
        self._send(404, b"not found", "text/plain")

    def _login(self) -> None:
        ip = self.headers.get("X-Real-IP") or self.client_address[0]
        ctype = (self.headers.get("Content-Type") or "").lower()
        data = self._read_json() if "json" in ctype else self._read_form()
        user = (data.get("user") or "").strip()
        password = data.get("pass") or data.get("password") or ""
        ok_user = hmac.compare_digest(user, _cfg.get("AUTH_USER") or "path")
        if not login_allowed(ip) or not ok_user or not verify_password(password):
            html = LOGIN_HTML.replace("ERR", '<div class="err">ورود نامعتبر است. دوباره تلاش کنید.</div>')
            self._send(401, html.encode("utf-8"), "text/html; charset=utf-8")
            return
        self._send(302, b"", "text/plain", [self._set_cookie_header(make_session()), ("Location", ".")])


def main() -> None:
    global _cfg
    _cfg = load_cfg()
    if not _cfg.get("AUTH_HASH") or not _cfg.get("SESSION_SECRET"):
        raise SystemExit("missing AUTH_HASH or SESSION_SECRET in config")
    listen = _cfg.get("LISTEN") or "127.0.0.1:8790"
    host, _, port_s = listen.rpartition(":")
    httpd = ThreadingHTTPServer((host or "127.0.0.1", int(port_s)), Handler)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
