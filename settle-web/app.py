#!/usr/bin/env python3
"""Reseller settlement: bill data_limit deltas per panel user id. Stdlib only."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import settle_ledger as ledger
import pay_orders as pay

def _get_seller_shop(conn, admin_id: int) -> dict:
    """Wrapper so local vars named `pay` cannot shadow pay_orders.get_seller_shop."""
    return pay.get_seller_shop(conn, admin_id)

CFG_PATH = Path(os.environ.get("SETTLE_CFG", "/etc/settle-web/config.env"))
SECRETS_PATH = Path("/root/.vpn-secrets/.env")
CONTAINER = "pasarguard"
PANEL_TOKEN_URL = "http://127.0.0.1:8000/api/admin/token"
PANEL_API_BASE = "http://127.0.0.1:8000"
GIB = 1024**3
DEFAULT_PRICE = 2500
LOGIN_WINDOW = 60.0
LOGIN_MAX = 12
OPERATOR_TTL = 7 * 24 * 3600
RESELLER_TTL = 24 * 3600
ADMIN_STATUS_TTL = 60.0
SMS_DEFAULTS = {
    "sms_enabled": "0",
    "sms_senders": "B.QMEHRIRAN",
    "sms_account": "",
    "sms_token": "",
    "sms_suffix_digits": "3",
    "sms_notify_telegram": "1",
}

_cfg: dict[str, str] = {}
_login_hits: dict[str, list[float]] = {}
_admin_status: dict[int, tuple[float, bool]] = {}
_lock = threading.RLock()
_scan_started = False


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
        "LISTEN": "127.0.0.1:8789",
        "AUTH_USER": "settle",
        "COOKIE_NAME": "settleweb",
        "DB_PATH": "/var/lib/settle-web/settle.db",
    }
    d.update(_parse_env(CFG_PATH))
    return d


def db() -> sqlite3.Connection:
    path = Path(_cfg["DB_PATH"])
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=8000")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS seller (
            admin_id INTEGER PRIMARY KEY,
            price INTEGER NOT NULL DEFAULT 2500,
            debt_toman INTEGER NOT NULL DEFAULT 0
        )"""
    )
    cols = {r[1] for r in conn.execute("PRAGMA table_info(seller)").fetchall()}
    if "debt_toman" not in cols:
        conn.execute("ALTER TABLE seller ADD COLUMN debt_toman INTEGER NOT NULL DEFAULT 0")
    pay.ensure_tables(conn)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS ledger (
            admin_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            billed_bytes INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (admin_id, user_id)
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS settlement (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER NOT NULL,
            ts REAL NOT NULL,
            kind TEXT NOT NULL,
            delta_bytes INTEGER NOT NULL,
            toman INTEGER NOT NULL,
            users INTEGER NOT NULL,
            note TEXT NOT NULL DEFAULT ''
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS settlement_item (
            settlement_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            prev_billed INTEGER NOT NULL,
            new_limit INTEGER NOT NULL,
            delta INTEGER NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS sms_inbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            sender TEXT NOT NULL,
            body TEXT NOT NULL,
            fingerprint TEXT NOT NULL UNIQUE,
            amount INTEGER,
            when_s TEXT,
            account TEXT,
            status TEXT NOT NULL,
            admin_id INTEGER,
            detail TEXT NOT NULL DEFAULT ''
        )"""
    )
    ledger.ensure_tables(conn)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS agency (
            admin_id INTEGER PRIMARY KEY,
            parent_id INTEGER NOT NULL
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_agency_parent ON agency(parent_id)"
    )
    return conn


def setting_get(key: str, default: str = "") -> str:
    conn = db()
    try:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        if row is None:
            return default
        return str(row["value"])
    finally:
        conn.close()


def setting_set(key: str, value: str) -> None:
    conn = db()
    try:
        conn.execute(
            "INSERT INTO settings(key, value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
    finally:
        conn.close()


def sms_settings() -> dict[str, str]:
    out = dict(SMS_DEFAULTS)
    conn = db()
    try:
        for row in conn.execute("SELECT key, value FROM settings WHERE key LIKE 'sms_%'"):
            out[str(row["key"])] = str(row["value"])
    finally:
        conn.close()
    if not out.get("sms_token"):
        tok = secrets.token_urlsafe(24)
        setting_set("sms_token", tok)
        out["sms_token"] = tok
    return out


def ensure_sms_token() -> str:
    return sms_settings()["sms_token"]


def unique_pay_amount(total: int, admin_id: int, digits: int = 3) -> int:
    """Encode admin_id into the last `digits` of the transfer amount (≤ total)."""
    total = max(0, int(total))
    admin_id = int(admin_id)
    digits = max(1, min(6, int(digits)))
    mod = 10**digits
    if admin_id < 1 or admin_id >= mod or total < admin_id:
        return total
    base = (total // mod) * mod + admin_id
    if base > total:
        base -= mod
    return max(admin_id, base)


def parse_bank_sms(text: str) -> dict | None:
    """Parse Mehr Iran style SMS. Returns deposit info or None."""
    raw = (text or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not raw:
        return None
    lines = [ln.strip() for ln in raw.split("\n") if ln.strip()]
    amount = None
    sign = None
    when_s = ""
    account = ""
    balance = None
    for ln in lines:
        m = re.fullmatch(r"([\d,]+)([+-])", ln.replace(" ", ""))
        if m:
            amount = int(m.group(1).replace(",", ""))
            sign = m.group(2)
            continue
        m = re.fullmatch(r"(\d{4}/\d{1,2}/\d{1,2}-\d{1,2}:\d{2})", ln.replace(" ", ""))
        if m:
            when_s = m.group(1)
            continue
        m = re.match(r"مانده\s*:\s*([\d,]+)", ln)
        if m:
            balance = int(m.group(1).replace(",", ""))
            continue
        if re.fullmatch(r"\d{10,24}", ln.replace(" ", "")) and not account:
            account = ln.replace(" ", "")
    if amount is None or sign is None:
        # single-line / loose fallback
        m = re.search(r"([\d,]+)\s*([+-])", raw)
        if not m:
            return None
        amount = int(m.group(1).replace(",", ""))
        sign = m.group(2)
        m2 = re.search(r"(\d{4}/\d{1,2}/\d{1,2}-\d{1,2}:\d{2})", raw)
        when_s = m2.group(1) if m2 else ""
        m3 = re.search(r"مانده\s*:\s*([\d,]+)", raw)
        balance = int(m3.group(1).replace(",", "")) if m3 else None
        m4 = re.search(r"\b(\d{15,24})\b", raw)
        account = m4.group(1) if m4 else ""
    return {
        "amount": amount,
        "is_deposit": sign == "+",
        "when_s": when_s,
        "account": account,
        "balance": balance,
        "raw": raw,
    }


def sms_fingerprint(sender: str, parsed: dict) -> str:
    base = "|".join(
        [
            (sender or "").strip().upper(),
            str(parsed.get("account") or ""),
            str(parsed.get("amount") or ""),
            "+" if parsed.get("is_deposit") else "-",
            str(parsed.get("when_s") or ""),
            str(parsed.get("balance") if parsed.get("balance") is not None else ""),
        ]
    )
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def telegram_notify(text: str) -> None:
    secrets_env = _parse_env(SECRETS_PATH)
    token = secrets_env.get("TELEGRAM_BOT_TOKEN") or ""
    chat = secrets_env.get("TELEGRAM_CHAT_ID") or ""
    if not token or not chat:
        return
    body = urllib.parse.urlencode({"chat_id": chat, "text": text}).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=body,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=12):
            return
    except Exception:
        return


def log_sms(
    sender: str,
    body: str,
    fingerprint: str,
    parsed: dict | None,
    status: str,
    admin_id: int | None = None,
    detail: str = "",
) -> bool:
    """Insert SMS row. Returns False if duplicate fingerprint."""
    conn = db()
    try:
        conn.execute(
            "INSERT INTO sms_inbox(ts, sender, body, fingerprint, amount, when_s, account, status, admin_id, detail) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                time.time(),
                sender,
                body,
                fingerprint,
                (parsed or {}).get("amount"),
                (parsed or {}).get("when_s") or "",
                (parsed or {}).get("account") or "",
                status,
                admin_id,
                detail,
            ),
        )
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def list_sms(limit: int = 30) -> list[dict]:
    conn = db()
    try:
        rows = conn.execute(
            "SELECT id, ts, sender, amount, when_s, account, status, admin_id, detail "
            "FROM sms_inbox ORDER BY ts DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def process_sms_webhook(
    sender: str, body: str, *, seller_admin_id: int | None = None
) -> dict:
    """Process inbound bank SMS.

    seller_admin_id: when set (per-admin webhook token), only match that admin's
    /pay/ orders — never another reseller's. Owner token (admin #1) may fall
    through to agency settle on the same card; other sellers stop at unmatched.
    """
    cfg = sms_settings()
    if cfg.get("sms_enabled") != "1":
        return {"ok": False, "error": "دریافت پیامک خاموش است.", "code": 503}

    sender_n = (sender or "").strip()
    # App "TEST" button often sends dummy sender 123456789 — treat as connectivity OK.
    if sender_n in ("123456789", "1234567890", "test", "TEST"):
        fp = hashlib.sha256(f"test|{sender_n}|{body}|{time.time()}".encode()).hexdigest()
        log_sms(
            sender_n,
            body,
            fp,
            None,
            "test_ok",
            detail="تست اتصال موفق؛ برای تسویه واقعی فرستنده باید B.QMEHRIRAN باشد",
        )
        return {
            "ok": True,
            "status": "test",
            "message": "اتصال برقرار است. دکمه TEST فرستنده جعلی می‌فرستد؛ پیامک واقعی بانک ثبت می‌شود.",
        }

    allow = [s.strip().upper() for s in (cfg.get("sms_senders") or "").split(",") if s.strip()]
    if allow and sender_n.upper() not in allow:
        fp = hashlib.sha256(f"{sender_n}|{body}".encode()).hexdigest()
        log_sms(sender_n, body, fp, None, "ignored_sender", detail="فرستنده مجاز نیست")
        # 200 تا اپ فوروارد ERROR/retry نزند؛ پیامک را عمداً نادیده گرفتیم.
        return {
            "ok": True,
            "status": "ignored",
            "message": f"فرستنده «{sender_n}» مجاز نیست؛ فقط پیامک‌های تنظیم‌شده پردازش می‌شوند.",
        }

    parsed = parse_bank_sms(body)
    if not parsed:
        fp = hashlib.sha256(f"{sender_n}|{body}".encode()).hexdigest()
        log_sms(sender_n, body, fp, None, "parse_fail", detail="قالب ناشناخته")
        return {
            "ok": True,
            "status": "ignored",
            "message": "قالب پیامک بانک شناخته نشد؛ نادیده گرفته شد.",
        }

    fp = sms_fingerprint(sender_n, parsed)
    if not parsed["is_deposit"]:
        if not log_sms(sender_n, body, fp, parsed, "ignored_withdraw", detail="برداشت نادیده گرفته شد"):
            return {"ok": True, "status": "duplicate", "message": "قبلاً دیده شده."}
        return {"ok": True, "status": "ignored", "message": "برداشت بود؛ نادیده گرفته شد."}

    digits = as_int(cfg.get("sms_suffix_digits"), 3)
    raw_amount = int(parsed["amount"])

    # Retail /pay/ orders first (before account filter — reseller cards vary).
    # Scoped by seller_admin_id when using a per-admin webhook token.
    pay_hit = None
    pay_unit = "toman"
    amount = 0
    for cand in pay.toman_candidates_from_sms(raw_amount):
        conn_p = db()
        try:
            pay_hit = pay.find_pending_by_amount(
                conn_p, cand, admin_id=seller_admin_id
            )
        finally:
            conn_p.close()
        if pay_hit:
            amount = cand
            pay_unit = "rial" if cand == raw_amount // 10 and raw_amount % 10 == 0 else "toman"
            break

    if pay_hit:
        aid_hit = int(pay_hit["admin_id"])
        conn_mode = db()
        try:
            mode = pay.seller_pay_mode(conn_mode, aid_hit)
        finally:
            conn_mode.close()
        if mode != "auto":
            # Admin chose manual confirm — log SMS but do not auto-charge.
            if not log_sms(
                sender_n,
                body,
                fp,
                parsed,
                "order_manual",
                admin_id=aid_hit,
                detail=f"سفارش #{pay_hit['id']} حالت دستی · {fmt_toman(amount)}",
            ):
                return {"ok": True, "status": "duplicate", "message": "قبلاً دیده شده."}
            if cfg.get("sms_notify_telegram") == "1":
                telegram_notify(
                    "واریز سفارش (تأیید دستی لازم است)\n"
                    f"سفارش #{pay_hit['id']} · {pay_hit.get('username')}\n"
                    f"ادمین #{aid_hit} · {fmt_toman(amount)}\n"
                    "در settle → فروش به مشتری → تأیید کنید."
                )
            return {
                "ok": True,
                "status": "order_manual",
                "order_id": int(pay_hit["id"]),
                "admin_id": aid_hit,
                "amount": amount,
                "message": "واریز دیده شد؛ ادمین باید دستی تأیید کند.",
            }
        if not log_sms(
            sender_n,
            body,
            fp,
            parsed,
            "processing",
            admin_id=aid_hit,
            detail=f"سفارش خرید #{pay_hit['id']} · {pay_unit}→{amount}",
        ):
            return {"ok": True, "status": "duplicate", "message": "قبلاً دیده شده."}
        try:
            fulfilled = fulfill_pay_order(int(pay_hit["id"]))
        except Exception as e:  # noqa: BLE001
            _sms_update_status(fp, "error", str(e)[:300])
            if cfg.get("sms_notify_telegram") == "1":
                telegram_notify(
                    f"خطا در شارژ خودکار سفارش #{pay_hit['id']}\n"
                    f"یوزر: {pay_hit.get('username')}\n{e}"
                )
            return {"ok": False, "error": str(e), "code": 500}
        _sms_update_status(
            fp,
            "paid_order",
            f"سفارش #{pay_hit['id']} · {pay_hit.get('username')} · {fmt_toman(amount)}",
        )
        if cfg.get("sms_notify_telegram") == "1":
            telegram_notify(
                "شارژ خودکار مشتری (/pay/)\n"
                f"سفارش: #{pay_hit['id']}\n"
                f"یوزر: {pay_hit.get('username')} (ادمین #{aid_hit})\n"
                f"پلن: {pay_hit.get('gib')} گیگ / {pay_hit.get('days')} روز\n"
                f"واریز: {fmt_toman(amount)}\n"
                f"{fulfilled.get('detail') or ''}"
            )
        return {
            "ok": True,
            "status": "paid_order",
            "order_id": int(pay_hit["id"]),
            "admin_id": aid_hit,
            "username": pay_hit.get("username"),
            "amount": amount,
            "message": "سفارش مشتری شارژ شد.",
        }

    # Per-admin shop token: اگر سفارش /pay/ نبود —
    # برای مالک (ادمین ۱) ادامه بده تا تسویه نمایندگی روی همان کارت ثبت شود.
    # برای بقیه فروشنده‌ها فقط سفارش خودشان؛ وگرنه unmatched_seller.
    if seller_admin_id is not None and int(seller_admin_id) != 1:
        if not log_sms(
            sender_n,
            body,
            fp,
            parsed,
            "unmatched_seller",
            admin_id=int(seller_admin_id),
            detail=f"مبلغ {raw_amount:,} با سفارش ادمین #{seller_admin_id} جور نشد",
        ):
            return {"ok": True, "status": "duplicate", "message": "قبلاً دیده شده."}
        return {
            "ok": True,
            "status": "unmatched",
            "admin_id": int(seller_admin_id),
            "message": "واریز دیده شد ولی سفارش در انتظار این ادمین با این مبلغ نبود.",
        }

    account_filter = (cfg.get("sms_account") or "").strip()
    if account_filter and parsed.get("account") and parsed["account"] != account_filter:
        if not log_sms(sender_n, body, fp, parsed, "ignored_account", detail="شماره حساب جور نیست"):
            return {"ok": True, "status": "duplicate", "message": "قبلاً دیده شده."}
        return {
            "ok": True,
            "status": "ignored",
            "message": "شماره حساب با تنظیمات جور نیست؛ نادیده گرفته شد.",
        }

    amount, admin_id, unit = sms_raw_to_toman(raw_amount, digits)
    if admin_id < 1:
        if not log_sms(sender_n, body, fp, parsed, "unmatched", detail="کد ادمین از مبلغ درنیامد"):
            return {"ok": True, "status": "duplicate", "message": "قبلاً دیده شده."}
        if cfg.get("sms_notify_telegram") == "1":
            telegram_notify(
                f"پیامک واریز بدون کد ادمین\nمبلغ خام: {raw_amount:,}\nزمان: {parsed.get('when_s') or '-'}"
            )
        return {"ok": False, "error": "از مبلغ کد ادمین درنیامد (رقم‌های آخر).", "code": 409}

    # Reserve fingerprint before settle to avoid double-settle races.
    if not log_sms(
        sender_n,
        body,
        fp,
        parsed,
        "processing",
        admin_id=admin_id,
        detail=f"در حال ثبت · {unit}→{amount}",
    ):
        return {"ok": True, "status": "duplicate", "message": "قبلاً دیده شده."}

    try:
        info = build_rows(admin_id)
    except Exception as e:  # noqa: BLE001
        _sms_update_status(fp, "error", f"خواندن پنل: {e}")
        return {"ok": False, "error": str(e), "code": 500}

    # ادمین اصلی با زیرمجموعه: بدهی شبکه؛ وگرنه بدهی خودش
    total = int(info.get("network_total") or info["total"])
    if total <= 0:
        _sms_update_status(fp, "unmatched", "این ادمین بدهی ندارد")
        if cfg.get("sms_notify_telegram") == "1":
            telegram_notify(
                f"واریز {fmt_toman(amount)} برای #{admin_id} ({info.get('admin_username')}) "
                f"ولی بدهی صفر بود."
            )
        return {"ok": False, "error": "این ادمین الان بدهی ندارد.", "code": 409}

    expected = unique_pay_amount(total, admin_id, digits)
    if amount > total:
        _sms_update_status(fp, "unmatched", f"مبلغ بیشتر از بدهی ({fmt_toman(total)})")
        if cfg.get("sms_notify_telegram") == "1":
            telegram_notify(
                f"واریز زیاد از حد برای #{admin_id}\nواریز: {fmt_toman(amount)}\nبدهی: {fmt_toman(total)}"
            )
        return {"ok": False, "error": "مبلغ واریز بیشتر از مجموع بدهی است.", "code": 409}

    # Soft match: suffix encodes admin and amount ≤ debt. Prefer exact unique amount.
    try:
        result = do_settle(admin_id, "charge", paid=amount)
    except Exception as e:  # noqa: BLE001
        _sms_update_status(fp, "error", str(e))
        return {"ok": False, "error": str(e), "code": 500}

    note_extra = (
        f"خودکار از پیامک ({unit}) · خام {raw_amount:,} · "
        f"انتظار {fmt_toman(expected)} / {fmt_rial(toman_to_rial(expected))}"
    )
    _sms_update_status(fp, "settled", note_extra)
    if cfg.get("sms_notify_telegram") == "1":
        telegram_notify(
            f"تسویه خودکار پیامک\n"
            f"ادمین: {info.get('admin_username')} (#{admin_id})\n"
            f"واریز: {fmt_toman(amount)} ({fmt_rial(toman_to_rial(amount))})\n"
            f"بدهی قبل: {fmt_toman(total)}\n"
            f"{result.get('message') or ''}"
        )
    return {
        "ok": True,
        "status": "settled",
        "admin_id": admin_id,
        "amount": amount,
        "amount_rial": toman_to_rial(amount),
        "raw_amount": raw_amount,
        "unit": unit,
        "expected": expected,
        "message": result.get("message"),
    }


def _sms_update_status(fingerprint: str, status: str, detail: str = "") -> None:
    conn = db()
    try:
        conn.execute(
            "UPDATE sms_inbox SET status=?, detail=? WHERE fingerprint=?",
            (status, detail, fingerprint),
        )
    finally:
        conn.close()


def panel_query(sql: str, args: list | None = None) -> list[dict]:
    payload = json.dumps({"sql": sql, "args": args or []}, ensure_ascii=False)
    py = r"""
import json, sqlite3, sys
req = json.loads(sys.stdin.read())
c = sqlite3.connect("/var/lib/pasarguard/db.sqlite3")
c.row_factory = sqlite3.Row
rows = c.execute(req["sql"], req["args"]).fetchall()
print(json.dumps([dict(r) for r in rows], ensure_ascii=False, default=str))
"""
    p = subprocess.run(
        ["docker", "exec", "-i", CONTAINER, "/code/.venv/bin/python", "-c", py],
        input=payload,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if p.returncode != 0:
        err = (p.stderr or p.stdout or "").strip().splitlines()
        tail = err[-1] if err else f"exit {p.returncode}"
        raise RuntimeError(f"خواندن پنل ناموفق بود: {tail}")
    try:
        data = json.loads(p.stdout or "[]")
    except json.JSONDecodeError as e:
        raise RuntimeError("جواب دیتابیس پنل قابل‌خواندن نبود.") from e
    return data if isinstance(data, list) else []


def as_int(v, default: int = 0) -> int:
    try:
        if v is None:
            return default
        return int(v)
    except (TypeError, ValueError):
        return default


def fmt_gib(n: int) -> str:
    b = float(max(0, int(n)))
    if b < 1024:
        return f"{int(b)} B"
    for unit, div in (("KiB", 1024), ("MiB", 1024**2), ("GiB", GIB), ("TiB", 1024**4)):
        if b < div * 1024 or unit == "TiB":
            val = b / div
            if val >= 10:
                return f"{val:.1f} {unit}"
            return f"{val:.2f} {unit}"
    return f"{b:.1f} B"


def toman_of(delta_bytes: int, price: int) -> int:
    if delta_bytes <= 0 or price <= 0:
        return 0
    return int(round((delta_bytes / GIB) * price))


def fmt_toman(n: int) -> str:
    return f"{int(n):,}".replace(",", "٬") + " تومان"


def fmt_rial(n: int) -> str:
    return f"{int(n):,}".replace(",", "٬") + " ریال"


def toman_to_rial(toman: int) -> int:
    return max(0, int(toman)) * 10


def sms_raw_to_toman(raw_amount: int, digits: int = 3) -> tuple[int, int, str]:
    """Bank SMS is usually Rials. Return (toman, admin_id, unit) preferring rial decode."""
    raw_amount = int(raw_amount)
    digits = max(1, min(6, int(digits)))
    mod = 10**digits
    candidates: list[tuple[int, int, str]] = []
    if raw_amount % 10 == 0:
        toman = raw_amount // 10
        candidates.append((toman, toman % mod, "rial"))
    candidates.append((raw_amount, raw_amount % mod, "toman"))
    for toman, aid, unit in candidates:
        if aid >= 1:
            return toman, aid, unit
    toman, aid, unit = candidates[0]
    return toman, aid, unit


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


def _sign(msg: str) -> str:
    return hmac.new((_cfg.get("SESSION_SECRET") or "").encode(), msg.encode(), hashlib.sha256).hexdigest()


def make_session(role: str, admin_id: int = 0) -> str:
    """role 'op' = settlement operator (full). role 'ro' = one panel admin, read-only own data."""
    ttl = OPERATOR_TTL if role == "op" else RESELLER_TTL
    exp = int(time.time()) + ttl
    body = f"{exp}:{role}:{int(admin_id)}"
    return f"{body}:{_sign(body)}"


def session_info(token: str) -> dict | None:
    parts = (token or "").split(":")
    if len(parts) != 4:
        return None
    exp_s, role, aid_s, sig = parts
    if role not in ("op", "ro"):
        return None
    try:
        exp = int(exp_s)
        aid = int(aid_s)
    except ValueError:
        return None
    if exp < int(time.time()):
        return None
    if not hmac.compare_digest(sig, _sign(f"{exp_s}:{role}:{aid_s}")):
        return None
    if role == "ro" and aid < 1:
        return None
    return {"role": role, "admin_id": aid}


def panel_login(username: str, password: str) -> bool:
    """True if PasarGuard accepts these admin credentials. Never logs the password."""
    body = urllib.parse.urlencode({"username": username, "password": password}).encode()
    req = urllib.request.Request(
        PANEL_TOKEN_URL,
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status == 200
    except urllib.error.HTTPError:
        return False
    except urllib.error.URLError:
        raise RuntimeError("پنل PasarGuard در دسترس نیست؛ چند دقیقه بعد دوباره امتحان کنید.") from None


def panel_admin_by_name(username: str) -> dict | None:
    rows = panel_query(
        "SELECT id, username, status FROM admins WHERE lower(username)=lower(?)", [username]
    )
    return rows[0] if len(rows) == 1 else None


def admin_active(admin_id: int) -> bool:
    now = time.time()
    hit = _admin_status.get(admin_id)
    if hit and now - hit[0] < ADMIN_STATUS_TTL:
        return hit[1]
    rows = panel_query("SELECT status FROM admins WHERE id=?", [admin_id])
    ok = bool(rows) and (rows[0].get("status") or "") == "active"
    _admin_status[admin_id] = (now, ok)
    return ok


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


def price_for(admin_id: int) -> int:
    conn = db()
    try:
        row = conn.execute("SELECT price FROM seller WHERE admin_id=?", (admin_id,)).fetchone()
        return int(row["price"]) if row else DEFAULT_PRICE
    finally:
        conn.close()


def debt_for(admin_id: int) -> int:
    conn = db()
    try:
        row = conn.execute("SELECT debt_toman FROM seller WHERE admin_id=?", (admin_id,)).fetchone()
        return max(0, int(row["debt_toman"])) if row else 0
    finally:
        conn.close()


def set_price(admin_id: int, price: int) -> None:
    conn = db()
    try:
        conn.execute(
            "INSERT INTO seller(admin_id, price, debt_toman) VALUES(?,?,0) "
            "ON CONFLICT(admin_id) DO UPDATE SET price=excluded.price",
            (admin_id, price),
        )
    finally:
        conn.close()


def set_debt(admin_id: int, debt: int) -> None:
    debt = max(0, int(debt))
    conn = db()
    try:
        conn.execute(
            "INSERT INTO seller(admin_id, price, debt_toman) VALUES(?,?,?) "
            "ON CONFLICT(admin_id) DO UPDATE SET debt_toman=excluded.debt_toman",
            (admin_id, DEFAULT_PRICE, debt),
        )
    finally:
        conn.close()


def agency_map() -> dict[int, int]:
    """child_admin_id -> parent_admin_id"""
    conn = db()
    try:
        rows = conn.execute("SELECT admin_id, parent_id FROM agency").fetchall()
        return {int(r["admin_id"]): int(r["parent_id"]) for r in rows}
    finally:
        conn.close()


def parent_of(admin_id: int) -> int | None:
    return agency_map().get(int(admin_id))


def children_of(admin_id: int) -> list[int]:
    aid = int(admin_id)
    return sorted(cid for cid, pid in agency_map().items() if pid == aid)


def network_ids(admin_id: int) -> list[int]:
    aid = int(admin_id)
    return [aid] + children_of(aid)


def set_agency(admin_id: int, parent_id: int | None) -> dict:
    """Link child under parent (one level). parent_id=None unlinks."""
    aid = int(admin_id)
    if aid < 1:
        raise ValueError("ادمین نامعتبر است.")
    rows = panel_query("SELECT id, username FROM admins WHERE id=?", [aid])
    if not rows:
        raise ValueError("این ادمین در پنل نیست.")
    amap = agency_map()
    if parent_id is None or int(parent_id) <= 0:
        conn = db()
        try:
            conn.execute("DELETE FROM agency WHERE admin_id=?", (aid,))
        finally:
            conn.close()
        return {
            "ok": True,
            "message": f"ادمین #{aid} دیگر زیر نظر مدیر ارشد نیست.",
            "admin_id": aid,
            "parent_id": None,
        }
    pid = int(parent_id)
    if pid == aid:
        raise ValueError("ادمین نمی‌تواند مدیر ارشد خودش باشد.")
    prows = panel_query("SELECT id, username FROM admins WHERE id=?", [pid])
    if not prows:
        raise ValueError("مدیر ارشد در پنل پیدا نشد.")
    if amap.get(pid):
        raise ValueError("انتخاب‌شده خودش مدیر است؛ فقط یک سطح مجاز است.")
    if any(p == aid for p in amap.values()):
        raise ValueError("این ادمین خودش مدیر ارشد است؛ نمی‌تواند مدیر شود.")
    if amap.get(aid) == pid:
        return {
            "ok": True,
            "message": "قبلاً همین مدیر ارشد تنظیم شده بود.",
            "admin_id": aid,
            "parent_id": pid,
        }
    conn = db()
    try:
        conn.execute(
            "INSERT INTO agency(admin_id, parent_id) VALUES(?,?) "
            "ON CONFLICT(admin_id) DO UPDATE SET parent_id=excluded.parent_id",
            (aid, pid),
        )
    finally:
        conn.close()
    pname = (prows[0].get("username") or "") or f"#{pid}"
    cname = (rows[0].get("username") or "") or f"#{aid}"
    return {
        "ok": True,
        "message": f"{cname} مدیر زیر نظر {pname} شد.",
        "admin_id": aid,
        "parent_id": pid,
    }


def can_view_admin(sess: dict, admin_id: int) -> bool:
    aid = int(admin_id)
    if aid < 1:
        return False
    if sess.get("role") == "op":
        return True
    mine = int(sess.get("admin_id") or 0)
    if mine == aid:
        return True
    return parent_of(aid) == mine


def network_money(parent_id: int, *, self_info: dict | None = None) -> dict:
    """Sum period/debt/total for parent + children; pay suffix uses parent id."""
    pid = int(parent_id)
    member_ids = network_ids(pid)
    members = []
    tot_period = tot_debt = tot_delta = 0
    for mid in member_ids:
        info = self_info if mid == pid and self_info is not None else build_rows(mid, with_network=False)
        members.append(
            {
                "id": mid,
                "username": info.get("admin_username") or "",
                "toman": info["toman"],
                "toman_h": info["toman_h"],
                "debt": info["debt"],
                "debt_h": info["debt_h"],
                "total": info["total"],
                "total_h": info["total_h"],
                "delta_h": info["delta_h"],
                "count": info["count"],
                "new": info["new"],
                "recharge": info["recharge"],
                "is_self": mid == pid,
            }
        )
        tot_period += int(info["toman"])
        tot_debt += int(info["debt"])
        tot_delta += int(info["delta"])
    total = tot_period + tot_debt
    digits = as_int(sms_settings().get("sms_suffix_digits"), 3)
    pay = unique_pay_amount(total, pid, digits) if total > 0 else 0
    return {
        "parent_id": pid,
        "members": members,
        "toman": tot_period,
        "toman_h": fmt_toman(tot_period),
        "debt": tot_debt,
        "debt_h": fmt_toman(tot_debt),
        "total": total,
        "total_h": fmt_toman(total),
        "delta": tot_delta,
        "delta_h": fmt_gib(tot_delta),
        "pay": pay,
        "pay_h": fmt_toman(pay) if pay else fmt_toman(0),
        "pay_rial": toman_to_rial(pay) if pay else 0,
        "pay_rial_h": fmt_rial(toman_to_rial(pay)) if pay else fmt_rial(0),
        "pay_both_h": (
            f"{fmt_toman(pay)}  ·  {fmt_rial(toman_to_rial(pay))}" if pay else fmt_toman(0)
        ),
    }


def billed_map(admin_id: int) -> dict[int, int]:
    conn = db()
    try:
        rows = conn.execute(
            "SELECT user_id, billed_bytes FROM ledger WHERE admin_id=?", (admin_id,)
        ).fetchall()
        return {int(r["user_id"]): int(r["billed_bytes"]) for r in rows}
    finally:
        conn.close()


def last_settlement(admin_id: int) -> dict | None:
    conn = db()
    try:
        row = conn.execute(
            "SELECT id, ts, kind, delta_bytes, toman, users, note FROM settlement "
            "WHERE admin_id=? ORDER BY ts DESC LIMIT 1",
            (admin_id,),
        ).fetchone()
        if not row:
            return None
        return dict(row)
    finally:
        conn.close()


def classify(billed: int, limit: int) -> str:
    delta = max(0, limit - billed)
    if delta <= 0:
        return "unchanged"
    if billed <= 0:
        return "new"
    return "recharge"


def _row_payload(
    *,
    uid: int,
    username: str,
    status: str,
    limit: int,
    prev: int,
    price: float,
    used: int = 0,
    deleted: bool = False,
    waive: dict | None = None,
) -> dict:
    delta = max(0, limit - prev)
    kind = "deleted" if deleted and delta > 0 else classify(prev, limit)
    if deleted and delta <= 0:
        kind = "deleted"
    wt = toman_of(delta, price)
    pending = bool(waive)
    return {
        "id": uid,
        "username": username or "",
        "status": status,
        "limit": limit,
        "limit_h": fmt_gib(limit),
        "billed": prev,
        "billed_h": fmt_gib(prev),
        "delta": delta,
        "delta_h": fmt_gib(delta),
        "toman": wt,
        "toman_h": fmt_toman(wt),
        "kind": kind,
        "used_h": fmt_gib(used),
        "deleted": deleted,
        "waive_pending": pending,
        "waive_id": int(waive["id"]) if pending else None,
        "can_waive": delta > 0 and not pending,
    }


def format_tg_handle(raw: str) -> str:
    """Normalize telegram id/link to @handle for display; empty if missing."""
    s = (raw or "").strip()
    if not s:
        return ""
    low = s.lower()
    for prefix in ("https://t.me/", "http://t.me/", "t.me/"):
        if low.startswith(prefix):
            s = s[len(prefix) :]
            break
    s = s.strip().strip("@").split("?")[0].split("/")[0].strip().strip("@")
    if not s or any(c.isspace() for c in s):
        return ""
    return "@" + s


def build_rows(admin_id: int, *, with_network: bool = True) -> dict:
    users = panel_query(
        "SELECT id, username, status, used_traffic, data_limit, created_at, expire "
        "FROM users WHERE admin_id=? ORDER BY username COLLATE NOCASE",
        [admin_id],
    )
    admins = panel_query("SELECT username FROM admins WHERE id=?", [admin_id])
    admin_name = (admins[0].get("username") if admins else "") or f"#{admin_id}"
    billed = billed_map(admin_id)
    price = price_for(admin_id)
    conn = db()
    try:
        ledger.scan_admin(conn, admin_id, users, as_int=as_int)
        tracks = ledger.track_map(conn, admin_id)
        waives = ledger.pending_waive_map(conn, admin_id)
    finally:
        conn.close()

    rows = []
    tot_delta = tot_limit = 0
    n_new = n_recharge = n_deleted = 0
    seen: set[int] = set()
    for u in users:
        uid = as_int(u.get("id"))
        seen.add(uid)
        # Prefer max(live limit, tracked) so mid-scan bumps aren't lost
        live_limit = as_int(u.get("data_limit"))
        tracked = tracks.get(uid) or {}
        limit = max(live_limit, as_int(tracked.get("last_limit")))
        prev = billed.get(uid, 0)
        row = _row_payload(
            uid=uid,
            username=u.get("username") or "",
            status=u.get("status") or "",
            limit=limit,
            prev=prev,
            price=price,
            used=as_int(u.get("used_traffic")),
            deleted=False,
            waive=waives.get(uid),
        )
        if row["kind"] == "new":
            n_new += 1
        elif row["kind"] == "recharge":
            n_recharge += 1
        tot_delta += row["delta"]
        tot_limit += limit
        rows.append(row)

    # Tombstones: deleted in panel but still owe unbilled limit
    for uid, tr in tracks.items():
        if uid in seen:
            continue
        if not int(tr.get("deleted") or 0):
            continue
        limit = as_int(tr.get("last_limit"))
        prev = billed.get(uid, 0)
        if limit <= prev:
            continue
        row = _row_payload(
            uid=uid,
            username=str(tr.get("username") or ""),
            status="deleted",
            limit=limit,
            prev=prev,
            price=price,
            used=as_int(tr.get("last_used")),
            deleted=True,
            waive=waives.get(uid),
        )
        n_deleted += 1
        if row["kind"] in ("new", "deleted") and prev <= 0:
            n_new += 1
        elif row["delta"] > 0:
            n_recharge += 1
        tot_delta += row["delta"]
        tot_limit += limit
        rows.append(row)

    rows.sort(key=lambda r: ((0 if r["delta"] else 1), (r["username"] or "").lower(), r["id"]))
    last = last_settlement(admin_id)
    days = None
    if last:
        days = max(0, int((time.time() - float(last["ts"])) / 86400))
    period = toman_of(tot_delta, price)
    debt = debt_for(admin_id)
    total = period + debt
    digits = as_int(sms_settings().get("sms_suffix_digits"), 3)
    pay = unique_pay_amount(total, admin_id, digits) if total > 0 else 0
    pending_waive_n = sum(1 for r in rows if r.get("waive_pending"))
    pid = parent_of(admin_id)
    kids = children_of(admin_id)
    out = {
        "admin_id": admin_id,
        "admin_username": admin_name,
        "price": price,
        "users": rows,
        "count": len(rows),
        "live_count": len(seen),
        "new": n_new,
        "recharge": n_recharge,
        "deleted_owing": n_deleted,
        "pending_waive": pending_waive_n,
        "delta": tot_delta,
        "delta_h": fmt_gib(tot_delta),
        "limit_h": fmt_gib(tot_limit),
        "toman": period,
        "toman_h": fmt_toman(period),
        "debt": debt,
        "debt_h": fmt_toman(debt),
        "total": total,
        "total_h": fmt_toman(total),
        "pay": pay,
        "pay_h": fmt_toman(pay) if pay else fmt_toman(0),
        "pay_rial": toman_to_rial(pay) if pay else 0,
        "pay_rial_h": fmt_rial(toman_to_rial(pay)) if pay else fmt_rial(0),
        "pay_both_h": (
            f"{fmt_toman(pay)}  ·  {fmt_rial(toman_to_rial(pay))}" if pay else fmt_toman(0)
        ),
        "has_ledger": bool(billed),
        "parent_id": pid,
        "is_child": pid is not None,
        "child_ids": kids,
        "is_parent": bool(kids),
        "parent_username": "",
        "last": (
            {
                "ts": last["ts"],
                "kind": last["kind"],
                "delta_h": fmt_gib(int(last["delta_bytes"])),
                "toman_h": fmt_toman(int(last["toman"])),
                "days": days,
                "note": last.get("note") or "",
            }
            if last
            else None
        ),
    }
    out["parent_support_telegram"] = ""
    out["support_contact"] = ""
    if pid is not None:
        prows = panel_query("SELECT username FROM admins WHERE id=?", [pid])
        out["parent_username"] = (prows[0].get("username") if prows else "") or f"#{pid}"
        # توجه: بالاتر متغیر محلی pay (= مبلغ واریز) ماژول pay را می‌پوشاند
        try:
            sconn = db()
            try:
                shop = _get_seller_shop(sconn, int(pid))
            finally:
                sconn.close()
            tg = (shop.get("support_telegram") or "").strip()
        except Exception:
            tg = ""
        out["parent_support_telegram"] = tg
        out["support_contact"] = format_tg_handle(tg)
    if with_network and kids:
        net = network_money(admin_id, self_info=out)
        out["network"] = net
        # مبلغ واریز به مالک برای شبکهٔ نمایندگی (پسوند = id والد)
        out["pay"] = net["pay"]
        out["pay_h"] = net["pay_h"]
        out["pay_rial"] = net["pay_rial"]
        out["pay_rial_h"] = net["pay_rial_h"]
        out["pay_both_h"] = net["pay_both_h"]
        out["network_total"] = net["total"]
        out["network_total_h"] = net["total_h"]
        out["network_toman"] = net["toman"]
        out["network_toman_h"] = net["toman_h"]
        out["network_debt"] = net["debt"]
        out["network_debt_h"] = net["debt_h"]
    return out


def scan_all_admins() -> None:
    try:
        admins = panel_query("SELECT id FROM admins")
    except Exception:
        return
    for a in admins:
        aid = as_int(a.get("id"))
        if aid < 1:
            continue
        try:
            users = panel_query(
                "SELECT id, username, status, used_traffic, data_limit FROM users WHERE admin_id=?",
                [aid],
            )
            conn = db()
            try:
                ledger.scan_admin(conn, aid, users, as_int=as_int)
                ledger.expire_waives(conn)
            finally:
                conn.close()
        except Exception:
            continue


def _scan_loop() -> None:
    while True:
        try:
            scan_all_admins()
        except Exception:
            pass
        time.sleep(ledger.SCAN_INTERVAL_SEC)


def start_scanner() -> None:
    global _scan_started
    with _lock:
        if _scan_started:
            return
        _scan_started = True
    t = threading.Thread(target=_scan_loop, name="settle-scan", daemon=True)
    t.start()


def fulfill_pay_order(order_id: int) -> dict:
    conn = db()
    try:
        return pay.fulfill_order(conn, order_id)
    finally:
        conn.close()


def lookup_pay_user(username: str) -> dict:
    uname = (username or "").strip()
    if not uname or len(uname) > 64:
        raise ValueError("نام کاربری نامعتبر است.")
    rows = panel_query(
        "SELECT id, username, status, used_traffic, data_limit, expire, admin_id "
        "FROM users WHERE username = ? COLLATE NOCASE LIMIT 1",
        [uname],
    )
    if not rows:
        raise ValueError("کاربری با این نام پیدا نشد.")
    u = rows[0]
    aid = as_int(u.get("admin_id"))
    admins = panel_query("SELECT username FROM admins WHERE id=?", [aid]) if aid else []
    admin_name = (admins[0].get("username") if admins else "") or f"#{aid}"
    conn = db()
    try:
        plans = pay.list_plans(conn, aid, active_only=True)
        shop = pay.get_seller_shop(conn, aid)
        pending = pay.pending_for_username(conn, str(u.get("username") or uname))
    finally:
        conn.close()
    limit = as_int(u.get("data_limit"))
    used = as_int(u.get("used_traffic"))
    pending_pub = _order_public(pending) if pending else None
    if pending_pub and pending:
        pid = as_int(pending.get("plan_id"))
        pl = next((p for p in plans if int(p["id"]) == pid), None)
        if pl:
            pending_pub["user_count"] = max(1, int(pl.get("user_count") or 1))
            pending_pub["plan_id"] = pid
    return {
        "user_id": as_int(u.get("id")),
        "username": str(u.get("username") or uname),
        "status": str(u.get("status") or ""),
        "admin_id": aid,
        "admin_username": admin_name,
        "limit": limit,
        "limit_h": fmt_gib(limit) if limit else "نامحدود",
        "used": used,
        "used_h": fmt_gib(used),
        "plans": [
            {
                "id": int(p["id"]),
                "title": p["title"],
                "gib": float(p["gib"]),
                "days": int(p["days"]),
                "user_count": max(1, int(p.get("user_count") or 1)),
                "users_h": f"{max(1, int(p.get('user_count') or 1))} کاربره",
                "unlimited": float(p["gib"]) <= 0,
                "volume_h": "نامحدود" if float(p["gib"]) <= 0 else f"{float(p['gib']):g} گیگ",
                "price_toman": int(p["price_toman"]),
                "price_h": fmt_toman(int(p["price_toman"])),
            }
            for p in plans
        ],
        "card_number": shop.get("card_number") or "",
        "card_name": shop.get("card_name") or "",
        "has_card": bool(shop.get("card_number")),
        "business_name": shop.get("business_name") or "",
        "telegram_channel": shop.get("telegram_channel") or "",
        "support_phone": shop.get("support_phone") or "",
        "support_telegram": shop.get("support_telegram") or "",
        "slogan": shop.get("slogan") or pay.DEFAULT_SLOGAN,
        "pending": pending_pub,
    }


def _order_public(order: dict | None) -> dict | None:
    if not order:
        return None
    left = max(0, int(float(order["expires_ts"]) - time.time()))
    return {
        "id": int(order["id"]),
        "username": order.get("username"),
        "admin_id": int(order["admin_id"]),
        "gib": float(order["gib"]),
        "days": int(order["days"]),
        "price_toman": int(order["price_toman"]),
        "price_h": fmt_toman(int(order["price_toman"])),
        "pay_amount": int(order["pay_amount"]),
        "pay_h": fmt_toman(int(order["pay_amount"])),
        "pay_rial_h": fmt_rial(toman_to_rial(int(order["pay_amount"]))),
        "status": order.get("status"),
        "ts": float(order["ts"]),
        "expires_ts": float(order["expires_ts"]),
        "expires_in": left,
        "paid_ts": order.get("paid_ts"),
        "detail": order.get("detail") or "",
    }


def create_pay_order_for_user(username: str, plan_id: int) -> dict:
    info = lookup_pay_user(username)
    if not info["has_card"]:
        raise ValueError("فروشنده هنوز شماره کارت ثبت نکرده است. بعداً تلاش کنید.")
    if not info["plans"]:
        raise ValueError("پلنی برای خرید تعریف نشده است.")
    plan = next((p for p in info["plans"] if int(p["id"]) == int(plan_id)), None)
    if not plan:
        raise ValueError("پلن انتخاب‌شده معتبر نیست.")
    conn = db()
    try:
        # need full plan row
        rows = pay.list_plans(conn, info["admin_id"], active_only=True)
        full = next((p for p in rows if int(p["id"]) == int(plan_id)), None)
        if not full:
            raise ValueError("پلن پیدا نشد.")
        order = pay.create_order(
            conn,
            admin_id=info["admin_id"],
            user_id=info["user_id"],
            username=info["username"],
            plan=full,
        )
        card = pay.get_seller_card(conn, info["admin_id"])
    finally:
        conn.close()
    pub = _order_public(order)
    assert pub is not None
    pub["card_number"] = card.get("card_number") or ""
    pub["card_name"] = card.get("card_name") or ""
    pub["username"] = info["username"]
    pub["plan_id"] = int(full["id"])
    pub["user_count"] = max(1, int(full.get("user_count") or 1))
    return {"ok": True, "order": pub, "message": "سفارش ثبت شد؛ دقیقاً همین مبلغ را واریز کنید."}


def shop_payload(admin_id: int) -> dict:
    conn = db()
    try:
        seller_tok = pay.ensure_seller_sms_token(conn, admin_id)
        shop = pay.get_seller_shop(conn, admin_id)
        plans = pay.list_plans(conn, admin_id, active_only=False)
        pending = pay.list_pending_orders(conn, admin_id, limit=40)
        conn.commit()
    finally:
        conn.close()
    for p in plans:
        p["price_h"] = fmt_toman(int(p["price_toman"]))
        p["active"] = bool(int(p.get("active") or 0))
        p["unlimited"] = float(p.get("gib") or 0) <= 0
        p["volume_h"] = "نامحدود" if p["unlimited"] else f"{float(p['gib']):g} گیگ"
        uc = max(1, int(p.get("user_count") or 1))
        p["user_count"] = uc
        p["users_h"] = f"{uc} کاربره"
    pending_pub = []
    for o in pending:
        pub = _order_public(o)
        if pub:
            pending_pub.append(pub)
    sms = sms_settings()
    webhook = (
        f"https://panel.jetengine.ir:2096/settle/api/sms?token={seller_tok}"
    )
    # Never expose another admin's token; strip raw token from public shop dict copy
    shop_pub = dict(shop)
    shop_pub.pop("sms_webhook_token", None)
    return {
        "admin_id": admin_id,
        **shop_pub,
        "default_slogan": pay.DEFAULT_SLOGAN,
        "can_unlimited": int(admin_id) == pay.UNLIMITED_ADMIN_ID,
        "plans": plans,
        "pending_orders": pending_pub,
        "pay_url": "https://panel.jetengine.ir:2096/pay/",
        # Always include URL so radio preview works; UI only shows it in auto mode.
        "sms_webhook_url": webhook,
        "sms_webhook_token": seller_tok,
        "sms_enabled": sms.get("sms_enabled") == "1",
        "sms_senders": sms.get("sms_senders") or "B.QMEHRIRAN",
    }


def approve_pay_order(order_id: int, *, admin_id: int | None = None) -> dict:
    conn = db()
    try:
        row = pay.get_order(conn, order_id)
        if not row:
            raise ValueError("سفارش پیدا نشد.")
        if admin_id is not None and int(row["admin_id"]) != int(admin_id):
            raise ValueError("این سفارش مال شما نیست.")
        if row.get("status") != "pending":
            raise ValueError("سفارش در انتظار نیست.")
        out = pay.fulfill_order(conn, order_id)
    finally:
        conn.close()
    telegram_notify(
        "تأیید دستی سفارش /pay/\n"
        f"#{order_id} · {out.get('username')} · ادمین #{out.get('admin_id')}\n"
        f"{out.get('detail') or ''}"
    )
    return {"ok": True, "message": "سفارش تأیید و شارژ شد.", "order": _order_public(out)}


def reject_pay_order(order_id: int, *, admin_id: int | None = None) -> dict:
    conn = db()
    try:
        out = pay.reject_order(conn, order_id, admin_id=admin_id)
    finally:
        conn.close()
    return {"ok": True, "message": "سفارش رد شد.", "order": _order_public(out)}


def request_waive(admin_id: int, user_id: int, reason: str, requested_by: str) -> dict:
    info = build_rows(admin_id)
    hit = next((u for u in info["users"] if int(u["id"]) == int(user_id)), None)
    if not hit:
        raise ValueError("کاربر در دفترچهٔ این ادمین پیدا نشد.")
    used = int(hit.get("used") or 0)
    conn = db()
    try:
        if used <= 0:
            tr = conn.execute(
                "SELECT last_used FROM user_track WHERE admin_id=? AND user_id=?",
                (admin_id, user_id),
            ).fetchone()
            if tr:
                used = max(0, int(tr["last_used"] or 0))
        row = ledger.create_waive_request(
            conn,
            admin_id=admin_id,
            user_id=user_id,
            username=hit["username"],
            limit_bytes=hit["limit"],
            billed_bytes=hit["billed"],
            toman=hit["toman"],
            reason=reason,
            requested_by=requested_by,
            used_bytes=used,
        )
    finally:
        conn.close()
    used_h = fmt_gib(used) if used else "—"
    telegram_notify(
        "درخواست حذف بدون هزینه\n"
        f"ادمین: {info.get('admin_username')} (#{admin_id})\n"
        f"کاربر: {hit['username']} (id={user_id})\n"
        f"مصرف: {used_h} / سقف {hit.get('limit_h', '—')}\n"
        f"بدهی احتمالی: {hit['toman_h']} ({hit['delta_h']})\n"
        f"درخواست‌کننده: {requested_by}\n"
        f"دلیل: {(reason or '—')[:200]}\n"
        "تا ۴۸ ساعت در /settle/ → درخواست‌های حذف تأیید کنید."
    )
    return {"ok": True, "message": "درخواست ثبت شد؛ مدیر مطلع شد.", "request": row}


def decide_waive_request(request_id: int, approve: bool) -> dict:
    conn = db()
    try:
        def set_billed(aid: int, uid: int, limit: int) -> None:
            conn.execute(
                "INSERT INTO ledger(admin_id, user_id, billed_bytes) VALUES (?,?,?) "
                "ON CONFLICT(admin_id, user_id) DO UPDATE SET billed_bytes=excluded.billed_bytes",
                (aid, uid, limit),
            )

        row = ledger.decide_waive(conn, request_id=request_id, approve=approve, set_billed=set_billed)
    finally:
        conn.close()
    st = "تأیید شد — بدهی این یوزر بخشیده شد." if approve else "رد شد — بدهی همچنان حساب می‌شود."
    telegram_notify(
        f"نتیجه درخواست حذف بدون هزینه #{request_id}\n"
        f"کاربر: {row.get('username')} (id={row.get('user_id')})\n"
        f"ادمین #{row.get('admin_id')}\n{st}"
    )
    return {"ok": True, "message": st, "request": row}


def monthly_payload(months: int = 12, admin_id: int | None = None) -> dict:
    conn = db()
    try:
        data = ledger.monthly_sales(conn, months=months, admin_id=admin_id)
    finally:
        conn.close()
    # Enrich admin names
    names = {}
    try:
        for a in panel_query("SELECT id, username FROM admins"):
            names[as_int(a.get("id"))] = a.get("username") or ""
    except Exception:
        names = {}
    for m in data["months"]:
        # Reseller view: operator costs are not their expenses.
        if admin_id is not None:
            m["cost_toman"] = 0
            m["cost_note"] = ""
            m["profit_toman"] = int(m["sales_toman"])
        m["sales_h"] = fmt_toman(int(m["sales_toman"]))
        m["cost_h"] = fmt_toman(int(m["cost_toman"]))
        m["profit_h"] = fmt_toman(int(m["profit_toman"]))
        m["sales_bytes_h"] = fmt_gib(int(m["sales_bytes"]))
        m["waive_h"] = fmt_toman(int(m["waive_toman"]))
        m["year_month_fa"] = ledger.ym_label_fa(str(m["year_month"]))
        for ab in m.get("admins") or []:
            ab["username"] = names.get(int(ab["admin_id"]), f"#{ab['admin_id']}")
            ab["sales_h"] = fmt_toman(int(ab["sales_toman"]))
            ab["waive_h"] = fmt_toman(int(ab["waive_toman"]))
            ab["sales_bytes_h"] = fmt_gib(int(ab["sales_bytes"]))
    return data


def ym_to_jalali_label(ym: str) -> str:
    """Label for YYYY-MM (Jalali preferred; legacy Gregorian still accepted)."""
    return ledger.ym_label_fa(ym)


def _gregorian_to_jalali(gy: int, gm: int, gd: int) -> tuple[int, int, int]:
    return ledger.gregorian_to_jalali(gy, gm, gd)


def costs_payload() -> dict:
    conn = db()
    try:
        items = ledger.list_month_costs(conn)
    finally:
        conn.close()
    for it in items:
        it["amount_h"] = fmt_toman(int(it["amount_toman"]))
        it["year_month_fa"] = ledger.ym_label_fa(str(it["year_month"]))
    return {
        "items": items,
        "current_month": ledger.current_jalali_ym(),
    }


def save_cost(year_month: str, amount: int, note: str = "") -> dict:
    conn = db()
    try:
        row = ledger.add_month_cost(conn, year_month, amount, note)
    finally:
        conn.close()
    return {"ok": True, "message": "ردیف هزینه اضافه شد.", "item": row, **costs_payload()}


def edit_cost(item_id: int, *, amount: int | None = None, note: str | None = None, year_month: str | None = None) -> dict:
    conn = db()
    try:
        row = ledger.update_month_cost(
            conn, item_id, amount=amount, note=note, year_month=year_month
        )
    finally:
        conn.close()
    return {"ok": True, "message": "ردیف هزینه ویرایش شد.", "item": row, **costs_payload()}


def remove_cost(item_id: int) -> dict:
    conn = db()
    try:
        ledger.delete_month_cost(conn, item_id)
    finally:
        conn.close()
    return {"ok": True, "message": "ردیف هزینه حذف شد.", **costs_payload()}


def list_admins(*, scope_ids: list[int] | None = None) -> dict:
    admins = panel_query(
        "SELECT id, username, status, "
        "(SELECT COUNT(*) FROM users u WHERE u.admin_id = admins.id) AS n "
        "FROM admins ORDER BY id"
    )
    amap = agency_map()
    scope = set(int(x) for x in scope_ids) if scope_ids is not None else None
    flat: list[dict] = []
    by_id: dict[int, dict] = {}
    for a in admins:
        aid = as_int(a.get("id"))
        if scope is not None and aid not in scope:
            continue
        info = build_rows(aid, with_network=False)
        item = {
            "id": aid,
            "username": a.get("username") or "",
            "status": a.get("status") or "",
            "count": info["count"],
            "delta_h": info["delta_h"],
            "toman_h": info["toman_h"],
            "toman": info["toman"],
            "debt": info["debt"],
            "debt_h": info["debt_h"],
            "total": info["total"],
            "total_h": info["total_h"],
            "recharge": info["recharge"],
            "new": info["new"],
            "has_ledger": info["has_ledger"],
            "days": (info["last"] or {}).get("days"),
            "parent_id": amap.get(aid),
            "is_child": amap.get(aid) is not None,
            "children": [],
        }
        flat.append(item)
        by_id[aid] = item

    roots: list[dict] = []
    for item in flat:
        pid = item.get("parent_id")
        if pid and pid in by_id:
            by_id[pid]["children"].append(item)
        else:
            roots.append(item)

    parent_choices = [
        {"id": r["id"], "username": r["username"]}
        for r in flat
        if not r.get("parent_id") and r["id"] in by_id
    ]

    for root in roots:
        kids = root.get("children") or []
        root["is_parent"] = bool(kids)
        if not kids:
            root["network_total"] = root["total"]
            root["network_total_h"] = root["total_h"]
            root["network_toman"] = root["toman"]
            root["network_toman_h"] = root["toman_h"]
            continue
        nt = int(root["total"]) + sum(int(c["total"]) for c in kids)
        np_ = int(root["toman"]) + sum(int(c["toman"]) for c in kids)
        root["network_total"] = nt
        root["network_total_h"] = fmt_toman(nt)
        root["network_toman"] = np_
        root["network_toman_h"] = fmt_toman(np_)

    return {
        "admins": roots,
        "flat": flat,
        "parent_choices": parent_choices,
        "agency": {str(k): v for k, v in amap.items()},
    }


def do_settle_network(parent_id: int, kind: str, paid: int | None = None) -> dict:
    """Settle parent + all children; remaining debt stays on parent only."""
    if kind not in ("charge", "baseline"):
        raise ValueError("نوع تسویه نامعتبر است.")
    pid = int(parent_id)
    kids = children_of(pid)
    if not kids:
        return do_settle(pid, kind, paid=paid, network=False)
    members = [pid] + kids
    infos = {mid: build_rows(mid, with_network=False) for mid in members}
    net_period = sum(int(infos[m]["toman"]) for m in members)
    net_debt = sum(int(infos[m]["debt"]) for m in members)
    net_total = net_period + net_debt
    net_delta = sum(int(infos[m]["delta"]) for m in members)

    if kind == "baseline":
        last = None
        for mid in members:
            last = do_settle(mid, "baseline", network=False)
        out = build_rows(pid)
        out["message"] = (
            f"سقف شبکه بدون دریافت ثبت شد ({len(members)} ادمین: مدیر ارشد + {len(kids)} مدیر)."
        )
        out["ok"] = True
        return out

    if net_total <= 0 and (paid is None or int(paid) == 0):
        raise ValueError("مبلغی برای تسویه شبکه نیست (نه دوره و نه بدهی).")
    if paid is None:
        paid_amt = net_total
    else:
        try:
            paid_amt = int(paid)
        except (TypeError, ValueError) as e:
            raise ValueError("مبلغ دریافتی نامعتبر است.") from e
    if paid_amt < 0:
        raise ValueError("مبلغ دریافتی نمی‌تواند منفی باشد.")
    if paid_amt > net_total:
        raise ValueError(
            f"مبلغ دریافتی ({fmt_toman(paid_amt)}) بیشتر از جمع شبکه ({fmt_toman(net_total)}) است."
        )
    debt_after = net_total - paid_amt
    digits = as_int(sms_settings().get("sms_suffix_digits"), 3)
    mod = 10 ** max(1, min(6, digits))
    if paid_amt == unique_pay_amount(net_total, pid, digits) and 0 < debt_after < mod:
        debt_after = 0

    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        for mid in members:
            info = infos[mid]
            items = [r for r in info["users"] if r["delta"] > 0]
            is_parent = mid == pid
            note = (
                f"تسویه شبکه · دوره {fmt_toman(net_period)} + بدهی {fmt_toman(net_debt)} "
                f"= {fmt_toman(net_total)} · دریافتی {fmt_toman(paid_amt)}"
                + (f" · مانده روی والد {fmt_toman(debt_after)}" if debt_after and is_parent else "")
            )
            if not is_parent:
                note = f"تسویه شبکه زیر مدیر ارشد #{pid} · فروش دوره {fmt_toman(int(info['toman']))}"
            conn.execute(
                "INSERT INTO settlement(admin_id, ts, kind, delta_bytes, toman, users, note) "
                "VALUES (?,?,?,?,?,?,?)",
                (
                    mid,
                    time.time(),
                    "charge",
                    int(info["delta"]) if is_parent else int(info["delta"]),
                    paid_amt if is_parent else 0,
                    len(items),
                    note,
                ),
            )
            sid = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
            for r in info["users"]:
                if r["delta"] <= 0:
                    continue
                conn.execute(
                    "INSERT INTO settlement_item(settlement_id, user_id, username, prev_billed, new_limit, delta) "
                    "VALUES (?,?,?,?,?,?)",
                    (sid, r["id"], r["username"], r["billed"], r["limit"], r["delta"]),
                )
                conn.execute(
                    "INSERT INTO ledger(admin_id, user_id, billed_bytes) VALUES (?,?,?) "
                    "ON CONFLICT(admin_id, user_id) DO UPDATE SET billed_bytes=excluded.billed_bytes",
                    (mid, r["id"], r["limit"]),
                )
            # Remaining network debt only on parent; children cleared.
            new_debt = debt_after if is_parent else 0
            conn.execute(
                "INSERT INTO seller(admin_id, price, debt_toman) VALUES(?,?,?) "
                "ON CONFLICT(admin_id) DO UPDATE SET debt_toman=excluded.debt_toman",
                (mid, info["price"], new_debt),
            )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()

    out = build_rows(pid)
    if debt_after > 0:
        msg = (
            f"تسویه شبکه ثبت شد: دریافتی {fmt_toman(paid_amt)} از {fmt_toman(net_total)}. "
            f"مانده بدهی روی مدیر ارشد: {fmt_toman(debt_after)}"
        )
    else:
        msg = f"تسویه کامل شبکه ثبت شد: {fmt_toman(paid_amt)} ({len(kids)} مدیر + خودش)"
    out["ok"] = True
    out["message"] = msg
    out["network_settled"] = {
        "members": members,
        "paid": paid_amt,
        "total": net_total,
        "delta": net_delta,
    }
    return out


def do_settle(admin_id: int, kind: str, paid: int | None = None, *, network: bool | None = None) -> dict:
    if kind not in ("charge", "baseline"):
        raise ValueError("نوع تسویه نامعتبر است.")
    # پیش‌فرض: اگر زیرمجموعه دارد، تسویه شبکه (طرف‌حساب = ادمین اصلی)
    if network is None:
        network = bool(children_of(admin_id))
    if network and children_of(admin_id):
        return do_settle_network(admin_id, kind, paid=paid)
    if parent_of(admin_id) is not None and network is False:
        # تسویه تکی زیرمجموعه فقط وقتی صریح network=false و اپراتور بخواهد
        pass
    info = build_rows(admin_id, with_network=False)
    debt_before = int(info["debt"])
    period = int(info["toman"])
    total_due = int(info["total"])
    items = [r for r in info["users"] if r["delta"] > 0] if kind == "charge" else list(info["users"])
    delta = info["delta"] if kind == "charge" else 0

    if kind == "baseline":
        paid_amt = 0
        debt_after = debt_before
        note = "سقف فعلی بدون دریافت ثبت شد؛ بدهی قبلی دست نخورده ماند."
        users_n = info["count"]
    else:
        if total_due <= 0 and (paid is None or int(paid) == 0):
            raise ValueError("مبلغی برای تسویه نیست (نه دوره و نه بدهی).")
        if paid is None:
            paid_amt = total_due
        else:
            try:
                paid_amt = int(paid)
            except (TypeError, ValueError) as e:
                raise ValueError("مبلغ دریافتی نامعتبر است.") from e
        if paid_amt < 0:
            raise ValueError("مبلغ دریافتی نمی‌تواند منفی باشد.")
        if paid_amt > total_due:
            raise ValueError(
                f"مبلغ دریافتی ({fmt_toman(paid_amt)}) بیشتر از جمع بدهی ({fmt_toman(total_due)}) است."
            )
        debt_after = total_due - paid_amt
        # مبلغ یکتا معمولاً چند صد تومان کمتر از مجموع است؛ همان مانده را صفر می‌کنیم تا پنل «تسویه» نشان دهد.
        digits = as_int(sms_settings().get("sms_suffix_digits"), 3)
        mod = 10 ** max(1, min(6, digits))
        if paid_amt == unique_pay_amount(total_due, admin_id, digits) and 0 < debt_after < mod:
            debt_after = 0
        if debt_after > 0:
            note = (
                f"دوره {fmt_toman(period)} + بدهی قبلی {fmt_toman(debt_before)} "
                f"= {fmt_toman(total_due)} · دریافتی {fmt_toman(paid_amt)} · "
                f"بدهی باقی‌مانده {fmt_toman(debt_after)}"
            )
        elif debt_before > 0 or paid_amt < total_due:
            note = (
                f"دوره {fmt_toman(period)} + بدهی قبلی {fmt_toman(debt_before)} "
                f"= {fmt_toman(total_due)} · تمام پرداخت شد ({fmt_toman(paid_amt)})"
            )
        else:
            note = f"تسویه کامل دوره: {fmt_toman(period)}"
        users_n = len(items) if info["delta"] > 0 else 0

    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO settlement(admin_id, ts, kind, delta_bytes, toman, users, note) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                admin_id,
                time.time(),
                kind,
                delta,
                paid_amt if kind == "charge" else 0,
                users_n,
                note,
            ),
        )
        sid = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        for r in info["users"]:
            uid = r["id"]
            limit = r["limit"]
            prev = r["billed"]
            dlt = r["delta"]
            if kind == "charge" and dlt <= 0:
                continue
            conn.execute(
                "INSERT INTO settlement_item(settlement_id, user_id, username, prev_billed, new_limit, delta) "
                "VALUES (?,?,?,?,?,?)",
                (sid, uid, r["username"], prev, limit, dlt if kind == "charge" else 0),
            )
            conn.execute(
                "INSERT INTO ledger(admin_id, user_id, billed_bytes) VALUES (?,?,?) "
                "ON CONFLICT(admin_id, user_id) DO UPDATE SET billed_bytes=excluded.billed_bytes",
                (admin_id, uid, limit),
            )
        if kind == "charge":
            conn.execute(
                "INSERT INTO seller(admin_id, price, debt_toman) VALUES(?,?,?) "
                "ON CONFLICT(admin_id) DO UPDATE SET debt_toman=excluded.debt_toman",
                (admin_id, info["price"], debt_after),
            )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
    if kind == "baseline":
        msg = f"سقف فعلی بدون دریافت ثبت شد ({info['count']} کاربر). از این به بعد فقط افزایش سقف حساب می‌شود."
    elif debt_after > 0:
        msg = (
            f"تسویه ثبت شد: دریافتی {fmt_toman(paid_amt)} از {fmt_toman(total_due)}. "
            f"بدهی باقی‌مانده: {fmt_toman(debt_after)}"
        )
    else:
        msg = f"تسویه کامل ثبت شد: {fmt_toman(paid_amt)}"
    return {"ok": True, "message": msg, **build_rows(admin_id)}


def history_payload(admin_id: int) -> dict:
    conn = db()
    try:
        rows = conn.execute(
            "SELECT id, ts, kind, delta_bytes, toman, users, note FROM settlement "
            "WHERE admin_id=? ORDER BY ts DESC LIMIT 40",
            (admin_id,),
        ).fetchall()
        items = []
        for r in rows:
            items.append(
                {
                    "id": r["id"],
                    "ts": r["ts"],
                    "kind": r["kind"],
                    "delta_h": fmt_gib(int(r["delta_bytes"])),
                    "toman": int(r["toman"]),
                    "toman_h": fmt_toman(int(r["toman"])),
                    "users": int(r["users"]),
                    "note": r["note"] or "",
                }
            )
        return {"admin_id": admin_id, "items": items}
    finally:
        conn.close()


LOGIN_HTML = """<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>تسویه فروش</title>
<style>
@font-face{
  font-family:'IRANYekanX';
  src:url('static/IRANYekanX-Medium.woff2') format('woff2');
  font-weight:500;font-style:normal;font-display:swap;
}
:root { --bg:#0b1220; --card:#152036; --line:#243656; --txt:#e8eef9; --mut:#8aa0c2; }
* { box-sizing:border-box; }
body { margin:0; min-height:100vh; font-family:'IRANYekanX',Tahoma,sans-serif; background:radial-gradient(1200px 500px at 80% -10%, #3b2a14 0%, var(--bg) 55%); color:var(--txt); display:flex; align-items:center; justify-content:center; }
form { width:min(420px,92vw); background:var(--card); border:1px solid var(--line); border-radius:18px; padding:28px 24px 22px; box-shadow:0 20px 50px #0007; }
h1 { margin:0 0 6px; font-size:22px; font-weight:500; }
p { margin:0 0 18px; color:var(--mut); font-size:13px; line-height:1.7; }
label { display:block; font-size:12px; color:var(--mut); margin:12px 0 6px; }
input,button { font-family:inherit; }
input { width:100%; padding:11px 12px; border-radius:10px; border:1px solid var(--line); background:#0d1728; color:var(--txt); font-size:15px; }
button { width:100%; margin-top:18px; padding:12px; border:0; border-radius:11px; background:linear-gradient(180deg,#fbbf24,#d97706); color:#1c1005; font-weight:700; cursor:pointer; }
.err { background:#3f1d2a; color:#fecdd3; padding:8px 10px; border-radius:8px; margin-bottom:12px; font-size:13px; }
</style>
</head>
<body>
<form method="post" action="login">
<h1>تسویه فروش</h1>
<p>سامانه تسویه حساب روتیت</p>
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
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>تسویه فروش</title>
<style>
@font-face{
  font-family:'IRANYekanX';
  src:url('static/IRANYekanX-Medium.woff2') format('woff2');
  font-weight:500;font-style:normal;font-display:swap;
}
:root {
  --bg:#0b1220; --card:#121c2f; --line:#2a3a55; --txt:#e8eef9; --mut:#94a3b8;
  --ok:#34d399; --side:#0e1728; --accent:#c4a574; --accent-dim:#3a3226;
  --pay:#0f2a22; --pay-line:#2d6a56; --pay-txt:#b7ebc7;
}
* { box-sizing:border-box; }
html { -webkit-text-size-adjust:100%; overflow-x:hidden; max-width:100%; }
body { margin:0; font-family:'IRANYekanX',Tahoma,sans-serif; background:var(--bg); color:var(--txt); padding-bottom:env(safe-area-inset-bottom); overflow-x:hidden; max-width:100vw; }
select, textarea { font-family:inherit; }
.shell { display:grid; grid-template-columns:240px 1fr; min-height:100vh; min-width:0; max-width:100%; }
.work { min-width:0; max-width:100%; overflow-x:hidden; }
aside.menu { background:var(--side); border-left:1px solid var(--line); padding:18px 12px; position:relative; height:auto; }
.app-bar {
  display:none; align-items:center; gap:10px; flex-direction:row; flex-wrap:nowrap;
}
.menu-backdrop { display:none; }
.shop-row {
  display:grid; gap:10px 12px; align-items:end;
  grid-template-columns:repeat(auto-fit, minmax(140px, 1fr));
}
.shop-row label.hint { min-width:0; max-width:100%; display:flex; flex-direction:column; gap:6px; margin:0; }
.shop-row label.hint input,
.shop-row label.hint textarea {
  width:100% !important; max-width:100%; min-width:0; box-sizing:border-box; display:block; margin:0 !important;
}
.shop-row .shop-row-btn { align-self:end; }
.shop-row-card { grid-template-columns:minmax(0, 1.1fr) minmax(0, 1fr); }
.shop-row-plan { grid-template-columns:repeat(auto-fit, minmax(110px, 1fr)); }
.shop-row-plan .shop-plan-title { grid-column:1 / -1; }
.shop-row-plan .shop-plan-price { grid-column:span 2; }
.shop-row-plan .shop-row-btn { grid-column:1 / -1; width:100%; }
.brand { font-weight:800; padding:8px 12px 16px; font-size:16px; line-height:1.35; min-width:0; }
.brand #brand-name, .brand .brand-name {
  display:block; font-weight:800; color:var(--txt);
  overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:100%;
}
.brand #brand-sub, .brand .brand-sub { display:block; color:var(--mut); font-weight:400; font-size:11px; margin-top:4px; }
.mi { display:block; padding:10px 12px; border-radius:10px; color:var(--txt); text-decoration:none; margin-bottom:6px; }
.mi:hover { background:#18263d; }
.mi.active { background:#b45309; color:#fff7ed; }
.icon-btn {
  display:inline-flex; align-items:center; justify-content:center;
  width:40px; height:40px; padding:0; border-radius:10px;
  background:transparent; color:var(--mut); border:1px solid var(--line); cursor:pointer; flex:0 0 auto;
}
.icon-btn:hover { background:#18263d; color:var(--txt); }
.icon-btn svg { width:18px; height:18px; display:block; }
.logout-form { display:inline-flex; margin:0; }
.menu-logout { margin-top:14px; padding-top:12px; border-top:1px solid var(--line); }
.menu-logout .logout-form { width:100%; }
.menu-logout .icon-btn { width:100%; height:42px; gap:8px; font-size:13px; font-weight:700; color:#cbd5e1; }
.menu-logout .icon-btn span { display:inline; }
.st { display:inline-flex; align-items:center; gap:7px; white-space:nowrap; }
.st i {
  width:9px; height:9px; border-radius:50%; flex:0 0 auto;
  background:#64748b; box-shadow:0 0 0 3px rgba(100,116,139,.22);
}
.st .st-t { font-size:12px; color:var(--mut); }
.st-on i { background:#34d399; box-shadow:0 0 0 3px rgba(52,211,153,.22); }
.st-on .st-t { color:#a7f3d0; }
.st-off i { background:#f87171; box-shadow:0 0 0 3px rgba(248,113,113,.22); }
.st-off .st-t { color:#fecaca; }
.st-exp i { background:#fbbf24; box-shadow:0 0 0 3px rgba(251,191,36,.22); }
.st-exp .st-t { color:#fde68a; }
.st-lim i { background:#60a5fa; box-shadow:0 0 0 3px rgba(96,165,250,.22); }
.st-lim .st-t { color:#bfdbfe; }
.st-hold i { background:#a78bfa; box-shadow:0 0 0 3px rgba(167,139,250,.22); }
.st-hold .st-t { color:#ddd6fe; }
.st-del i { background:#94a3b8; box-shadow:0 0 0 3px rgba(148,163,184,.22); }
.st-unk i { background:#64748b; }
header { display:flex; justify-content:space-between; align-items:flex-start; gap:16px; padding:16px 22px; border-bottom:1px solid var(--line); background:var(--bg); flex-wrap:wrap; position:static; }
.actions { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
/* موبایل display:flex روی label را از [hidden] قوی‌تر می‌کند — بدون این، فیلد قیمت حساب خودِ ارشد دیده می‌شود */
[hidden] { display: none !important; }
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
.hint { color:var(--mut); font-size:12px; line-height:1.7; }
input { padding:9px 10px; border-radius:9px; border:1px solid var(--line); background:#0d1728; color:var(--txt); font-family:inherit; font-size:16px; }
button { border:0; border-radius:9px; padding:9px 12px; cursor:pointer; font-weight:700; font-family:inherit; font-size:14px; }
.btn { background:#b45309; color:#fff7ed; }
.ghost { background:transparent; color:var(--mut); border:1px solid var(--line); }
.danger { background:#7f1d1d; color:#fecaca; }
.kpi { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; min-width:0; }
.kpi div { background:#0d1728; border:1px solid var(--line); border-radius:12px; padding:12px; min-width:0; overflow:hidden; }
.kpi b { display:block; font-size:18px; margin-top:4px; overflow-wrap:anywhere; word-break:break-word; }
.kpi .hi { border-color:#5b4a32; background:var(--accent-dim); }
.item { display:flex; justify-content:space-between; gap:12px; align-items:flex-start; padding:12px 0; border-bottom:1px solid #1c2a44; text-decoration:none; color:inherit; min-width:0; }
.item:last-child { border:0; }
.item .item-side { text-align:left; flex:0 0 auto; max-width:42%; }
.item .item-side b { font-size:13px; font-weight:600; color:var(--mut); }
.item .item-side .mut { font-size:11px; margin-top:2px; }
.item .mut { font-size:10px; line-height:1.5; letter-spacing:-0.01em; }
.agency-block { border:1px solid var(--line); border-radius:14px; padding:10px 12px; margin-bottom:12px; background:#0d1728; min-width:0; }
.agency-block > .item { border-bottom:0; padding-bottom:8px; }
.agency-kids { margin:4px 8px 0 0; padding:8px 10px; border-right:3px solid var(--accent); background:#121c2f; border-radius:10px; }
.agency-kids .item { padding:10px 0; }
.agency-meta { display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin-top:8px; }
.agency-meta select { max-width:220px; font-size:13px; }
.pill.agency { background:var(--accent-dim); color:var(--accent); }
.pill.child { background:#1e293b; color:#cbd5e1; }
.net-card { border-color:#3a4558; background:#101827; }
.rank-card {
  display:none;
  position:relative;
  overflow:hidden;
  background:linear-gradient(145deg, #151c2a 0%, #121c2f 60%, #0e1728 100%);
  border:1px solid #3a4558;
  border-radius:16px;
  padding:16px 18px;
  margin-bottom:4px;
}
.rank-card.on { display:block; }
.rank-card::before {
  content:"";
  position:absolute; inset:0 auto 0 0; width:3px;
  background:linear-gradient(180deg, var(--accent), #5b4a32);
}
.rank-eyebrow {
  font-size:11px; letter-spacing:.04em; color:var(--accent);
  margin:0 0 10px; font-weight:700;
}
.rank-tree { display:flex; flex-direction:column; gap:0; }
.rank-node {
  display:flex; align-items:center; gap:12px;
  padding:10px 12px; border-radius:12px;
  background:#0d1728cc; border:1px solid var(--line); min-width:0;
}
.rank-node.senior {
  border-color:#5b4a32;
  background:linear-gradient(90deg, var(--accent-dim), #0d1728cc);
}
.rank-node.you { border-style:dashed; }
.rank-avatar {
  width:42px; height:42px; border-radius:12px; flex:0 0 auto;
  display:grid; place-items:center;
  font-weight:800; font-size:15px; color:#f5efe6;
  background:linear-gradient(145deg, #8a7350, #5b4a32);
  border:1px solid #c4a57466;
}
.rank-node.you .rank-avatar {
  background:linear-gradient(145deg, #334155, #1e293b);
  border-color:#64748b88; color:#e2e8f0;
}
.rank-meta { min-width:0; flex:1; }
.rank-meta b { display:block; font-size:15px; word-break:break-word; }
.rank-meta span { display:block; color:var(--mut); font-size:11px; margin-top:3px; }
.rank-badge {
  font-size:11px; padding:4px 10px; border-radius:999px; white-space:nowrap;
  background:var(--accent-dim); color:var(--accent); border:1px solid #5b4a32;
}
.rank-node.you .rank-badge { background:#1e293b; color:#cbd5e1; border-color:#334155; }
.rank-link {
  width:2px; height:14px; margin:2px 32px 2px auto;
  background:linear-gradient(180deg, var(--accent), #475569);
  border-radius:2px; opacity:.85;
}
.rank-foot {
  margin:12px 0 0; color:var(--mut); font-size:12px; line-height:1.7;
}
.rank-foot b { color:var(--accent); font-weight:700; }
.brand .rank-mini {
  display:none; margin-top:8px; padding:8px 10px; border-radius:10px;
  background:var(--accent-dim); border:1px solid #5b4a32; font-size:11px; line-height:1.55;
  color:var(--accent); font-weight:400;
}
body.ro.child .brand .rank-mini,
body.ro.parent .brand .rank-mini { display:block; }
.brand .rank-mini b { color:#f5efe6; font-weight:700; }
.pill { font-size:11px; padding:2px 8px; border-radius:999px; white-space:nowrap; }
.new { background:#1e3a8a; color:#bfdbfe; }
.recharge { background:#7c2d12; color:#fed7aa; }
.unchanged { background:#1e293b; color:#94a3b8; }
.mut { color:var(--mut); }
.empty { color:var(--mut); padding:24px 8px; text-align:center; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th, td { border-bottom:1px solid #1c2a44; padding:8px 6px; text-align:right; }
th { color:var(--mut); font-weight:700; }
.num { font-variant-numeric:tabular-nums; white-space:nowrap; }
.table-wrap { overflow-x:auto; -webkit-overflow-scrolling:touch; margin:0; max-width:100%; }
.table-wrap table { min-width:0; width:100%; }
@media (max-width:720px) {
  .table-wrap { overflow-x:auto; -webkit-overflow-scrolling:touch; }
  .table-wrap table { font-size:12px; }
  /* جدول کاربران: اسکرول افقی به‌جای فشردن ستون‌ها */
  .table-wrap.users-mobile table { min-width:640px; }
  .table-wrap.users-mobile th,
  .table-wrap.users-mobile td { white-space:nowrap; padding:8px 10px; }
  .table-wrap.users-mobile .num { white-space:nowrap; overflow-wrap:normal; }
  .table-wrap.hist-mobile table { min-width:480px; }
  .table-wrap.hist-mobile th:nth-child(3),
  .table-wrap.hist-mobile td:nth-child(3),
  .table-wrap.hist-mobile th:nth-child(5),
  .table-wrap.hist-mobile td:nth-child(5) { display:none; }
}
.docs { padding:20px 28px 48px; max-width:900px; line-height:1.85; }
.docs h2 { font-size:17px; margin:28px 0 10px; padding-top:8px; border-top:1px solid var(--line); }
.docs p, .docs li { color:#dbe4f3; font-size:14px; }
.docs ul { padding-right:20px; }
.callout { background:var(--accent-dim); border:1px solid #5b4a32; border-radius:14px; padding:14px 16px; }
body.ro .op-only, body:not(.ro) .ro-only { display:none !important; }
.pay-box { display:none; background:var(--pay); border:1px solid var(--pay-line); border-radius:12px; padding:12px 14px; margin-bottom:8px; }
body.ro .pay-box.on { display:block; }
.pay-box .label { color:var(--pay-txt); font-size:11px; font-weight:700; }
.pay-box .pay-amts { display:flex; flex-wrap:wrap; align-items:baseline; gap:6px 14px; margin-top:4px; min-width:0; }
.pay-box .amt { font-size:18px; font-weight:800; margin:0; letter-spacing:-0.02em; color:#ecfdf5; overflow-wrap:anywhere; }
.pay-box .amt-rial { display:inline !important; font-size:14px; font-weight:600; margin:0; color:#a7f3d0; line-height:1.3; opacity:.9; overflow-wrap:anywhere; }
.pay-box .hint { margin-top:6px; color:#86efac; font-size:11px; line-height:1.5; }
.ok-box { display:none; background:#0f2a22; border:1px solid var(--pay-line); color:#a7f3d0; border-radius:14px; padding:14px 16px; margin-bottom:8px; line-height:1.8; font-size:14px; }
.ok-box.on { display:block; }
.ok-box b { color:#ecfdf5; }
.kpi .ok { border-color:var(--pay-line); background:#0f2a22; }
.ghost { color:#cbd5e1; border-color:#334155; }
.btn { background:#8a7350; color:#f5efe6; }
.mi.active { background:#5b4a32; color:#f5efe6; }
@media (max-width:1100px) {
  .shell { grid-template-columns:1fr; width:100%; }
  .app-bar {
    display:flex !important; flex-direction:row !important; flex-wrap:nowrap !important;
    align-items:center; justify-content:space-between; gap:10px;
    position:sticky; top:0; z-index:40;
    padding:10px 12px;
    padding-top:max(10px, env(safe-area-inset-top, 0px));
    background:var(--side); border-bottom:1px solid var(--line);
  }
  .app-bar .brand {
    padding:0; flex:1 1 auto; min-width:0; max-width:none; font-size:14px; margin:0;
    text-align:right;
  }
  .app-bar .brand-sub { display:block !important; font-size:10px; margin-top:2px; }
  .app-bar .rank-mini { display:none !important; }
  .app-bar .icon-btn { flex:0 0 auto; }
  .menu-backdrop {
    display:none; position:fixed; inset:0; z-index:50;
    background:rgba(2,6,23,.55); backdrop-filter:blur(2px);
  }
  .menu-backdrop.on { display:block; }
  aside.menu {
    position:fixed; top:0; right:0; bottom:0; z-index:60;
    width:min(300px, 86vw); max-width:100%;
    display:flex; flex-direction:column; align-items:stretch; gap:4px;
    padding:18px 14px; padding-top:max(18px, env(safe-area-inset-top, 0px));
    border:0; border-left:1px solid var(--line);
    overflow-x:hidden; overflow-y:auto; -webkit-overflow-scrolling:touch;
    transform:translateX(105%); transition:transform .22s ease;
    box-shadow:-12px 0 40px rgba(0,0,0,.35);
  }
  aside.menu.open { transform:translateX(0); }
  aside.menu .brand { display:none; }
  aside.menu .mi {
    margin:0; padding:12px 14px; font-size:14px; white-space:nowrap;
    width:100%; background:#152036; border:1px solid var(--line);
  }
  .menu-logout { margin-top:auto; }
  body.menu-open { overflow:hidden; }
  /* خروج در app-bar هست؛ از هدر صفحات تکرار نشود */
  .work header .logout-form { display:none !important; }
  .kpi { grid-template-columns:1fr 1fr; }
  body.ro aside.menu #nav-waives { display:none; }
}
@media (max-width:720px) {
  .work header {
    flex-direction:column; align-items:stretch; padding:10px 12px; gap:8px; max-width:100%;
  }
  .work header > div:first-child { min-width:0; max-width:100%; }
  .shop-row, .shop-row-card, .shop-row-plan { grid-template-columns:1fr 1fr; }
  .shop-row-card label.hint,
  .shop-row-plan .shop-plan-title,
  .shop-row-plan .shop-plan-price,
  .shop-row-plan .shop-row-btn,
  .shop-row-plan #shop-unlim-wrap { grid-column:1 / -1; }
  .card { overflow-x:clip; }
  h1 { font-size:15px; line-height:1.4; word-break:break-word; overflow-wrap:anywhere; }
  .sub { font-size:11px; line-height:1.55; display:-webkit-box; -webkit-line-clamp:2; -webkit-box-orient:vertical; overflow:hidden; }
  .actions {
    width:100%; max-width:100%; gap:8px; display:grid;
    grid-template-columns:1fr 1fr; align-items:stretch;
  }
  .actions .ghost, .actions .btn, .actions a.ghost, .actions form {
    flex:none; width:100%; min-width:0; margin:0;
  }
  .actions form.logout-form { width:auto; justify-self:start; }
  .actions .icon-btn.logout-btn { width:40px; height:40px; min-height:40px; padding:0; }
  .actions form { display:contents; }
  .actions form.logout-form { display:inline-flex; }
  .actions form button { width:100%; }
  .actions button, .actions a.ghost {
    width:100%; text-align:center; min-height:40px; padding:8px 10px; font-size:13px;
  }
  .actions label.hint {
    grid-column:1 / -1; display:flex; align-items:center; justify-content:space-between;
    gap:8px; margin:0; min-width:0;
  }
  .actions label.hint input { flex:1; width:auto !important; min-width:0; max-width:none; }
  body.ro .actions { grid-template-columns:1fr 1fr; }
  .pad { padding:10px; gap:10px; max-width:100%; min-width:0; }
  .card { padding:12px; border-radius:12px; max-width:100%; min-width:0; overflow:visible; }
  .card .table-wrap { margin-inline:-4px; padding-bottom:4px; }
  .kpi, #network-kpi, #kpi {
    grid-template-columns:1fr !important; gap:8px; width:100%;
  }
  body.ro .kpi div:nth-child(4) { display:none; }
  .kpi div { padding:10px 12px; }
  .kpi b { font-size:15px; }
  .kpi .mut { font-size:11px; }
  .item { flex-direction:column; gap:4px; padding:10px 0; }
  .item > div { min-width:0; max-width:100%; }
  .item .item-side {
    max-width:100%; width:100%; text-align:right;
    display:flex; justify-content:flex-start; align-items:baseline; gap:8px;
  }
  .item .item-side b { font-size:12px; }
  .item .mut { font-size:9.5px; line-height:1.45; }
  .item b { overflow-wrap:anywhere; }
  .flash { margin:8px 10px 0; font-size:12px; }
  .docs { padding:14px 16px 40px; }
  .table-wrap { max-width:100%; }
  th, td { padding:8px 8px; }
  .agency-block { padding:8px; margin-bottom:8px; border-radius:12px; }
  .agency-kids { margin:2px 0 0; padding:6px 8px; }
  .agency-meta { width:100%; }
  .agency-meta select { max-width:none; flex:1 1 140px; min-width:0; }
  .net-card { padding:12px; }
  .net-card h2 { font-size:14px; margin-bottom:8px; color:var(--accent); }
  .pay-box { padding:12px; border-radius:12px; max-width:100%; }
  .pay-box .amt { font-size:17px; }
  .pay-box .amt-rial { font-size:13px; }
  .pay-box .hint { font-size:11px; margin-top:6px; }
  .pill { font-size:10px; padding:2px 6px; }
  .rank-card { padding:12px; border-radius:14px; max-width:100%; }
  .rank-node { padding:9px 10px; gap:10px; }
  .rank-avatar { width:36px; height:36px; font-size:13px; border-radius:10px; }
  .rank-meta b { font-size:14px; }
  .rank-link { margin-right:27px; }
  .rank-badge { font-size:10px; padding:3px 8px; }
  .st .st-t { font-size:11px; }
}
@media (max-width:420px) {
  .actions { grid-template-columns:1fr; }
}
</style>
</head>
<body>
<div class="shell">
<header class="app-bar" id="app-bar">
  <button type="button" class="icon-btn" id="menu-toggle" aria-label="منو" title="منو">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16"/></svg>
  </button>
  <div class="brand">
    <span class="brand-name" id="brand-name">تسویه فروش</span>
    <span class="brand-sub" id="brand-sub">تسویه فروش</span>
    <div class="rank-mini" id="brand-rank"></div>
  </div>
  <form class="logout-form" method="post" action="logout">
    <button class="icon-btn logout-btn" type="submit" title="خروج" aria-label="خروج">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 6H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h4"/><path d="M14 16l4-4-4-4"/><path d="M18 12H9"/></svg>
    </button>
  </form>
</header>
<aside class="menu" id="side-menu">
  <div class="brand side-brand">
    <span class="brand-name" id="side-brand-name">تسویه فروش</span>
    <span class="brand-sub" id="side-brand-sub">تسویه فروش</span>
    <div class="rank-mini" id="side-brand-rank"></div>
  </div>
  <a class="mi" id="nav-home" href=".">ادمین‌ها</a>
  <a class="mi" id="nav-monthly" href="monthly">فروش ماهانه</a>
  <a class="mi" id="nav-shop" href="shop">فروش به مشتری</a>
  <a class="mi op-only" id="nav-costs" href="costs">هزینه و سود</a>
  <a class="mi" id="nav-waives" href="waives">حذف بدون هزینه</a>
  <a class="mi op-only" id="nav-settings" href="settings">تنظیمات پیامک</a>
  <a class="mi op-only" id="nav-docs" href="docs">مستندات</a>
  <div class="menu-logout">
    <form class="logout-form" method="post" action="logout">
      <button class="icon-btn logout-btn" type="submit" title="خروج" aria-label="خروج">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 6H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h4"/><path d="M14 16l4-4-4-4"/><path d="M18 12H9"/></svg>
        <span>خروج</span>
      </button>
    </form>
  </div>
</aside>
<div class="menu-backdrop" id="menu-backdrop" hidden></div>
<div class="work">
<div id="flash" class="flash"></div>

<div id="page-home">
<header>
  <div>
    <h1 id="home-title">ادمین‌های پنل</h1>
    <div class="sub" id="home-sub">هر ادمین PasarGuard یک فروشنده است. مبلغ = افزایش سقف از آخرین تسویه × قیمت هر گیگ. مدیران با مدیر ارشد تسویه می‌کنند؛ شما فقط با مدیر ارشد.</div>
  </div>
  <div class="actions">
    <form class="logout-form" method="post" action="logout">
      <button class="icon-btn logout-btn" type="submit" title="خروج" aria-label="خروج">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 6H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h4"/><path d="M14 16l4-4-4-4"/><path d="M18 12H9"/></svg>
      </button>
    </form>
  </div>
</header>
<div class="pad"><section class="card" id="admins"></section></div>
</div>

<div id="page-admin" hidden>
<header>
  <div>
    <h1 id="admin-title">فروشنده</h1>
    <div class="sub" id="admin-sub"></div>
  </div>
  <div class="actions">
    <label class="hint price-edit" id="price-wrap" hidden>تومان / گیگ <input id="price" type="number" min="1" step="1" style="width:110px"></label>
    <button class="ghost price-edit" id="save-price" type="button" hidden>ذخیره قیمت</button>
    <button class="ghost" id="report-copy" type="button">کپی گزارش فروش</button>
    <button class="ghost" id="report-dl" type="button">دانلود گزارش</button>
    <button class="ghost op-only" id="baseline" type="button">بدون دریافت ثبت کن</button>
    <label class="hint op-only">دریافتی (تومان) <input id="paid" type="number" min="0" step="1000" style="width:130px" title="اگر کمتر از مجموع بدهی بزنید، مانده بدهی می‌ماند"></label>
    <button class="btn op-only" id="charge" type="button">ثبت تسویه</button>
    <a class="ghost op-only" href="." style="text-decoration:none;display:inline-block;padding:9px 12px">بازگشت</a>
    <a class="ghost ro-only" id="back-network" href="." style="text-decoration:none;display:none;padding:9px 12px">بازگشت</a>
    <form class="logout-form" method="post" action="logout">
      <button class="icon-btn logout-btn" type="submit" title="خروج" aria-label="خروج">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 6H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h4"/><path d="M14 16l4-4-4-4"/><path d="M18 12H9"/></svg>
      </button>
    </form>
  </div>
</header>
<div class="pad">
  <section class="rank-card" id="rank-card" aria-label="سلسله‌مراتب نمایندگی">
    <div class="rank-eyebrow">سلسله‌مراتب نمایندگی</div>
    <div class="rank-tree" id="rank-tree"></div>
    <p class="rank-foot" id="rank-foot"></p>
  </section>
  <div class="pay-box" id="pay-box">
    <div class="label">مبلغ دقیق کارت‌به‌کارت</div>
    <div class="pay-amts">
      <div class="amt" id="pay-amt">—</div>
      <div class="amt-rial" id="pay-rial">—</div>
    </div>
    <div class="hint" id="pay-hint">لطفا دقیقا مبلغ درج شده را واریز بفرمایید تا خودکار ثبت شود</div>
  </div>
  <div class="ok-box" id="ok-box"></div>
  <div class="kpi" id="kpi"></div>
  <section class="card net-card" id="network-box" hidden>
    <h2>شبکه نمایندگی</h2>
    <div class="kpi" id="network-kpi" style="margin-top:10px"></div>
    <div id="network-members" style="margin-top:12px"></div>
  </section>
  <section class="card">
    <div id="banner"></div>
    <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:8px">
      <h2 style="margin:0">کاربران این دوره</h2>
      <label class="hint" style="display:flex;align-items:center;gap:6px;cursor:pointer">
        <input type="checkbox" id="only-delta" checked> فقط جدید و شارژ مجدد
      </label>
    </div>
    <div id="utable"></div>
  </section>
  <section class="card"><h2>تاریخچه تسویه</h2><div id="hist"></div></section>
</div>
</div>

<div id="page-monthly" hidden>
<header>
  <div>
    <h1>فروش ماهانه</h1>
    <div class="sub">مجموع تسویه‌های ثبت‌شده هر ماه. تاریخ به شمسی نشان داده می‌شود.</div>
  </div>
  <div class="actions">
    <form class="logout-form" method="post" action="logout">
      <button class="icon-btn logout-btn" type="submit" title="خروج" aria-label="خروج">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 6H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h4"/><path d="M14 16l4-4-4-4"/><path d="M18 12H9"/></svg>
      </button>
    </form>
  </div>
</header>
<div class="pad"><section class="card" id="monthly-box"></section></div>
</div>

<div id="page-costs" hidden>
<header>
  <div>
    <h1>هزینه و سود ماهانه</h1>
    <div class="sub">فقط مدیر. هر ذخیره یک ردیف جدید می‌سازد (جایگزین قبلی نمی‌شود). سود = فروش ماه − جمع هزینه‌های همان ماه.</div>
  </div>
  <div class="actions">
    <form class="logout-form" method="post" action="logout">
      <button class="icon-btn logout-btn" type="submit" title="خروج" aria-label="خروج">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 6H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h4"/><path d="M14 16l4-4-4-4"/><path d="M18 12H9"/></svg>
      </button>
    </form>
  </div>
</header>
<div class="pad">
  <section class="card">
    <h2>افزودن هزینه</h2>
    <p class="hint">اگر مبلغ را اشتباه زدید، همان ردیف را در لیست پایین ویرایش یا حذف کنید.</p>
    <div class="shop-row">
      <label class="hint">ماه شمسی (مثل 1405-07)<input id="cost-ym" placeholder="1405-07"></label>
      <label class="hint">مبلغ تومان<input id="cost-amt" type="number" min="1" step="1000"></label>
      <label class="hint" style="grid-column:1 / -1">یادداشت<input id="cost-note" placeholder="سرور، دامنه، …"></label>
      <button class="btn shop-row-btn" id="cost-save" type="button">افزودن</button>
    </div>
  </section>
  <section class="card"><h2>خلاصه سود/زیان</h2><div id="profit-box"></div></section>
  <section class="card"><h2>ردیف‌های هزینه</h2><div id="costs-box"></div></section>
</div>
</div>

<div id="page-waives" hidden>
<header>
  <div>
    <h1>حذف بدون هزینه</h1>
    <div class="sub">مصرف واقعی یوزر (حتی بعد از حذف از پنل) اینجا دیده می‌شود. مهلت درخواست ۴۸ ساعت.</div>
  </div>
  <div class="actions">
    <form class="logout-form" method="post" action="logout">
      <button class="icon-btn logout-btn" type="submit" title="خروج" aria-label="خروج">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 6H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h4"/><path d="M14 16l4-4-4-4"/><path d="M18 12H9"/></svg>
      </button>
    </form>
  </div>
</header>
<div class="pad"><section class="card" id="waives-box"></section></div>
</div>

<div id="page-shop" hidden>
<header>
  <div>
    <h1>فروش به مشتری</h1>
    <div class="sub">شماره کارت و پلن‌های تمدید. مشتری از صفحهٔ عمومی /pay/ بدون لاگین خرید می‌کند.</div>
  </div>
  <div class="actions">
    <form class="logout-form" method="post" action="logout">
      <button class="icon-btn logout-btn" type="submit" title="خروج" aria-label="خروج">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 6H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h4"/><path d="M14 16l4-4-4-4"/><path d="M18 12H9"/></svg>
      </button>
    </form>
  </div>
</header>
<div class="pad">
  <section class="card">
    <h2>لینک خرید مشتری</h2>
    <p class="hint">این آدرس را به مشتری بدهید (بدون کلادفلر، روی همان پنل):</p>
    <code id="shop-pay-url" style="display:block;margin-top:6px;word-break:break-all;background:#0d1728;padding:10px;border-radius:8px;font-size:12px"></code>
  </section>
  <section class="card op-only">
    <h2>انتخاب ادمین</h2>
    <label class="hint">admin_id
      <input id="shop-admin-id" type="number" min="1" style="width:120px;display:block;margin-top:6px">
    </label>
    <button class="ghost" id="shop-load-admin" type="button" style="margin-top:8px">بارگذاری</button>
  </section>
  <section class="card">
    <h2>نحوه تأیید پرداخت مشتری</h2>
    <p class="hint">پول به کارت خودتان می‌آید. یکی را انتخاب کنید:</p>
    <div style="display:grid;gap:10px;margin-top:10px">
      <label class="hint" style="display:flex;gap:8px;align-items:flex-start;cursor:pointer">
        <input type="radio" name="shop-mode" id="shop-mode-manual" value="manual" style="margin-top:4px">
        <span><b>تأیید دستی</b><div class="mut">بعد از واریز مشتری، خودتان در همین صفحه سفارش را تأیید می‌کنید. نیازی به اپ پیامک نیست.</div></span>
      </label>
      <label class="hint" style="display:flex;gap:8px;align-items:flex-start;cursor:pointer">
        <input type="radio" name="shop-mode" id="shop-mode-auto" value="auto" style="margin-top:4px">
        <span><b>تأیید خودکار (پیامک بانک)</b><div class="mut">روی گوشی صاحب کارت، SMS Forwarder نصب کنید تا پیامک واریز به سرور برسد و شارژ خودکار شود.</div></span>
      </label>
    </div>
    <div id="shop-mode-manual-box" hidden style="margin-top:14px;padding:12px;border:1px solid var(--line);border-radius:10px">
      <div class="hint">سفارش‌های در انتظار تأیید</div>
      <div id="shop-pending" style="margin-top:8px"></div>
    </div>
    <div id="shop-mode-auto-box" hidden style="margin-top:14px;padding:12px;border:1px solid var(--line);border-radius:10px">
      <div class="hint">راهنمای SMS Forwarder</div>
      <ol class="hint" style="margin:8px 0 0;padding-right:18px;line-height:1.8">
        <li>اپ Forwarder را روی گوشی‌ای بگذارید که پیامک بانک همان کارت می‌آید.</li>
        <li>فرستنده بانک را فیلتر کنید (مثلاً <code id="shop-sms-sender">B.QMEHRIRAN</code>).</li>
        <li>آدرس وب‌هوک زیر را با متد POST بفرستید — توکن مخصوص همین ادمین است و فقط سفارش‌های شما را شارژ می‌کند.</li>
      </ol>
      <div class="hint" style="margin-top:8px">آدرس وب‌هوک شما (اختصاصی)</div>
      <code id="shop-sms-url" style="display:block;margin-top:6px;word-break:break-all;background:#0d1728;padding:10px;border-radius:8px;font-size:12px"></code>
      <p class="hint" id="shop-sms-warn" style="margin-top:8px"></p>
    </div>
  </section>
  <section class="card">
    <h2>کارت بانکی دریافت وجه</h2>
    <div class="shop-row shop-row-card">
      <label class="hint">شماره کارت<input id="shop-card" inputmode="numeric" placeholder="6037…"></label>
      <label class="hint">نام صاحب کارت<input id="shop-card-name" autocomplete="name"></label>
    </div>
  </section>
  <section class="card">
    <h2>شخصی‌سازی صفحه فروش</h2>
    <p class="hint">این‌ها روی صفحهٔ عمومی /pay/ برای مشتریان همان ادمین دیده می‌شود.</p>
    <div style="display:grid;gap:10px;margin-top:10px">
      <label class="hint">نام کسب‌وکار<input id="shop-biz" style="width:100%;display:block;margin-top:6px"></label>
      <label class="hint">شعار من<textarea id="shop-slogan" rows="3" style="width:100%;display:block;margin-top:6px;background:#0d1728;color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:10px"></textarea></label>
      <label class="hint">آدرس کانال تلگرام<input id="shop-tg-ch" style="width:100%;display:block;margin-top:6px" placeholder="@mychannel یا لینک"></label>
      <label class="hint">شماره پشتیبانی<input id="shop-phone" style="width:100%;display:block;margin-top:6px" placeholder="09…"></label>
      <label class="hint">شناسه تلگرام پشتیبانی<input id="shop-tg-sup" style="width:100%;display:block;margin-top:6px" placeholder="@support"></label>
      <button class="btn" id="shop-card-save" type="button">ذخیره کارت و برند</button>
    </div>
  </section>
  <section class="card">
    <h2>افزودن پلن</h2>
    <div class="shop-row shop-row-plan">
      <label class="hint shop-plan-title">عنوان<input id="shop-title" placeholder="۵۰ گیگ ماهانه"></label>
      <label class="hint">گیگ<input id="shop-gib" type="number" min="0.1" step="0.1"></label>
      <label class="hint">روز<input id="shop-days" type="number" min="1" step="1"></label>
      <label class="hint">تعداد کاربر<input id="shop-users" type="number" min="1" max="1000" step="1" value="1"></label>
      <label class="hint shop-plan-price">قیمت تومان<input id="shop-price" type="number" min="1000" step="1000"></label>
      <label class="hint" id="shop-unlim-wrap" hidden style="display:none;flex-direction:row;align-items:center;gap:8px;padding-bottom:4px"><input type="checkbox" id="shop-unlim"> نامحدود (فقط ادمین ۱)</label>
      <button class="btn shop-row-btn" id="shop-plan-add" type="button">افزودن پلن</button>
    </div>
  </section>
  <section class="card"><h2>پلن‌های فعال</h2><div id="shop-plans"></div></section>
</div>
</div>

<div id="page-settings" hidden>
<header>
  <div>
    <h1>تنظیمات پیامک بانک</h1>
    <div class="sub">فرستنده معمولاً نام است نه شماره (مثل B.QMEHRIRAN). فقط واریزهای + ثبت می‌شوند.</div>
  </div>
  <div class="actions">
    <form class="logout-form" method="post" action="logout">
      <button class="icon-btn logout-btn" type="submit" title="خروج" aria-label="خروج">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 6H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h4"/><path d="M14 16l4-4-4-4"/><path d="M18 12H9"/></svg>
      </button>
    </form>
  </div>
</header>
<div class="pad">
  <section class="card">
    <h2>دریافت خودکار</h2>
    <p class="hint">روی گوشی یک SMS Forwarder بگذارید که پیامک‌های همین فرستنده را با توکن زیر به وب‌هوک بفرستد. سه رقم آخر مبلغ واریز = id ادمین پنل.</p>
    <div style="display:grid;gap:12px;margin-top:12px;max-width:640px">
      <label class="hint">فعال باشد <input type="checkbox" id="sms-enabled"></label>
      <label class="hint">فرستنده‌های مجاز (با ویرگول)
        <input id="sms-senders" style="width:100%;margin-top:6px" placeholder="B.QMEHRIRAN">
      </label>
      <label class="hint">شماره حساب / سپرده (اختیاری؛ خالی = هر حساب)
        <input id="sms-account" style="width:100%;margin-top:6px" placeholder="240101007246042001">
      </label>
      <label class="hint">تعداد رقم کد ادمین در انتهای مبلغ
        <input id="sms-digits" type="number" min="1" max="6" style="width:90px;margin-top:6px">
      </label>
      <label class="hint">خبر تلگرام بعد از ثبت/رد <input type="checkbox" id="sms-tg"></label>
      <div>
        <div class="hint">آدرس وب‌هوک</div>
        <code id="sms-url" style="display:block;margin-top:6px;word-break:break-all;background:#0d1728;padding:10px;border-radius:8px;font-size:12px"></code>
      </div>
      <div>
        <div class="hint">توکن مخفی</div>
        <code id="sms-token" style="display:block;margin-top:6px;word-break:break-all;background:#0d1728;padding:10px;border-radius:8px;font-size:12px"></code>
        <button class="ghost" id="sms-regen" type="button" style="margin-top:8px">ساخت توکن جدید</button>
      </div>
      <div>
        <button class="btn" id="sms-save" type="button">ذخیره تنظیمات</button>
      </div>
    </div>
  </section>
  <section class="card">
    <h2>آخرین پیامک‌ها</h2>
    <div id="sms-log"></div>
  </section>
</div>
</div>

<article class="docs" id="page-docs" hidden>
<header>
  <div>
    <h1>مستندات</h1>
    <div class="sub">تسویه روی id کاربر پنل؛ شماره ته نام لازم نیست</div>
  </div>
  <div class="actions">
    <form class="logout-form" method="post" action="logout">
      <button class="icon-btn logout-btn" type="submit" title="خروج" aria-label="خروج">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 6H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h4"/><path d="M14 16l4-4-4-4"/><path d="M18 12H9"/></svg>
      </button>
    </form>
  </div>
</header>
<div class="callout">
<p>صورتحساب از <b>سقف حجم (data_limit)</b> است، نه مصرف. اگر همان zahra1 را ماه دهم دوباره شارژ کنید، id عوض نمی‌شود؛ فقط سقف بالا می‌رود و همان افزایش در «اضافه این دوره» می‌آید. لیست ماه‌های قبل را نگه ندارید.</p>
</div>
<h2>اولین بار</h2>
<p>اگر تا امروز دستی تسویه کرده‌اید، یک‌بار «بدون دریافت ثبت کن» بزنید تا سقف فعلی صفرِ دفترچه شود. وگرنه کل سقف فعلی در اولین «ثبت تسویه» حساب می‌شود.</p>
<h2>بعد از آن</h2>
<ul>
<li>یوزر جدید زیر همان ادمین پنل → کل سقفش در دوره بعد</li>
<li>شارژ مجدد همان id → فقط گیگ اضافه‌شده</li>
<li>کم کردن سقف → این دوره صفر؛ بعداً فقط از سقف قبلاً حساب‌شده به بالا</li>
<li>دکمه <b>کپی گزارش فروش</b> / دانلود: فقط یوزرهای جدید و شارژ مجدد را برای فرستادن به فروشنده می‌سازد</li>
<li>اگر کمتر از جمع پرداخت کرد: در <b>دریافتی</b> همان رقم را بزنید و ثبت تسویه کنید؛ مانده به‌عنوان بدهی می‌ماند و ماه بعد با دورهٔ جدید جمع می‌شود</li>
<li>اگر یوزر از پنل حذف شود ولی سقفش تسویه نشده باشد، در جدول با وضعیت <b>deleted</b> می‌ماند تا پولش گرفته شود</li>
<li><b>درخواست حذف بدون هزینه</b> → مدیر در منوی «حذف بدون هزینه» تأیید/رد می‌کند؛ فقط بعد از تأیید بدهی آن id بخشیده می‌شود</li>
</ul>
<p>یوزرها باید در PasarGuard زیر همان ادمین فروشنده ساخته شوند (<code>admin_id</code>). قیمت پیش‌فرض ۲۵۰۰ تومان هر گیگ (همان گیگ پنل، ۱۰۲۴³ بایت) است.</p>
</article>
</div>
</div>
<script>
const $ = (id) => document.getElementById(id);
const params = new URLSearchParams(location.search);
let adminId = params.get('id');
const segs = location.pathname.replace(/\\/+$/,'').split('/').filter(Boolean);
const leaf = segs[segs.length-1] || '';
const isDocs = leaf === 'docs';
const isSettings = leaf === 'settings';
const isMonthly = leaf === 'monthly';
const isCosts = leaf === 'costs';
const isWaives = leaf === 'waives';
const isShop = leaf === 'shop';
let page = isDocs ? 'docs' : (isSettings ? 'settings' : (isMonthly ? 'monthly' : (isCosts ? 'costs' : (isWaives ? 'waives' : (isShop ? 'shop' : (adminId ? 'admin' : 'home'))))));
let readOnly = false;
let shopAdminId = 0;
let meAdminId = 0;
let isParentUser = false;
function showPage(){
  ['home','admin','docs','settings','monthly','costs','waives','shop'].forEach(p => { const el = $('page-'+p); if (el) el.hidden = p !== page; });
  $('nav-home').classList.toggle('active', page === 'home' || page === 'admin');
  if ($('nav-docs')) $('nav-docs').classList.toggle('active', page === 'docs');
  if ($('nav-settings')) $('nav-settings').classList.toggle('active', page === 'settings');
  if ($('nav-monthly')) $('nav-monthly').classList.toggle('active', page === 'monthly');
  if ($('nav-costs')) $('nav-costs').classList.toggle('active', page === 'costs');
  if ($('nav-waives')) $('nav-waives').classList.toggle('active', page === 'waives');
  if ($('nav-shop')) $('nav-shop').classList.toggle('active', page === 'shop');
}
function esc(s){ return String(s||'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function flash(msg, kind){ const el=$('flash'); el.className='flash on '+(kind||'ok'); el.textContent=msg||''; }
async function api(path, body){
  const opt = body !== undefined ? {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify(body)} : {};
  const r = await fetch(path, opt);
  if (r.status === 401) { location.reload(); return null; }
  const data = await r.json().catch(() => ({error:'جواب نامعتبر'}));
  if (!r.ok) throw new Error(data.error || ('خطا '+r.status));
  return data;
}
const kindFa = {new:'یوزر جدید', recharge:'شارژ مجدد', unchanged:'بدون تغییر', deleted:'حذف‌شده (بدهکار)'};
const statusFa = {
  active:'فعال', disabled:'غیرفعال', expired:'منقضی', limited:'محدود',
  on_hold:'معلق', hold:'معلق', deleted:'حذف‌شده', inactive:'غیرفعال'
};
const statusCls = {
  active:'on', disabled:'off', inactive:'off', expired:'exp', limited:'lim',
  on_hold:'hold', hold:'hold', deleted:'del'
};
function statusDot(status){
  const raw = String(status || '').trim();
  const key = raw.toLowerCase().replace(/\\s+/g, '_');
  const cls = statusCls[key] || 'unk';
  const label = statusFa[key] || (raw || '—');
  return `<span class="st st-${cls}" title="${esc(label)}"><i aria-hidden="true"></i><span class="st-t">${esc(label)}</span></span>`;
}
function setMenuOpen(open){
  const menu = $('side-menu');
  const bd = $('menu-backdrop');
  if (menu) menu.classList.toggle('open', !!open);
  if (bd) {
    bd.hidden = !open;
    bd.classList.toggle('on', !!open);
  }
  document.body.classList.toggle('menu-open', !!open);
  const btn = $('menu-toggle');
  if (btn) btn.setAttribute('aria-expanded', open ? 'true' : 'false');
}
function wireMobileMenu(){
  const toggle = $('menu-toggle');
  const bd = $('menu-backdrop');
  if (toggle) toggle.onclick = () => {
    const open = $('side-menu') && $('side-menu').classList.contains('open');
    setMenuOpen(!open);
  };
  if (bd) bd.onclick = () => setMenuOpen(false);
  document.querySelectorAll('aside.menu .mi').forEach(a => {
    a.addEventListener('click', () => setMenuOpen(false));
  });
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') setMenuOpen(false);
  });
}
let lastAdmin = null;
let lastHist = null;
function billable(u){ return u && Number(u.delta) > 0 && (u.kind === 'new' || u.kind === 'recharge' || u.kind === 'deleted'); }
function adminLabel(d){
  return (d.admin_username || '') + ' (#' + d.admin_id + ')';
}
function buildReport(d){
  const rows = (d.users || []).filter(billable).sort((a,b) => b.delta - a.delta);
  const when = new Date().toLocaleString('fa-IR');
  const lines = [];
  lines.push('گزارش فروش / بدهکاری');
  lines.push('فروشنده: ' + adminLabel(d));
  lines.push('زمان گزارش: ' + when);
  lines.push('قیمت: ' + d.price + ' تومان / گیگ');
  lines.push('');
  if (!rows.length) {
    lines.push('در این دوره یوزر جدید یا شارژ مجددی نیست.');
  } else {
    lines.push('— یوزرهای جدید و شارژ مجدد —');
    let i = 1;
    for (const u of rows) {
      lines.push(
        i + ') ' + (u.username || ('id='+u.id)) +
        ' | ' + (kindFa[u.kind] || u.kind) +
        ' | اضافه: ' + u.delta_h +
        ' | مبلغ: ' + u.toman_h +
        ' | سقف: ' + u.limit_h
      );
      i += 1;
    }
    lines.push('');
    lines.push('جمع حجم این دوره: ' + d.delta_h);
    lines.push('مبلغ این دوره: ' + d.toman_h);
    lines.push('تعداد: ' + rows.length + ' (جدید ' + d.new + ' · شارژ مجدد ' + d.recharge + ')');
  }
  lines.push('');
  lines.push('بدهی قبلی: ' + d.debt_h);
  lines.push('مجموع بدهی: ' + d.total_h + ' (دوره + بدهی قبلی)');
  if (d.pay && d.pay > 0) {
    lines.push('مبلغ دقیق کارت‌به‌کارت:');
    lines.push('  ' + d.pay_h);
    lines.push('  ' + (d.pay_rial_h || ''));
    lines.push('لطفا دقیقا مبلغ درج شده را واریز بفرمایید تا خودکار ثبت شود');
  }
  return lines.join('\\n');
}
async function copyReport(){
  if (!lastAdmin) return;
  const text = buildReport(lastAdmin);
  try {
    await navigator.clipboard.writeText(text);
    flash(readOnly ? 'گزارش فقطِ جدید/شارژ مجدد کپی شد.' : 'گزارش فقطِ جدید/شارژ مجدد کپی شد. برای ادمین بفرستید.', 'ok');
  } catch (e) {
    const ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); flash('گزارش کپی شد.', 'ok'); }
    catch (e2) { flash('کپی نشد؛ از دانلود گزارش استفاده کنید.', 'err'); }
    ta.remove();
  }
}
function downloadReport(){
  if (!lastAdmin) return;
  const text = buildReport(lastAdmin);
  const blob = new Blob([text], {type:'text/plain;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'settle-report-admin-' + lastAdmin.admin_id + '.txt';
  a.click();
  URL.revokeObjectURL(a.href);
  flash('فایل گزارش دانلود شد.', 'ok');
}
function adminRowHtml(a, opts){
  opts = opts || {};
  const isChild = !!a.is_child || !!opts.child;
  const hasKids = (a.children && a.children.length) || a.is_parent;
  const subBits = [
    a.count + ' کاربر',
    'جدید ' + a.new,
    'شارژ مجدد ' + a.recharge,
  ];
  if (a.days != null) subBits.push(a.days + ' روز از تسویه');
  if (hasKids) subBits.push((a.children||[]).length + ' مدیر');
  let pills = '';
  if (hasKids) pills += ' <span class="pill agency">مدیر ارشد</span>';
  if (isChild) pills += ' <span class="pill child">مدیر</span>';
  // در لیست فقط حجم این دوره؛ مبلغ در پروفایل هر مدیر دیده می‌شود
  return `<a class="item" href="?id=${a.id}">
    <div><b>${esc(a.username)}</b>${pills}<div class="mut">${subBits.map(esc).join(' · ')}</div></div>
    <div class="item-side"><span class="mut">${esc(a.delta_h)} این دوره</span></div>
  </a>`;
}
function parentSelectHtml(a, choices){
  if (readOnly) return '';
  const kids = a.children || [];
  if (kids.length) return '<div class="agency-meta mut" style="font-size:12px">برای انتساب، از ردیف مدیر استفاده کنید.</div>';
  const opts = ['<option value="">— مستقل (بدون والد) —</option>']
    .concat((choices||[]).filter(c => c.id !== a.id).map(c =>
      `<option value="${c.id}" ${a.parent_id===c.id?'selected':''}>${esc(c.username)} (#${c.id})</option>`
    ));
  return `<div class="agency-meta op-only">
    <span class="mut" style="font-size:12px">مدیر ارشد:</span>
    <select class="agency-parent" data-id="${a.id}">${opts.join('')}</select>
    <button class="ghost agency-save" type="button" data-id="${a.id}" style="padding:6px 10px;font-size:12px">ذخیره</button>
  </div>`;
}
async function loadHome(){
  const d = await api('api/admins');
  if (!d) return;
  const box = $('admins');
  window._parentChoices = d.parent_choices || [];
  if (!d.admins.length){ box.innerHTML = '<div class="empty">ادمینی در پنل نیست.</div>'; return; }
  const parts = [];
  for (const a of d.admins) {
    const kids = a.children || [];
    if (kids.length) {
      parts.push(`<div class="agency-block">
        ${adminRowHtml(a)}
        <div class="agency-kids">${kids.map(c => adminRowHtml(c, {child:true}) + parentSelectHtml(c, d.parent_choices)).join('')}</div>
        ${parentSelectHtml(a, d.parent_choices)}
      </div>`);
    } else {
      parts.push(`<div class="agency-block">${adminRowHtml(a)}${parentSelectHtml(a, d.parent_choices)}</div>`);
    }
  }
  box.innerHTML = parts.join('');
  box.querySelectorAll('.agency-save').forEach(btn => {
    btn.onclick = async (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      const id = Number(btn.getAttribute('data-id'));
      const sel = box.querySelector('select.agency-parent[data-id="'+id+'"]');
      const parent_id = sel && sel.value ? Number(sel.value) : null;
      try {
        const r = await api('api/agency', {admin_id: id, parent_id});
        flash(r.message || 'ذخیره شد.', 'ok');
        loadHome();
      } catch (e) { flash(e.message, 'err'); }
    };
  });
  box.querySelectorAll('select.agency-parent').forEach(sel => {
    sel.onclick = (ev) => { ev.preventDefault(); ev.stopPropagation(); };
    sel.onchange = (ev) => { ev.stopPropagation(); };
  });
}
function initials(name){
  const s = String(name || '').trim();
  if (!s) return '؟';
  const parts = s.replace(/[_-]+/g, ' ').split(/\s+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return s.slice(0, 2).toUpperCase();
}
function renderRankCard(d){
  const card = $('rank-card');
  if (!card) return;
  const show = !!(d && d.is_child && d.parent_id);
  card.classList.toggle('on', show);
  if (!show) return;
  const senior = d.parent_username || ('#' + d.parent_id);
  const you = d.admin_username || ('#' + d.admin_id);
  const tree = $('rank-tree');
  if (tree) {
    tree.innerHTML =
      `<div class="rank-node senior">
        <div class="rank-avatar">${esc(initials(senior))}</div>
        <div class="rank-meta"><b>${esc(senior)}</b><span>رتبه سازمانی · مدیر ارشد شبکه</span></div>
        <span class="rank-badge">مدیر ارشد</span>
      </div>
      <div class="rank-link" aria-hidden="true"></div>
      <div class="rank-node you">
        <div class="rank-avatar">${esc(initials(you))}</div>
        <div class="rank-meta"><b>${esc(you)}</b><span>حساب شما · زیر نظر مستقیم مدیر ارشد</span></div>
        <span class="rank-badge">مدیر</span>
      </div>`;
  }
  if ($('rank-foot')) {
    $('rank-foot').innerHTML =
      'تسویه مالی و پشتیبانی از طریق <b>' + esc(senior) + '</b> انجام می‌شود. شما عضو شبکهٔ نمایندگی او هستید.';
  }
}
function renderAdmin(d, hist){
  lastAdmin = d; lastHist = hist;
  const net = d.network || null;
  const dueTotal = net ? Number(net.total) : Number(d.total);
  const isParentView = !!(d.is_parent && net);
  const titlePrefix = readOnly
    ? (d.admin_id === meAdminId ? 'حساب من — ' : 'مدیر — ')
    : '';
  $('admin-title').textContent = titlePrefix + adminLabel(d);
  let sub = d.live_count + ' زنده' + (d.deleted_owing ? (' · ' + d.deleted_owing + ' حذف‌شده بدهکار') : '') +
    ' · قیمت ' + d.price + ' تومان / گیگ' +
    (d.pending_waive ? (' · ' + d.pending_waive + ' درخواست بخشش') : '');
  if (isParentView) sub += ' · ' + (d.child_ids||[]).length + ' مدیر';
  if (readOnly) {
    // زیرمجموعه → تلگرام مدیر ارشد؛ بقیه → تلگرام مالک (fallback)
    let tg = '';
    if (d.is_child && d.support_contact) tg = d.support_contact;
    else if (d.is_child && d.parent_support_telegram) {
      tg = String(d.parent_support_telegram).trim();
      if (tg && tg.charAt(0) !== '@' && tg.indexOf('t.me/') < 0) tg = '@' + tg.replace(/^@+/, '');
    }
    if (!tg && !d.is_child) tg = '@AZROOT94';
    if (tg) sub += ' · لطفا جهت هرگونه سوال به تلگرام پیام بدهید ' + tg;
  }
  $('admin-sub').textContent = sub;
  renderRankCard(d);
  if ($('price')) $('price').value = d.price;
  if ($('paid') && document.activeElement !== $('paid')) $('paid').value = dueTotal;
  // فقط مالک (op) یا مدیر ارشد روی حسابِ مدیرِ زیرمجموعه — نه روی حساب خودش
  const canEditPrice = (!readOnly) || (
    isParentUser
    && !!d.is_child
    && Number(d.admin_id) !== meAdminId
    && Number(d.parent_id) === meAdminId
  );
  document.querySelectorAll('.price-edit').forEach(el => {
    el.hidden = !canEditPrice;
    el.style.display = canEditPrice ? '' : 'none';
    if (!canEditPrice && el.tagName === 'INPUT') el.value = '';
  });
  if ($('back-network')) {
    $('back-network').style.display = (readOnly && isParentUser && Number(adminId) !== meAdminId) ? 'inline-block' : 'none';
  }
  const settledClean = dueTotal <= 0;
  const ownClean = Number(d.total) <= 0;
  const lastPay = d.last && d.last.kind !== 'baseline' && d.last.kind !== 'waive' ? d.last : null;
  const recentPay = lastPay && lastPay.days != null && lastPay.days <= 2;
  const payBox = $('pay-box');
  if (payBox) {
    // زیرمجموعه از دید والد: باکس واریز مالک را نشان نده
    const viewingChildAsParent = readOnly && d.is_child && d.admin_id !== meAdminId;
    const showPay = !settledClean && Number(d.pay) > 0 && !viewingChildAsParent;
    payBox.classList.toggle('on', showPay);
    if (readOnly && d.is_child && d.admin_id === meAdminId) {
      if ($('pay-hint')) $('pay-hint').textContent = 'این مبلغ را به مدیر ارشد خودتان بپردازید (نه به مالک پنل).';
    } else if ($('pay-hint')) {
      $('pay-hint').textContent = 'لطفا دقیقا مبلغ درج شده را واریز بفرمایید تا خودکار ثبت شود';
    }
    const tomanTxt = d.pay_h || '—';
    let rialTxt = d.pay_rial_h || '';
    if (!rialTxt && Number(d.pay) > 0) {
      rialTxt = (Number(d.pay) * 10).toLocaleString('fa-IR') + ' ریال';
    }
    if ($('pay-amt')) $('pay-amt').textContent = tomanTxt;
    if ($('pay-rial')) {
      $('pay-rial').textContent = rialTxt || '—';
      $('pay-rial').style.display = 'block';
    }
  }
  const okBox = $('ok-box');
  if (okBox) {
    if (settledClean && recentPay) {
      okBox.className = 'ok-box on';
      okBox.innerHTML = '<b>پرداخت شما ثبت شد.</b><br>مجموع بدهی صفر است. آخرین تسویه: ' + esc(lastPay.toman_h) +
        (lastPay.days === 0 ? ' · امروز' : (' · ' + lastPay.days + ' روز پیش'));
    } else if (settledClean) {
      okBox.className = 'ok-box on';
      okBox.innerHTML = '<b>حساب شما تسویه است.</b> بدهی فعلی صفر تومان است.';
    } else {
      okBox.className = 'ok-box';
      okBox.innerHTML = '';
    }
  }
  if (isParentView) {
    // روی موبایل اعداد شبکه کافی‌اند؛ KPI خودی خلاصه می‌ماند
    $('kpi').innerHTML = [
      ['فروش خودتان این دوره', d.toman_h, ''],
      ['بدهی خودتان', d.total_h, ownClean ? 'ok' : 'hi'],
    ].map(([k,v,cls]) => `<div class="${cls}"><span class="mut">${k}</span><b>${esc(v)}</b></div>`).join('');
  } else {
    $('kpi').innerHTML = [
      ['بدهی قبلی', d.debt_h, d.debt > 0 ? 'hi' : ''],
      ['مبلغ این دوره', d.toman_h, ''],
      ['مجموع بدهی', d.total_h, ownClean ? 'ok' : 'hi'],
      ['مبلغ واریز', settledClean ? '—' : (d.pay_both_h || d.pay_h || d.total_h), (!settledClean && d.pay > 0) ? 'hi' : ''],
    ].map(([k,v,cls]) => `<div class="${cls}"><span class="mut">${k}</span><b>${esc(v)}</b></div>`).join('');
  }

  const nbox = $('network-box');
  if (nbox) {
    if (isParentView) {
      nbox.hidden = false;
      $('network-kpi').innerHTML = [
        ['فروش شبکه این دوره', net.toman_h, ''],
        ['بدهی شبکه', net.debt_h, net.debt > 0 ? 'hi' : ''],
        ['مجموع شبکه (قابل واریز)', net.total_h, Number(net.total) <= 0 ? 'ok' : 'hi'],
      ].map(([k,v,cls]) => `<div class="${cls}"><span class="mut">${k}</span><b>${esc(v)}</b></div>`).join('');
      const mems = (net.members || []).filter(m => !m.is_self);
      $('network-members').innerHTML = mems.length
        ? mems.map(m => `<a class="item" href="?id=${m.id}">
            <div><b>${esc(m.username)}</b> <span class="pill child">مدیر</span>
              <div class="mut">جدید ${m.new} · شارژ ${m.recharge}</div></div>
            <div><b>${esc(m.total_h)}</b><div class="mut">${esc(m.toman_h)}</div></div>
          </a>`).join('')
        : '<div class="empty">مدیری نیست.</div>';
      if ($('charge')) $('charge').textContent = 'ثبت تسویه شبکه';
      if ($('baseline')) $('baseline').textContent = 'بدون دریافت ثبت کن (شبکه)';
    } else {
      nbox.hidden = true;
      if ($('charge')) $('charge').textContent = 'ثبت تسویه';
      if ($('baseline')) $('baseline').textContent = 'بدون دریافت ثبت کن';
    }
  }

  let banners = [];
  if (!(d.has_ledger || readOnly)) {
    banners.push('<p class="hint">دفترچه این ادمین خالی است. اگر قبلاً دستی حساب کرده‌اید اول «بدون دریافت ثبت کن» بزنید.</p>');
  }
  if (d.debt > 0) {
    banners.push('<p class="hint">بدهی قبلی: <b>' + esc(d.debt_h) + '</b> + این دوره <b>' + esc(d.toman_h) + '</b> = مجموع بدهی <b>' + esc(d.total_h) + '</b>.</p>');
  }
  if (isParentView && !readOnly) {
    banners.push('<p class="hint">با «ثبت تسویه شبکه» فروش خودش + همه مدیران یکجا بسته می‌شود؛ مانده بدهی فقط روی مدیر ارشد می‌ماند.</p>');
  }
  if (d.deleted_owing > 0) {
    banners.push('<p class="hint">تعدادی یوزر از پنل حذف شده‌اند ولی بدهی سقف‌شان هنوز هست. برای انصراف واقعی از دکمهٔ <b>حذف بدون هزینه</b> استفاده کنید.</p>');
  }
  if (!settledClean && d.pay > 0 && !readOnly) {
    banners.push('<p class="hint">برای ثبت خودکار دقیقاً <b>' + esc(d.pay_rial_h || d.pay_h) + '</b> (یا ' + esc(d.pay_h) + ') کارت‌به‌کارت کنید.</p>');
  }
  $('banner').innerHTML = banners.join('');
  const only = $('only-delta') && $('only-delta').checked;
  const shown = only ? (d.users || []).filter(billable) : (d.users || []);
  if (!d.users.length){ $('utable').innerHTML = '<div class="empty">کاربری زیر این ادمین نیست.</div>'; }
  else if (!shown.length){ $('utable').innerHTML = '<div class="empty">' + (settledClean && ownClean ? 'در این دوره مورد تسویه‌نشده‌ای نیست.' : 'در این دوره یوزر جدید یا شارژ مجددی نیست.') + '</div>'; }
  else {
    $('utable').innerHTML = `<div class="table-wrap users-mobile"><table><thead><tr>
      <th>کاربر</th><th>وضعیت</th><th>سقف فعلی</th><th>قبلاً حساب‌شده</th><th>اضافه این دوره</th><th>مبلغ</th><th></th><th></th>
    </tr></thead><tbody>${shown.map(u => `<tr>
      <td><b>${esc(u.username)}</b><div class="mut">id=${u.id}</div></td>
      <td>${statusDot(u.status)}</td>
      <td class="num">${esc(u.limit_h)}</td>
      <td class="num">${esc(u.billed_h)}</td>
      <td class="num">${esc(u.delta_h)}</td>
      <td class="num">${esc(u.toman_h)}</td>
      <td><span class="pill ${u.kind}">${kindFa[u.kind]||u.kind}</span>${u.waive_pending?' <span class="pill recharge">در انتظار بخشش</span>':''}</td>
      <td>${u.can_waive ? '<button class="ghost waive-btn" type="button" data-uid="'+u.id+'" data-name="'+esc(u.username)+'" style="white-space:nowrap;font-size:11px;padding:6px 8px">حذف بدون هزینه</button>' : (u.waive_pending?'—':'')}</td>
    </tr>`).join('')}</tbody></table></div>`;
    $('utable').querySelectorAll('.waive-btn').forEach(btn => {
      btn.onclick = () => requestWaive(Number(btn.getAttribute('data-uid')), btn.getAttribute('data-name') || '');
    });
  }
  if (!hist || !hist.items.length) $('hist').innerHTML = '<div class="empty">هنوز تسویه‌ای نیست.</div>';
  else $('hist').innerHTML = `<div class="table-wrap hist-mobile"><table><thead><tr><th>زمان</th><th>نوع</th><th>حجم</th><th>دریافتی</th><th>تعداد</th><th>توضیح</th></tr></thead><tbody>${
    hist.items.map(h => `<tr>
      <td>${new Date(h.ts*1000).toLocaleString('fa-IR')}</td>
      <td>${h.kind==='baseline'?'بدون دریافت':(h.kind==='waive'?'بخشش حذف':'تسویه')}</td>
      <td class="num">${esc(h.delta_h)}</td>
      <td class="num">${esc(h.toman_h)}</td>
      <td>${h.users}</td>
      <td class="mut" style="font-size:12px;max-width:360px">${esc(h.note||'')}</td>
    </tr>`).join('')}</tbody></table></div>`;
}
async function requestWaive(uid, name){
  const reason = prompt('دلیل حذف بدون هزینه برای «' + name + '» (مثلاً انصراف مشتری):', '') || '';
  if (reason === null) return;
  if (!confirm('کسر هزینه بعد از تایید مدیریت انجام میشود')) return;
  try {
    const d = await api('api/waive/request', {admin_id: Number(adminId), user_id: uid, reason});
    flash(d.message || 'ثبت شد.', 'ok');
    loadAdmin();
  } catch (e) { flash(e.message, 'err'); }
}
async function loadAdmin(){
  const [d, h] = await Promise.all([api('api/admin?id='+adminId), api('api/history?id='+adminId)]);
  if (!d) return;
  renderAdmin(d, h);
}
async function boot(){
  let me = null;
  try { me = await api('api/me'); } catch (e) { flash(e.message, 'err'); return; }
  if (!me) return;
  readOnly = me.role !== 'op';
  meAdminId = Number(me.admin_id || 0);
  isParentUser = !!(me.is_parent);
  document.body.classList.toggle('ro', readOnly);
  document.body.classList.toggle('child', !!(readOnly && me.is_child));
  document.body.classList.toggle('parent', !!(readOnly && me.is_parent));
  const loginName = (me.username || '').trim() || (me.admin_id ? ('#' + me.admin_id) : '');
  const brandTitle = loginName || 'تسویه فروش';
  const brandSub = loginName ? 'تسویه فروش' : 'سقف حجم، نه مصرف';
  ['brand-name', 'side-brand-name'].forEach(id => { if ($(id)) $(id).textContent = brandTitle; });
  ['brand-sub', 'side-brand-sub'].forEach(id => { if ($(id)) $(id).textContent = brandSub; });
  let rankHtml = '';
  if (readOnly && me.is_child && me.parent_username) {
    rankHtml = 'مدیر ارشد شما<br><b>' + esc(me.parent_username) + '</b>';
  } else if (readOnly && me.is_parent) {
    rankHtml = 'نقش شما<br><b>مدیر ارشد</b>';
  }
  ['brand-rank', 'side-brand-rank'].forEach(id => { if ($(id)) $(id).innerHTML = rankHtml; });
  wireMobileMenu();
  if (readOnly) {
    // Remove operator-only nodes from DOM (not just CSS hide) so Inspect also clean is.
    document.querySelectorAll('.op-only').forEach(el => el.remove());
    if (isParentUser) {
      $('nav-home').textContent = 'شبکه من';
      $('nav-home').href = '.';
      if ($('home-title')) $('home-title').textContent = 'مدیران من';
      if ($('home-sub')) $('home-sub').textContent = 'فروش و بدهی هر مدیر را ببینید.';
      if (page === 'settings' || page === 'costs' || page === 'docs') page = 'home';
      if (page === 'admin' && !adminId) {
        page = 'home';
      }
      if (page === 'admin' && adminId && Number(adminId) !== meAdminId) {
        // اجازهٔ مشاهدهٔ زیرمجموعه در can_view سمت سرور چک می‌شود
      } else if (page === 'admin' && !params.get('id')) {
        adminId = String(me.admin_id);
      }
    } else {
      if (page === 'home' || page === 'settings' || page === 'costs' || page === 'docs') page = 'admin';
      adminId = String(me.admin_id);
      $('nav-home').textContent = 'حساب من';
      $('nav-home').href = '.';
    }
  } else if (page === 'settings') {
    // keep
  }
  showPage();
  if (page === 'home') loadHome();
  if (page === 'admin') loadAdmin();
  if (page === 'settings') loadSettings();
  if (page === 'monthly') loadMonthly();
  if (page === 'costs') loadCosts();
  if (page === 'waives') loadWaives();
  if (page === 'shop') {
    shopAdminId = readOnly ? Number(me.admin_id) : Number(($('shop-admin-id') && $('shop-admin-id').value) || me.admin_id || adminId || 0);
    if ($('shop-admin-id') && shopAdminId) $('shop-admin-id').value = String(shopAdminId);
    loadShop();
  }
  if (readOnly && page === 'admin') {
    setInterval(() => { if (!document.hidden) loadAdmin(); }, 20000);
  }
}
boot();
async function loadShop(){
  if (!shopAdminId){
    if ($('shop-plans')) $('shop-plans').innerHTML = '<div class="empty">admin_id را مشخص کنید.</div>';
    return;
  }
  const q = readOnly ? '' : ('?id=' + shopAdminId);
  const d = await api('api/shop' + q);
  if (!d) return;
  window._lastShop = d;
  const origin = location.origin;
  const payPath = location.pathname.replace(/shop\\/?$/, '').replace(/\\/?$/, '/') + '../pay/';
  let payUrl = origin + '/pay/';
  try {
    payUrl = new URL('/pay/', origin).href;
  } catch (e) {}
  if ($('shop-pay-url')) $('shop-pay-url').textContent = payUrl;
  if ($('shop-card')) $('shop-card').value = d.card_number || '';
  if ($('shop-card-name')) $('shop-card-name').value = d.card_name || '';
  if ($('shop-biz')) $('shop-biz').value = d.business_name || '';
  if ($('shop-slogan')) $('shop-slogan').value = d.slogan || d.default_slogan || '';
  if ($('shop-tg-ch')) $('shop-tg-ch').value = d.telegram_channel || '';
  if ($('shop-phone')) $('shop-phone').value = d.support_phone || '';
  if ($('shop-tg-sup')) $('shop-tg-sup').value = d.support_telegram || '';
  const mode = (d.pay_confirm_mode === 'auto') ? 'auto' : 'manual';
  if ($('shop-mode-manual')) $('shop-mode-manual').checked = mode === 'manual';
  if ($('shop-mode-auto')) $('shop-mode-auto').checked = mode === 'auto';
  renderShopMode(d);
  const canUnlim = !!d.can_unlimited;
  if ($('shop-unlim-wrap')) {
    $('shop-unlim-wrap').hidden = !canUnlim;
    $('shop-unlim-wrap').style.display = canUnlim ? 'flex' : 'none';
  }
  if (!canUnlim) {
    if ($('shop-unlim')) $('shop-unlim').checked = false;
    if ($('shop-gib')) { $('shop-gib').disabled = false; $('shop-gib').min = '0.1'; }
  } else if ($('shop-gib')) {
    $('shop-gib').min = '0';
  }
  const box = $('shop-plans');
  if (!d.plans || !d.plans.length) box.innerHTML = '<div class="empty">پلنی نیست.</div>';
  else {
    box.innerHTML = `<table><thead><tr><th>عنوان</th><th>حجم</th><th>روز</th><th>کاربر</th><th>قیمت</th><th>وضعیت</th><th></th></tr></thead><tbody>${
      d.plans.map(p => `<tr>
        <td>${esc(p.title)}</td>
        <td class="num">${esc(p.volume_h || p.gib)}</td>
        <td class="num">${p.days}</td>
        <td class="num">${esc(p.users_h || ((p.user_count||1)+' کاربره'))}</td>
        <td class="num">${esc(p.price_h)}</td>
        <td>${p.active?'فعال':'خاموش'}</td>
        <td style="white-space:nowrap">
          <button class="ghost shop-toggle" type="button" data-id="${p.id}" data-active="${p.active?0:1}">${p.active?'خاموش':'فعال'}</button>
          <button class="danger shop-del" type="button" data-id="${p.id}">حذف</button>
        </td>
      </tr>`).join('')}</tbody></table>`;
    box.querySelectorAll('.shop-del').forEach(btn => {
      btn.onclick = async () => {
        if (!confirm('این پلن حذف شود؟')) return;
        try {
          await api('api/shop', {action:'delete_plan', admin_id: shopAdminId, id: Number(btn.dataset.id)});
          flash('حذف شد.', 'ok'); loadShop();
        } catch (e) { flash(e.message, 'err'); }
      };
    });
    box.querySelectorAll('.shop-toggle').forEach(btn => {
      btn.onclick = async () => {
        try {
          await api('api/shop', {action:'update_plan', admin_id: shopAdminId, id: Number(btn.dataset.id), active: Number(btn.dataset.active)===1});
          flash('به‌روز شد.', 'ok'); loadShop();
        } catch (e) { flash(e.message, 'err'); }
      };
    });
  }
}
if ($('shop-load-admin')) $('shop-load-admin').onclick = () => {
  shopAdminId = Number($('shop-admin-id').value||0);
  loadShop();
};
function renderShopMode(d){
  const mode = (d && d.pay_confirm_mode === 'auto') ? 'auto' : 'manual';
  if ($('shop-mode-manual-box')) $('shop-mode-manual-box').hidden = mode !== 'manual';
  if ($('shop-mode-auto-box')) $('shop-mode-auto-box').hidden = mode !== 'auto';
  if ($('shop-sms-url')) $('shop-sms-url').textContent = d.sms_webhook_url || '—';
  if ($('shop-sms-sender')) $('shop-sms-sender').textContent = d.sms_senders || 'B.QMEHRIRAN';
  if ($('shop-sms-warn')) {
    $('shop-sms-warn').textContent = d.sms_enabled
      ? 'پیامک سرور فعال است. بعد از نصب Forwarder یک واریز تست بزنید.'
      : 'هشدار: دریافت پیامک در سرور هنوز خاموش است — با مدیر اصلی هماهنگ کنید.';
  }
  const box = $('shop-pending');
  if (!box) return;
  const items = (d && d.pending_orders) || [];
  if (mode !== 'manual'){ box.innerHTML = ''; return; }
  if (!items.length){ box.innerHTML = '<div class="empty">سفارش در انتظاری نیست.</div>'; return; }
  box.innerHTML = `<table><thead><tr><th>یوزر</th><th>مبلغ</th><th>پلن</th><th>مهلت</th><th></th></tr></thead><tbody>${
    items.map(o => `<tr>
      <td><b>${esc(o.username)}</b><div class="mut">#${o.id}</div></td>
      <td class="num">${esc(o.pay_h)}</td>
      <td class="mut">${(Number(o.gib)||0)<=0?'نامحدود':(o.gib+' گیگ')} / ${o.days} روز</td>
      <td class="mut">${Math.max(0,Math.floor(o.expires_in/60))} دقیقه</td>
      <td style="white-space:nowrap">
        <button class="btn shop-approve" type="button" data-id="${o.id}" style="padding:6px 10px;font-size:12px">تأیید و شارژ</button>
        <button class="ghost shop-reject" type="button" data-id="${o.id}" style="padding:6px 10px;font-size:12px;width:auto;margin:0">رد</button>
      </td>
    </tr>`).join('')}</tbody></table>`;
  box.querySelectorAll('.shop-approve').forEach(btn => {
    btn.onclick = async () => {
      if (!confirm('پرداخت تأیید و اکانت شارژ شود؟')) return;
      try {
        const r = await api('api/shop', {action:'approve_order', admin_id: shopAdminId, id: Number(btn.dataset.id)});
        flash(r.message || 'تأیید شد.', 'ok'); loadShop();
      } catch (e) { flash(e.message, 'err'); }
    };
  });
  box.querySelectorAll('.shop-reject').forEach(btn => {
    btn.onclick = async () => {
      if (!confirm('سفارش رد شود؟')) return;
      try {
        const r = await api('api/shop', {action:'reject_order', admin_id: shopAdminId, id: Number(btn.dataset.id)});
        flash(r.message || 'رد شد.', 'ok'); loadShop();
      } catch (e) { flash(e.message, 'err'); }
    };
  });
}
if ($('shop-mode-manual')) $('shop-mode-manual').onchange = () => {
  if ($('shop-mode-manual').checked) renderShopMode({pay_confirm_mode:'manual', pending_orders: (window._lastShop&&window._lastShop.pending_orders)||[], sms_enabled:false});
};
if ($('shop-mode-auto')) $('shop-mode-auto').onchange = () => {
  if ($('shop-mode-auto').checked && window._lastShop) {
    renderShopMode({...window._lastShop, pay_confirm_mode:'auto'});
  }
};
if ($('shop-unlim')) $('shop-unlim').onchange = () => {
  if ($('shop-unlim').checked) { $('shop-gib').value = '0'; $('shop-gib').disabled = true; }
  else { $('shop-gib').disabled = false; if (Number($('shop-gib').value||0)===0) $('shop-gib').value=''; }
};
if ($('shop-card-save')) $('shop-card-save').onclick = async () => {
  try {
    const mode = ($('shop-mode-auto') && $('shop-mode-auto').checked) ? 'auto' : 'manual';
    await api('api/shop', {
      action:'card', admin_id: shopAdminId,
      card_number: $('shop-card').value,
      card_name: $('shop-card-name').value,
      business_name: $('shop-biz') ? $('shop-biz').value : '',
      slogan: $('shop-slogan') ? $('shop-slogan').value : '',
      telegram_channel: $('shop-tg-ch') ? $('shop-tg-ch').value : '',
      support_phone: $('shop-phone') ? $('shop-phone').value : '',
      support_telegram: $('shop-tg-sup') ? $('shop-tg-sup').value : '',
      pay_confirm_mode: mode,
    });
    flash('تنظیمات فروش ذخیره شد.', 'ok');
    loadShop();
  } catch (e) { flash(e.message, 'err'); }
};
if ($('shop-plan-add')) $('shop-plan-add').onclick = async () => {
  try {
    const unlim = $('shop-unlim') && $('shop-unlim').checked;
    await api('api/shop', {
      action:'add_plan', admin_id: shopAdminId,
      title: $('shop-title').value,
      gib: unlim ? 0 : Number($('shop-gib').value||0),
      days: Number($('shop-days').value||0),
      user_count: Number(($('shop-users') && $('shop-users').value) || 1),
      price_toman: Number($('shop-price').value||0),
    });
    flash('پلن اضافه شد.', 'ok');
    $('shop-title').value=''; $('shop-gib').value=''; $('shop-days').value=''; $('shop-price').value='';
    if ($('shop-users')) $('shop-users').value='1';
    if ($('shop-unlim')) { $('shop-unlim').checked=false; $('shop-gib').disabled=false; }
    loadShop();
  } catch (e) { flash(e.message, 'err'); }
};
async function loadMonthly(){
  const d = await api('api/monthly?months=12');
  if (!d) return;
  const box = $('monthly-box');
  if (!d.months || !d.months.length){ box.innerHTML = '<div class="empty">هنوز فروش ماهانه‌ای ثبت نشده.</div>'; return; }
  box.innerHTML = d.months.map(m => {
    const title = esc(m.year_month_fa || m.year_month) + (m.year_month_fa ? ' <span class="mut" style="font-size:12px">(' + esc(m.year_month) + ')</span>' : '');
    const ads = readOnly ? '' : ((m.admins||[]).map(a =>
      `<div class="item" style="padding:8px 0"><div><b>${esc(a.username)}</b><div class="mut">#${a.admin_id} · ${a.charge_count} تسویه</div></div><div><b>${esc(a.sales_h)}</b><div class="mut">${esc(a.sales_bytes_h)}</div></div></div>`
    ).join('') || '<div class="empty">جزئیات ادمین نیست</div>');
    const kpis = readOnly
      ? `<div class="kpi" style="margin-bottom:10px;grid-template-columns:1fr 1fr">
        <div><span class="mut">خرید از پنل (فروش ثبت‌شده)</span><b>${esc(m.sales_h)}</b></div>
        <div><span class="mut">حجم</span><b>${esc(m.sales_bytes_h)}</b></div>
      </div>`
      : `<div class="kpi" style="margin-bottom:10px">
        <div><span class="mut">فروش</span><b>${esc(m.sales_h)}</b></div>
        <div><span class="mut">هزینه</span><b>${esc(m.cost_h)}</b></div>
        <div class="${m.profit_toman>=0?'ok':'hi'}"><span class="mut">سود/زیان</span><b>${esc(m.profit_h)}</b></div>
        <div><span class="mut">بخشش</span><b>${esc(m.waive_h)}</b></div>
      </div>`;
    return `<div style="margin-bottom:22px;padding-bottom:16px;border-bottom:1px solid var(--line)">
      <h2 style="margin:0 0 8px">${title}</h2>
      ${kpis}
      ${ads}
    </div>`;
  }).join('');
}
async function loadCosts(){
  const [c, m] = await Promise.all([api('api/costs'), api('api/monthly?months=12')]);
  if (!c) return;
  if ($('cost-ym') && !$('cost-ym').value) $('cost-ym').value = c.current_month || '';
  const pb = $('profit-box');
  if (m && m.months && m.months.length) {
    pb.innerHTML = `<table><thead><tr><th>ماه</th><th>فروش</th><th>جمع هزینه</th><th>سود/زیان</th></tr></thead><tbody>${
      m.months.map(x => `<tr><td>${esc(x.year_month_fa || x.year_month)}</td><td class="num">${esc(x.sales_h)}</td><td class="num">${esc(x.cost_h)}</td><td class="num">${esc(x.profit_h)}</td></tr>`).join('')
    }</tbody></table>`;
  } else pb.innerHTML = '<div class="empty">داده‌ای نیست.</div>';
  const box = $('costs-box');
  if (!c.items.length) box.innerHTML = '<div class="empty">هزینه‌ای ثبت نشده.</div>';
  else {
    box.innerHTML = `<table><thead><tr><th>ماه</th><th>مبلغ</th><th>یادداشت</th><th></th></tr></thead><tbody>${
      c.items.map(i => `<tr>
        <td>${esc(i.year_month_fa || i.year_month)}<div class="mut">${esc(i.year_month)}</div></td>
        <td class="num">${esc(i.amount_h)}</td>
        <td class="mut">${esc(i.note||'')}</td>
        <td style="white-space:nowrap">
          <button class="ghost cost-edit" type="button" data-id="${i.id}" data-ym="${esc(i.year_month)}" data-amt="${i.amount_toman}" data-note="${esc(i.note||'')}">ویرایش</button>
          <button class="danger cost-del" type="button" data-id="${i.id}">حذف</button>
        </td>
      </tr>`).join('')
    }</tbody></table>`;
    box.querySelectorAll('.cost-del').forEach(btn => {
      btn.onclick = async () => {
        if (!confirm('این ردیف هزینه حذف شود؟')) return;
        try {
          const d = await api('api/costs', {action: 'delete', id: Number(btn.dataset.id)});
          flash(d.message || 'حذف شد.', 'ok');
          loadCosts();
        } catch (e) { flash(e.message, 'err'); }
      };
    });
    box.querySelectorAll('.cost-edit').forEach(btn => {
      btn.onclick = async () => {
        const curAmt = Number(btn.dataset.amt || 0);
        const curNote = btn.dataset.note || '';
        const curYm = btn.dataset.ym || '';
        const amtS = prompt('مبلغ تومان:', String(curAmt));
        if (amtS === null) return;
        const noteS = prompt('یادداشت:', curNote);
        if (noteS === null) return;
        const ymS = prompt('ماه شمسی (مثل 1405-07):', curYm);
        if (ymS === null) return;
        try {
          const d = await api('api/costs', {
            action: 'update',
            id: Number(btn.dataset.id),
            amount: Number(amtS),
            note: noteS,
            year_month: ymS,
          });
          flash(d.message || 'ویرایش شد.', 'ok');
          loadCosts();
        } catch (e) { flash(e.message, 'err'); }
      };
    });
  }
}
function fmtGibClient(n){
  n = Number(n||0);
  if (!n) return '۰';
  const gib = n / (1024**3);
  if (gib >= 1) return gib.toLocaleString('fa-IR', {maximumFractionDigits: 2}) + ' گیگ';
  const mib = n / (1024**2);
  if (mib >= 1) return mib.toLocaleString('fa-IR', {maximumFractionDigits: 1}) + ' مگ';
  return Math.round(n).toLocaleString('fa-IR') + ' بایت';
}
async function loadWaives(){
  const d = await api('api/waives');
  if (!d) return;
  const box = $('waives-box');
  const items = d.items || [];
  if (!items.length){ box.innerHTML = '<div class="empty">درخواست حذفی وجود ندارد</div>'; return; }
  box.innerHTML = `<table><thead><tr><th>زمان</th><th>ادمین</th><th>کاربر</th><th>مصرف</th><th>سقف / بدهی</th><th>مبلغ</th><th>دلیل</th><th>انقضا</th><th></th></tr></thead><tbody>${
    items.map(w => `<tr>
      <td>${new Date(w.ts*1000).toLocaleString('fa-IR')}</td>
      <td>#${w.admin_id}</td>
      <td><b>${esc(w.username)}</b><div class="mut">id=${w.user_id}</div></td>
      <td class="num"><b>${esc(w.used_h || fmtGibClient(w.used_bytes))}</b></td>
      <td class="mut" style="font-size:12px">سقف ${esc(w.limit_h || fmtGibClient(w.limit_bytes))}<div>بدهی حجم ${esc(w.delta_h || fmtGibClient(w.delta_bytes))}</div></td>
      <td class="num">${Number(w.toman||0).toLocaleString('fa-IR')} تومان</td>
      <td class="mut" style="font-size:12px">${esc(w.reason||'')}<div>توسط ${esc(w.requested_by||'')}</div></td>
      <td>${new Date(w.expires_ts*1000).toLocaleString('fa-IR')}</td>
      <td>${readOnly ? (w.status||'pending') : `<button class="btn wa-ok" data-id="${w.id}" type="button">تأیید</button> <button class="ghost wa-no" data-id="${w.id}" type="button">رد</button>`}</td>
    </tr>`).join('')}</tbody></table>`;
  if (!readOnly) {
    box.querySelectorAll('.wa-ok').forEach(b => b.onclick = () => decideWaive(Number(b.dataset.id), true));
    box.querySelectorAll('.wa-no').forEach(b => b.onclick = () => decideWaive(Number(b.dataset.id), false));
  }
}
async function decideWaive(id, approve){
  if (!confirm(approve ? 'بخشش تأیید شود؟ بدهی این یوزر صفر می‌شود.' : 'درخواست رد شود؟')) return;
  try {
    const d = await api('api/waive/decide', {id, approve});
    flash(d.message || 'انجام شد.', 'ok');
    loadWaives();
  } catch (e) { flash(e.message, 'err'); }
}
$('cost-save') && ($('cost-save').onclick = async () => {
  try {
    const d = await api('api/costs', {
      action: 'add',
      year_month: $('cost-ym').value,
      amount: Number($('cost-amt').value||0),
      note: $('cost-note').value||'',
    });
    flash(d.message || 'ردیف هزینه اضافه شد.', 'ok');
    $('cost-amt').value = '';
    $('cost-note').value = '';
    loadCosts();
  } catch (e) { flash(e.message, 'err'); }
});
async function loadSettings(){
  const d = await api('api/settings');
  if (!d) return;
  $('sms-enabled').checked = !!d.sms_enabled;
  $('sms-senders').value = d.sms_senders || '';
  $('sms-account').value = d.sms_account || '';
  $('sms-digits').value = d.sms_suffix_digits || 3;
  $('sms-tg').checked = !!d.sms_notify_telegram;
  $('sms-url').textContent = d.webhook_url || '';
  $('sms-token').textContent = d.sms_token || '';
  const box = $('sms-log');
  if (!d.recent || !d.recent.length) box.innerHTML = '<div class="empty">هنوز پیامکی نیامده.</div>';
  else box.innerHTML = `<table><thead><tr><th>زمان</th><th>فرستنده</th><th>مبلغ</th><th>وضعیت</th><th>توضیح</th></tr></thead><tbody>${
    d.recent.map(r => `<tr>
      <td>${new Date(r.ts*1000).toLocaleString('fa-IR')}</td>
      <td>${esc(r.sender)}</td>
      <td class="num">${r.amount!=null ? Number(r.amount).toLocaleString('fa-IR') : '-'}</td>
      <td>${esc(r.status)}</td>
      <td class="mut" style="font-size:12px">${esc(r.detail||'')}${r.admin_id?(' · #'+r.admin_id):''}</td>
    </tr>`).join('')}</tbody></table>`;
}
$('sms-save') && ($('sms-save').onclick = async () => {
  try {
    const d = await api('api/settings', {
      sms_enabled: $('sms-enabled').checked,
      sms_senders: $('sms-senders').value,
      sms_account: $('sms-account').value,
      sms_suffix_digits: Number($('sms-digits').value||3),
      sms_notify_telegram: $('sms-tg').checked,
    });
    flash('تنظیمات ذخیره شد.', 'ok');
    $('sms-url').textContent = d.webhook_url || '';
    $('sms-token').textContent = d.sms_token || '';
    loadSettings();
  } catch (e) { flash(e.message, 'err'); }
});
$('sms-regen') && ($('sms-regen').onclick = async () => {
  if (!confirm('توکن قبلی باطل می‌شود. اپ گوشی را هم باید آپدیت کنید. ادامه؟')) return;
  try {
    const d = await api('api/settings', {regen_token: true});
    flash('توکن جدید ساخته شد.', 'ok');
    $('sms-token').textContent = d.sms_token || '';
    $('sms-url').textContent = d.webhook_url || '';
  } catch (e) { flash(e.message, 'err'); }
});
function bindAdminActions(){
  if ($('only-delta')) $('only-delta').onchange = () => { if (lastAdmin) renderAdmin(lastAdmin, lastHist); };
  if ($('report-copy')) $('report-copy').onclick = () => copyReport();
  if ($('report-dl')) $('report-dl').onclick = () => downloadReport();
  if ($('save-price')) $('save-price').onclick = async () => {
    const targetId = Number(adminId);
    if (readOnly && targetId === meAdminId) {
      flash('نمی‌توانید قیمت حساب خودتان را عوض کنید.', 'err');
      return;
    }
    try {
      const d = await api('api/price', {admin_id: targetId, price: Number($('price').value)});
      flash('قیمت ذخیره شد.', 'ok'); renderAdmin(d, await api('api/history?id='+adminId));
    } catch (e) { flash(e.message, 'err'); }
  };
  if ($('baseline')) $('baseline').onclick = async () => {
    const net = lastAdmin && lastAdmin.network;
    const q = net
      ? 'سقف کل شبکه (مدیر ارشد + مدیران) بدون دریافت ثبت شود؟'
      : 'سقف فعلی بدون دریافت ثبت شود؟ دوره‌های بعد فقط افزایش سقف حساب می‌شود.';
    if (!confirm(q)) return;
    try { const d = await api('api/settle', {admin_id: Number(adminId), kind:'baseline'}); flash(d.message,'ok'); loadAdmin(); }
    catch (e) { flash(e.message,'err'); }
  };
  if ($('charge')) $('charge').onclick = async () => {
    if (!lastAdmin) return;
    const net = lastAdmin.network;
    const total = net ? Number(net.total) || 0 : Number(lastAdmin.total) || 0;
    const totalH = net ? net.total_h : lastAdmin.total_h;
    const paidEl = $('paid');
    const paid = Number(paidEl && paidEl.value !== '' ? paidEl.value : total);
    if (!Number.isFinite(paid) || paid < 0) { flash('مبلغ دریافتی نامعتبر است.', 'err'); return; }
    if (paid > total) { flash('مبلغ دریافتی بیشتر از مجموع بدهی است.', 'err'); return; }
    const remain = total - paid;
    const msg = remain > 0
      ? ((net ? 'بدهی شبکه ' : 'مجموع بدهی ') + totalH + ' · دریافتی ' + paid.toLocaleString('fa-IR') + ' تومان · بدهی باقی ' + remain.toLocaleString('fa-IR') + ' تومان.\\nدوره بسته می‌شود و مانده روی مدیر ارشد می‌ماند. ادامه؟')
      : ((net ? 'تسویه کامل شبکه ' : 'تسویه کامل ') + totalH + ' ثبت شود؟');
    if (!confirm(msg)) return;
    try {
      const d = await api('api/settle', {admin_id: Number(adminId), kind:'charge', paid});
      flash(d.message,'ok'); loadAdmin();
    } catch (e) { flash(e.message,'err'); }
  };
}
bindAdminActions();
</script>
</body>
</html>
"""



def load_pay_html() -> str:
    """Decoy shop landing for /pay/ (light static HTML)."""
    for root in (Path(__file__).resolve().parent, Path("/usr/local/lib/settle-web")):
        fp = root / "pay_portal.html"
        if fp.is_file():
            return fp.read_text(encoding="utf-8")
    return (
        "<!doctype html><meta charset=utf-8><title>shop</title>"
        "<p>pay_portal.html missing</p>"
    )



PAGES = {"/", "/index.html", "/docs", "/settings", "/monthly", "/costs", "/waives", "/shop"}
PAY_PAGES = {"/pay", "/pay/"}


def settings_payload(req_host: str = "", forwarded_proto: str = "") -> dict:
    cfg = sms_settings()
    # Always show the public nginx URL phones must use (not loopback).
    host = "panel.jetengine.ir:2096"
    base = f"https://{host}/settle"
    token = cfg["sms_token"]
    return {
        "sms_enabled": cfg.get("sms_enabled") == "1",
        "sms_senders": cfg.get("sms_senders") or "",
        "sms_account": cfg.get("sms_account") or "",
        "sms_suffix_digits": as_int(cfg.get("sms_suffix_digits"), 3),
        "sms_notify_telegram": cfg.get("sms_notify_telegram") != "0",
        "sms_token": token,
        "webhook_url": f"{base}/api/sms?token={token}",
        "recent": list_sms(25),
    }


def save_sms_settings(data: dict) -> dict:
    if data.get("regen_token"):
        setting_set("sms_token", secrets.token_urlsafe(24))
    if "sms_enabled" in data:
        setting_set("sms_enabled", "1" if data.get("sms_enabled") else "0")
    if "sms_senders" in data:
        senders = ",".join(
            s.strip() for s in str(data.get("sms_senders") or "").split(",") if s.strip()
        )
        setting_set("sms_senders", senders or "B.QMEHRIRAN")
    if "sms_account" in data:
        setting_set("sms_account", re.sub(r"\D", "", str(data.get("sms_account") or "")))
    if "sms_suffix_digits" in data:
        digits = as_int(data.get("sms_suffix_digits"), 3)
        setting_set("sms_suffix_digits", str(max(1, min(6, digits))))
    if "sms_notify_telegram" in data:
        setting_set("sms_notify_telegram", "1" if data.get("sms_notify_telegram") else "0")
    return sms_settings()


class Handler(BaseHTTPRequestHandler):
    server_version = "settle-web/1"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return

    def _cookie(self) -> str:
        raw = self.headers.get("Cookie") or ""
        name = _cfg.get("COOKIE_NAME") or "settleweb"
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    def _session(self) -> dict | None:
        info = session_info(self._cookie())
        if info and info["role"] == "ro" and not admin_active(info["admin_id"]):
            return None
        return info

    def _client_ip(self) -> str:
        return (self.headers.get("X-Real-IP") or self.client_address[0] or "").strip()

    def _secure(self) -> bool:
        return (self.headers.get("X-Forwarded-Proto") or "").lower() == "https"

    def _send(self, code: int, body: bytes, ctype: str, extra: list[tuple[str, str]] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
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

    def _set_cookie_header(self, token: str, clear: bool = False, max_age: int = OPERATOR_TTL) -> tuple[str, str]:
        name = _cfg.get("COOKIE_NAME") or "settleweb"
        flags = "HttpOnly; SameSite=Strict; Path=/"
        if self._secure():
            flags += "; Secure"
        if clear:
            return "Set-Cookie", f"{name}=; Max-Age=0; {flags}"
        return "Set-Cookie", f"{name}={token}; Max-Age={max_age}; {flags}"

    def _ok(self, obj: dict, code: int = 200) -> None:
        self._send(*json_bytes(obj, code))

    def _fail(self, msg: str, code: int = 400) -> None:
        self._send(*json_bytes({"error": msg}, code))

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        raw_path = parsed.path or "/"
        path = raw_path.rstrip("/") or "/"
        # Fonts/assets for settle UI (no auth). Browser: /settle/static/... → here /static/...
        if raw_path.startswith("/static/"):
            self._pay_static(raw_path[len("/static/") :])
            return
        # Public customer pay portal (no login).
        if path == "/pay" or raw_path.startswith("/pay/"):
            self._pay_get(parsed, path if path == "/pay" else raw_path)
            return
        try:
            sess = self._session()
        except Exception as e:  # noqa: BLE001
            self._fail(str(e), 500)
            return
        if path in PAGES:
            if not sess:
                self._send(200, LOGIN_HTML.replace("ERR", "").encode("utf-8"), "text/html; charset=utf-8")
                return
            self._send(200, APP_HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if not sess:
            self._send(*json_bytes({"error": "auth"}, 401))
            return
        q = parse_qs(parsed.query)
        is_op = sess["role"] == "op"
        try:
            if path == "/api/shop":
                aid = sess["admin_id"] if not is_op else as_int((q.get("id") or ["0"])[0])
                if is_op and aid < 1:
                    aid = as_int((q.get("id") or ["0"])[0])
                if not is_op:
                    aid = sess["admin_id"]
                if aid < 1:
                    self._fail("ادمین نامعتبر است.")
                    return
                self._ok(shop_payload(aid))
                return
            if path == "/api/me":
                me = {
                    "role": sess["role"],
                    "admin_id": sess["admin_id"],
                    "parent_username": "",
                    "username": "",
                }
                if not is_op:
                    aid = int(sess["admin_id"])
                    rows = panel_query("SELECT username FROM admins WHERE id=?", [aid])
                    me["username"] = (rows[0].get("username") if rows else "") or ""
                    kids = children_of(aid)
                    me["parent_id"] = parent_of(aid)
                    me["child_ids"] = kids
                    me["is_parent"] = bool(kids)
                    me["is_child"] = me["parent_id"] is not None
                    if me["parent_id"]:
                        prows = panel_query(
                            "SELECT username FROM admins WHERE id=?", [me["parent_id"]]
                        )
                        me["parent_username"] = (
                            (prows[0].get("username") if prows else "")
                            or f"#{me['parent_id']}"
                        )
                else:
                    me["is_parent"] = False
                    me["is_child"] = False
                    me["child_ids"] = []
                    me["parent_id"] = None
                    # مالک (ادمین ۱) یا نمایش نام اپراتور
                    oid = int(sess["admin_id"] or 0) or 1
                    rows = panel_query("SELECT username FROM admins WHERE id=?", [oid])
                    me["username"] = (
                        (rows[0].get("username") if rows else "")
                        or (_cfg.get("AUTH_USER") or "settle")
                    )
                    if int(sess["admin_id"] or 0) < 1:
                        me["admin_id"] = 0
                self._ok(me)
                return
            if path == "/api/admins":
                if is_op:
                    self._ok(list_admins())
                    return
                aid = int(sess["admin_id"])
                kids = children_of(aid)
                if not kids:
                    self._fail("دسترسی ندارید.", 403)
                    return
                self._ok(list_admins(scope_ids=[aid] + kids))
                return
            if path in ("/api/admin", "/api/history"):
                if is_op:
                    aid = int((q.get("id") or ["0"])[0])
                else:
                    req = int((q.get("id") or [str(sess["admin_id"])])[0] or sess["admin_id"])
                    aid = req if can_view_admin(sess, req) else int(sess["admin_id"])
                    if not can_view_admin(sess, aid):
                        self._fail("دسترسی ندارید.", 403)
                        return
                if aid < 1:
                    self._fail("ادمین نامعتبر است.")
                    return
                if not is_op and not can_view_admin(sess, aid):
                    self._fail("دسترسی ندارید.", 403)
                    return
                self._ok(build_rows(aid) if path == "/api/admin" else history_payload(aid))
                return
            if path == "/api/settings":
                if not is_op:
                    self._fail("دسترسی ندارید.", 403)
                    return
                host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or ""
                proto = self.headers.get("X-Forwarded-Proto") or ""
                self._ok(settings_payload(host, proto))
                return
            if path == "/api/monthly":
                months = as_int((q.get("months") or ["12"])[0], 12)
                if is_op:
                    aid = as_int((q.get("id") or ["0"])[0]) or None if q.get("id") else None
                else:
                    req = as_int((q.get("id") or [str(sess["admin_id"])])[0], sess["admin_id"])
                    if not can_view_admin(sess, req):
                        self._fail("دسترسی ندارید.", 403)
                        return
                    aid = req
                self._ok(monthly_payload(months=months, admin_id=aid))
                return
            if path == "/api/costs":
                if not is_op:
                    self._fail("دسترسی ندارید.", 403)
                    return
                self._ok(costs_payload())
                return
            if path == "/api/waives":
                conn = db()
                try:
                    if is_op:
                        items = ledger.list_waives(conn, status="pending", limit=80)
                    else:
                        aid = int(sess["admin_id"])
                        kids = children_of(aid)
                        if kids:
                            items = []
                            for wid in [aid] + kids:
                                items.extend(
                                    ledger.list_waives(
                                        conn, admin_id=wid, status="pending", limit=40
                                    )
                                )
                        else:
                            items = ledger.list_waives(
                                conn, admin_id=aid, status="pending", limit=40
                            )
                    conn.commit()
                finally:
                    conn.close()
                for it in items:
                    it["used_h"] = fmt_gib(int(it.get("used_bytes") or 0))
                    it["limit_h"] = fmt_gib(int(it.get("limit_bytes") or 0))
                    it["delta_h"] = fmt_gib(int(it.get("delta_bytes") or 0))
                self._ok({"items": items})
                return
        except Exception as e:  # noqa: BLE001
            self._fail(str(e), 500)
            return
        self._send(404, b"not found", "text/plain")

    def _pay_get(self, parsed, path: str) -> None:
        q = parse_qs(parsed.query)
        if path in ("/pay", "/pay/"):
            self._send(200, load_pay_html().encode("utf-8"), "text/html; charset=utf-8")
            return
        if path.startswith("/pay/static/"):
            self._pay_static(path[len("/pay/static/") :])
            return
        try:
            if path == "/pay/api/lookup":
                uname = (q.get("username") or [""])[0].strip()
                self._ok(lookup_pay_user(uname))
                return
            if path == "/pay/api/order":
                oid = as_int((q.get("id") or ["0"])[0])
                if oid < 1:
                    self._fail("شناسه سفارش نامعتبر است.")
                    return
                conn = db()
                try:
                    order = pay.get_order(conn, oid)
                finally:
                    conn.close()
                if not order:
                    self._fail("سفارش پیدا نشد.", 404)
                    return
                pub = _order_public(order)
                card = {}
                conn = db()
                try:
                    card = pay.get_seller_card(conn, int(order["admin_id"]))
                finally:
                    conn.close()
                if pub:
                    pub["card_number"] = card.get("card_number") or ""
                    pub["card_name"] = card.get("card_name") or ""
                self._ok({"order": pub})
                return
        except ValueError as e:
            self._fail(str(e), 400)
            return
        except Exception as e:  # noqa: BLE001
            self._fail(str(e), 500)
            return
        self._send(404, b"not found", "text/plain")

    def _pay_static(self, name: str) -> None:
        # Only allow simple filenames under settle-web/static/
        safe = Path(name).name
        if not safe or safe != name or ".." in name:
            self._send(404, b"not found", "text/plain")
            return
        roots = [
            Path(__file__).resolve().parent / "static",
            Path("/usr/local/lib/settle-web/static"),
        ]
        for root in roots:
            fp = root / safe
            if fp.is_file():
                data = fp.read_bytes()
                ctype = "application/octet-stream"
                if safe.endswith(".woff2"):
                    ctype = "font/woff2"
                elif safe.endswith(".woff"):
                    ctype = "font/woff"
                elif safe.endswith(".css"):
                    ctype = "text/css; charset=utf-8"
                self._send(
                    200,
                    data,
                    ctype,
                    [("Cache-Control", "public, max-age=86400")],
                )
                return
        self._send(404, b"not found", "text/plain")

    def _pay_post(self, path: str) -> None:
        data = self._read_json()
        try:
            if path == "/pay/api/order":
                self._ok(
                    create_pay_order_for_user(
                        str(data.get("username") or ""),
                        as_int(data.get("plan_id")),
                    )
                )
                return
        except Exception as e:  # noqa: BLE001
            if isinstance(e, ValueError):
                self._fail(str(e), 400)
                return
            self._fail(str(e), 500)
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
        if path == "/api/sms":
            self._sms_ingest()
            return
        if path.startswith("/pay"):
            self._pay_post(path)
            return
        try:
            sess = self._session()
        except Exception as e:  # noqa: BLE001
            self._fail(str(e), 500)
            return
        if not sess:
            self._send(*json_bytes({"error": "auth"}, 401))
            return
        is_op = sess["role"] == "op"
        data = self._read_json()
        try:
            if path == "/api/shop":
                aid = sess["admin_id"] if not is_op else as_int(data.get("admin_id") or sess["admin_id"])
                if not is_op:
                    aid = sess["admin_id"]
                if is_op and as_int(data.get("admin_id")) >= 1:
                    aid = as_int(data.get("admin_id"))
                if aid < 1:
                    self._fail("ادمین نامعتبر است.")
                    return
                action = str(data.get("action") or "card").lower()
                if action == "approve_order":
                    self._ok(
                        approve_pay_order(
                            as_int(data.get("id") or data.get("order_id")),
                            admin_id=None if is_op else aid,
                        )
                    )
                    return
                if action == "reject_order":
                    self._ok(
                        reject_pay_order(
                            as_int(data.get("id") or data.get("order_id")),
                            admin_id=None if is_op else aid,
                        )
                    )
                    return
                conn = db()
                try:
                    if action == "card":
                        pay.set_seller_shop(
                            conn,
                            aid,
                            card_number=str(data.get("card_number") or ""),
                            card_name=str(data.get("card_name") or ""),
                            business_name=str(data.get("business_name") or ""),
                            telegram_channel=str(data.get("telegram_channel") or ""),
                            support_phone=str(data.get("support_phone") or ""),
                            support_telegram=str(data.get("support_telegram") or ""),
                            slogan=str(data.get("slogan") or ""),
                            pay_confirm_mode=str(data.get("pay_confirm_mode") or "manual"),
                        )
                        self._ok({"ok": True, "message": "تنظیمات فروش ذخیره شد.", **shop_payload(aid)})
                        return
                    if action == "add_plan":
                        pay.add_plan(
                            conn,
                            admin_id=aid,
                            title=str(data.get("title") or ""),
                            gib=float(data.get("gib") or 0),
                            days=as_int(data.get("days")),
                            price_toman=as_int(data.get("price_toman") or data.get("price")),
                            user_count=as_int(data.get("user_count") or data.get("users") or 1),
                        )
                        self._ok({"ok": True, "message": "پلن اضافه شد.", **shop_payload(aid)})
                        return
                    if action == "update_plan":
                        pay.update_plan(
                            conn,
                            as_int(data.get("id") or data.get("plan_id")),
                            admin_id=None if is_op else aid,
                            title=None if data.get("title") is None else str(data.get("title") or ""),
                            gib=None if data.get("gib") in (None, "") else float(data.get("gib")),
                            days=None if data.get("days") in (None, "") else as_int(data.get("days")),
                            price_toman=(
                                None
                                if data.get("price_toman") in (None, "") and data.get("price") in (None, "")
                                else as_int(data.get("price_toman") or data.get("price"))
                            ),
                            user_count=(
                                None
                                if data.get("user_count") in (None, "") and data.get("users") in (None, "")
                                else as_int(data.get("user_count") or data.get("users"))
                            ),
                            active=None if data.get("active") is None else bool(data.get("active")),
                        )
                        self._ok({"ok": True, "message": "پلن به‌روز شد.", **shop_payload(aid)})
                        return
                    if action == "delete_plan":
                        pay.delete_plan(
                            conn,
                            as_int(data.get("id") or data.get("plan_id")),
                            admin_id=None if is_op else aid,
                        )
                        self._ok({"ok": True, "message": "پلن حذف شد.", **shop_payload(aid)})
                        return
                finally:
                    conn.close()
                self._fail("عملیات فروشگاه نامعتبر است.")
                return
            if path == "/api/waive/request":
                aid = sess["admin_id"] if not is_op else as_int(data.get("admin_id"))
                if is_op and aid < 1:
                    aid = as_int(data.get("admin_id"))
                if not is_op:
                    req = as_int(data.get("admin_id") or sess["admin_id"])
                    if not can_view_admin(sess, req):
                        self._fail("دسترسی ندارید.", 403)
                        return
                    aid = req
                uid = as_int(data.get("user_id"))
                if aid < 1 or uid < 1:
                    self._fail("ادمین یا کاربر نامعتبر است.")
                    return
                who = "مدیر" if is_op else f"ادمین#{sess['admin_id']}"
                if is_op:
                    try:
                        rows = panel_query("SELECT username FROM admins WHERE id=?", [aid])
                        if rows:
                            who = f"مدیر/{rows[0].get('username') or aid}"
                    except Exception:
                        pass
                else:
                    try:
                        rows = panel_query(
                            "SELECT username FROM admins WHERE id=?", [sess["admin_id"]]
                        )
                        who = (rows[0].get("username") if rows else "") or who
                    except Exception:
                        pass
                self._ok(
                    request_waive(aid, uid, str(data.get("reason") or ""), who)
                )
                return
            if path == "/api/waive/decide":
                if not is_op:
                    self._fail("فقط مدیر می‌تواند تأیید/رد کند.", 403)
                    return
                rid = as_int(data.get("id"))
                if rid < 1:
                    self._fail("شناسه درخواست نامعتبر است.")
                    return
                approve = bool(data.get("approve"))
                self._ok(decide_waive_request(rid, approve))
                return
            if path == "/api/costs":
                if not is_op:
                    self._fail("دسترسی ندارید.", 403)
                    return
                action = str(data.get("action") or "add").lower()
                if action == "delete":
                    self._ok(remove_cost(as_int(data.get("id"))))
                    return
                if action == "update":
                    self._ok(
                        edit_cost(
                            as_int(data.get("id")),
                            amount=as_int(data.get("amount")) if data.get("amount") not in (None, "") else None,
                            note=None if data.get("note") is None else str(data.get("note") or ""),
                            year_month=(
                                None
                                if data.get("year_month") in (None, "")
                                else str(data.get("year_month") or "")
                            ),
                        )
                    )
                    return
                self._ok(
                    save_cost(
                        str(data.get("year_month") or ""),
                        as_int(data.get("amount")),
                        str(data.get("note") or ""),
                    )
                )
                return
            if path == "/api/agency":
                if not is_op:
                    self._fail("فقط مدیر می‌تواند زیرمجموعه تعیین کند.", 403)
                    return
                aid = as_int(data.get("admin_id"))
                raw_parent = data.get("parent_id", None)
                if raw_parent in ("", None):
                    parent = None
                else:
                    parent = as_int(raw_parent)
                    if parent < 1:
                        parent = None
                self._ok(set_agency(aid, parent))
                return
            if path == "/api/price":
                aid = int(data.get("admin_id") or 0)
                price = int(data.get("price") or 0)
                if aid < 1 or price < 1 or price > 10_000_000:
                    self._fail("قیمت نامعتبر است.")
                    return
                if is_op:
                    pass
                else:
                    mine = int(sess["admin_id"])
                    # مدیر ارشد هرگز قیمت حساب خودش را عوض نمی‌کند
                    if aid == mine:
                        self._fail(
                            "نمی‌توانید قیمت حساب خودتان را عوض کنید؛ فقط قیمت مدیران زیرمجموعه.",
                            403,
                        )
                        return
                    if parent_of(aid) != mine:
                        self._fail(
                            "فقط می‌توانید قیمت مدیران زیر نظر خودتان را عوض کنید.",
                            403,
                        )
                        return
                set_price(aid, price)
                self._ok(build_rows(aid))
                return
            if not is_op:
                self._fail("ثبت تسویه فقط با حساب مدیر ممکن است.", 403)
                return
            if path == "/api/settle":
                aid = int(data.get("admin_id") or 0)
                kind = str(data.get("kind") or "")
                if aid < 1:
                    self._fail("ادمین نامعتبر است.")
                    return
                paid = data.get("paid", None)
                if paid is not None and paid != "":
                    try:
                        paid = int(paid)
                    except (TypeError, ValueError):
                        self._fail("مبلغ دریافتی نامعتبر است.")
                        return
                else:
                    paid = None
                # network: true/false/omit — omit = auto (والد با زیرمجموعه ⇒ شبکه)
                net_flag = data.get("network", None)
                if net_flag is None:
                    network = None
                else:
                    network = bool(net_flag)
                self._ok(do_settle(aid, kind, paid=paid, network=network))
                return
            if path == "/api/debt":
                aid = int(data.get("admin_id") or 0)
                try:
                    debt = int(data.get("debt"))
                except (TypeError, ValueError):
                    self._fail("مبلغ بدهی نامعتبر است.")
                    return
                if aid < 1 or debt < 0 or debt > 50_000_000_000:
                    self._fail("بدهی نامعتبر است.")
                    return
                set_debt(aid, debt)
                self._ok(build_rows(aid))
                return
            if path == "/api/settings":
                host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or ""
                proto = self.headers.get("X-Forwarded-Proto") or ""
                save_sms_settings(data)
                self._ok(settings_payload(host, proto))
                return
        except ValueError as e:
            self._fail(str(e), 400)
            return
        except Exception as e:  # noqa: BLE001
            self._fail(str(e), 500)
            return
        self._send(404, b"not found", "text/plain")

    def _sms_extract_token(self, data: dict) -> str:
        q = parse_qs(urlparse(self.path).query)
        return str(
            (data.get("token") or data.get("secret") or data.get("key") or "")
            or (q.get("token") or q.get("secret") or [""])[0]
            or (self.headers.get("X-Sms-Token") or "")
            or (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
        )

    def _sms_resolve_token(self, got: str) -> tuple[bool, int | None]:
        """Return (ok, seller_admin_id|None). None admin = global op token."""
        got = (got or "").strip()
        if not got:
            return False, None
        expect = ensure_sms_token()
        if expect and hmac.compare_digest(got, expect):
            return True, None
        conn = db()
        try:
            aid = pay.find_admin_by_sms_token(conn, got)
        finally:
            conn.close()
        if aid is not None and aid >= 1:
            return True, int(aid)
        return False, None

    def _sms_ingest(self) -> None:
        ctype = (self.headers.get("Content-Type") or "").lower()
        if "json" in ctype:
            data = self._read_json()
        else:
            data = self._read_form()
        ok, seller_aid = self._sms_resolve_token(self._sms_extract_token(data))
        if not ok:
            self._fail("توکن نامعتبر است.", 401)
            return
        sender = (
            data.get("from")
            or data.get("sender")
            or data.get("address")
            or data.get("number")
            or ""
        )
        body = data.get("text") or data.get("body") or data.get("message") or data.get("sms") or ""
        if isinstance(body, list):
            body = body[-1] if body else ""
        if not str(body).strip():
            self._fail("متن پیامک خالی است.")
            return
        try:
            result = process_sms_webhook(
                str(sender), str(body), seller_admin_id=seller_aid
            )
        except Exception as e:  # noqa: BLE001
            self._fail(str(e), 500)
            return
        code = int(result.pop("code", 200) or 200)
        if not result.get("ok") and code == 200:
            code = 400
        self._ok(result, code)

    def _login_fail(self, msg: str = "ورود نامعتبر است. دوباره تلاش کنید.", code: int = 401) -> None:
        html = LOGIN_HTML.replace("ERR", f'<div class="err">{msg}</div>')
        self._send(code, html.encode("utf-8"), "text/html; charset=utf-8")

    def _login(self) -> None:
        ctype = (self.headers.get("Content-Type") or "").lower()
        data = self._read_json() if "json" in ctype else self._read_form()
        user = (data.get("user") or "").strip()
        password = data.get("pass") or data.get("password") or ""
        if not login_allowed(self._client_ip()):
            self._login_fail("تلاش زیاد بود؛ یک دقیقه صبر کنید.", 429)
            return
        if not user or not password or len(user) > 64 or len(password) > 256:
            self._login_fail()
            return
        if hmac.compare_digest(user, _cfg.get("AUTH_USER") or "settle"):
            if not verify_password(password):
                self._login_fail()
                return
            token, ttl = make_session("op"), OPERATOR_TTL
        else:
            try:
                row = panel_admin_by_name(user)
                if (
                    not row
                    or (row.get("status") or "") != "active"
                    or not panel_login(str(row.get("username") or ""), password)
                ):
                    self._login_fail()
                    return
            except RuntimeError as e:
                self._login_fail(str(e), 503)
                return
            aid = as_int(row.get("id"))
            _admin_status[aid] = (time.time(), True)
            # ادمین ۱ = مالک پنل → دسترسی کامل اپراتور (تنظیمات پیامک، هزینه، …)
            if aid == 1:
                token, ttl = make_session("op", 1), OPERATOR_TTL
            else:
                token, ttl = make_session("ro", aid), RESELLER_TTL
        self._send(
            302,
            b"",
            "text/plain",
            [self._set_cookie_header(token, max_age=ttl), ("Location", ".")],
        )


def main() -> None:
    global _cfg
    _cfg = load_cfg()
    if not _cfg.get("AUTH_HASH") or not _cfg.get("SESSION_SECRET"):
        raise SystemExit("missing AUTH_HASH or SESSION_SECRET in config")
    db().close()
    start_scanner()
    listen = _cfg.get("LISTEN") or "127.0.0.1:8789"
    host, _, port_s = listen.rpartition(":")
    httpd = ThreadingHTTPServer((host or "127.0.0.1", int(port_s)), Handler)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
