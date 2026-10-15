"""Anti-delete tracking, waive requests, monthly sales/costs for settle-web."""
from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Callable

try:
    from zoneinfo import ZoneInfo

    TEHRAN = ZoneInfo("Asia/Tehran")
except Exception:  # noqa: BLE001
    TEHRAN = timezone(timedelta(hours=3, minutes=30), name="Asia/Tehran")

GIB = 1024**3
WAIVE_TTL_SEC = 48 * 3600
SCAN_INTERVAL_SEC = 90

JALALI_MONTHS = (
    "",
    "فروردین",
    "اردیبهشت",
    "خرداد",
    "تیر",
    "مرداد",
    "شهریور",
    "مهر",
    "آبان",
    "آذر",
    "دی",
    "بهمن",
    "اسفند",
)


def ensure_tables(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS user_track (
            admin_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL DEFAULT '',
            last_limit INTEGER NOT NULL DEFAULT 0,
            last_used INTEGER NOT NULL DEFAULT 0,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            deleted INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (admin_id, user_id)
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS waive_request (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL DEFAULT '',
            limit_bytes INTEGER NOT NULL DEFAULT 0,
            billed_bytes INTEGER NOT NULL DEFAULT 0,
            delta_bytes INTEGER NOT NULL DEFAULT 0,
            used_bytes INTEGER NOT NULL DEFAULT 0,
            toman INTEGER NOT NULL DEFAULT 0,
            reason TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL,
            requested_by TEXT NOT NULL DEFAULT '',
            ts REAL NOT NULL,
            decided_ts REAL,
            expires_ts REAL NOT NULL
        )"""
    )
    wcols = {r[1] for r in conn.execute("PRAGMA table_info(waive_request)").fetchall()}
    if "used_bytes" not in wcols:
        conn.execute(
            "ALTER TABLE waive_request ADD COLUMN used_bytes INTEGER NOT NULL DEFAULT 0"
        )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS month_cost_item (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            year_month TEXT NOT NULL,
            amount_toman INTEGER NOT NULL DEFAULT 0,
            note TEXT NOT NULL DEFAULT '',
            created_ts REAL NOT NULL
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_month_cost_item_ym ON month_cost_item(year_month)"
    )
    # One-time migrate from old single-row-per-month table if present.
    old = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='month_cost'"
    ).fetchone()
    if old:
        for r in conn.execute(
            "SELECT year_month, amount_toman, note, updated_ts FROM month_cost"
        ).fetchall():
            exists = conn.execute(
                "SELECT 1 FROM month_cost_item WHERE year_month=? AND amount_toman=? AND note=? LIMIT 1",
                (r["year_month"], r["amount_toman"], r["note"] or ""),
            ).fetchone()
            if exists:
                continue
            conn.execute(
                "INSERT INTO month_cost_item(year_month, amount_toman, note, created_ts) "
                "VALUES (?,?,?,?)",
                (
                    r["year_month"],
                    int(r["amount_toman"] or 0),
                    r["note"] or "",
                    float(r["updated_ts"] or time.time()),
                ),
            )
        conn.execute("DROP TABLE month_cost")
    # Migrate Gregorian cost keys (e.g. 2026-10) → Jalali (1405-07).
    for r in conn.execute("SELECT id, year_month FROM month_cost_item").fetchall():
        raw = str(r["year_month"] or "")
        norm = normalize_ym_key(raw, strict=False)
        if norm and norm != raw:
            conn.execute(
                "UPDATE month_cost_item SET year_month=? WHERE id=?",
                (norm, int(r["id"])),
            )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_waive_admin_status ON waive_request(admin_id, status)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_settlement_ts ON settlement(ts)"
    )


def expire_waives(conn: sqlite3.Connection, now: float | None = None) -> int:
    now = now or time.time()
    cur = conn.execute(
        "UPDATE waive_request SET status='expired', decided_ts=? "
        "WHERE status='pending' AND expires_ts < ?",
        (now, now),
    )
    return int(cur.rowcount or 0)


def scan_admin(
    conn: sqlite3.Connection,
    admin_id: int,
    users: list[dict],
    *,
    as_int: Callable,
) -> dict:
    """Refresh user_track from live panel users. Marks missing ones deleted."""
    now = time.time()
    live_ids: set[int] = set()
    for u in users:
        uid = as_int(u.get("id"))
        if uid < 1:
            continue
        live_ids.add(uid)
        limit = max(0, as_int(u.get("data_limit")))
        used = max(0, as_int(u.get("used_traffic")))
        name = str(u.get("username") or "")
        row = conn.execute(
            "SELECT last_limit, deleted FROM user_track WHERE admin_id=? AND user_id=?",
            (admin_id, uid),
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO user_track(admin_id, user_id, username, last_limit, last_used, "
                "first_seen, last_seen, deleted) VALUES (?,?,?,?,?,?,?,0)",
                (admin_id, uid, name, limit, used, now, now),
            )
        else:
            # Never shrink last_limit on live users — reductions don't reduce debt.
            new_limit = max(int(row["last_limit"] or 0), limit)
            conn.execute(
                "UPDATE user_track SET username=?, last_limit=?, last_used=?, last_seen=?, deleted=0 "
                "WHERE admin_id=? AND user_id=?",
                (name, new_limit, used, now, admin_id, uid),
            )

    gone = conn.execute(
        "SELECT user_id, username, last_limit FROM user_track "
        "WHERE admin_id=? AND deleted=0",
        (admin_id,),
    ).fetchall()
    marked = 0
    for g in gone:
        uid = int(g["user_id"])
        if uid in live_ids:
            continue
        conn.execute(
            "UPDATE user_track SET deleted=1, last_seen=? WHERE admin_id=? AND user_id=?",
            (now, admin_id, uid),
        )
        marked += 1
    return {"live": len(live_ids), "tombstoned": marked}


def track_map(conn: sqlite3.Connection, admin_id: int) -> dict[int, dict]:
    rows = conn.execute(
        "SELECT user_id, username, last_limit, last_used, first_seen, last_seen, deleted "
        "FROM user_track WHERE admin_id=?",
        (admin_id,),
    ).fetchall()
    return {int(r["user_id"]): dict(r) for r in rows}


def pending_waive_map(conn: sqlite3.Connection, admin_id: int) -> dict[int, dict]:
    expire_waives(conn)
    rows = conn.execute(
        "SELECT id, user_id, username, delta_bytes, toman, reason, ts, expires_ts "
        "FROM waive_request WHERE admin_id=? AND status='pending'",
        (admin_id,),
    ).fetchall()
    return {int(r["user_id"]): dict(r) for r in rows}


def create_waive_request(
    conn: sqlite3.Connection,
    *,
    admin_id: int,
    user_id: int,
    username: str,
    limit_bytes: int,
    billed_bytes: int,
    toman: int,
    reason: str,
    requested_by: str,
    used_bytes: int = 0,
) -> dict:
    expire_waives(conn)
    existing = conn.execute(
        "SELECT id FROM waive_request WHERE admin_id=? AND user_id=? AND status='pending'",
        (admin_id, user_id),
    ).fetchone()
    if existing:
        raise ValueError("برای این کاربر قبلاً درخواست حذف بدون هزینه ثبت شده و در انتظار تأیید است.")
    delta = max(0, int(limit_bytes) - int(billed_bytes))
    if delta <= 0:
        raise ValueError("این کاربر بدهی باز از بابت سقف ندارد؛ حذفش هزینهٔ جدیدی نمی‌سازد.")
    # Prefer explicit used_bytes; fall back to last tracked usage.
    used = max(0, int(used_bytes or 0))
    if used <= 0:
        tr = conn.execute(
            "SELECT last_used FROM user_track WHERE admin_id=? AND user_id=?",
            (admin_id, user_id),
        ).fetchone()
        if tr:
            used = max(0, int(tr["last_used"] or 0))
    now = time.time()
    conn.execute(
        "INSERT INTO waive_request(admin_id, user_id, username, limit_bytes, billed_bytes, "
        "delta_bytes, used_bytes, toman, reason, status, requested_by, ts, decided_ts, expires_ts) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            admin_id,
            user_id,
            username,
            int(limit_bytes),
            int(billed_bytes),
            delta,
            used,
            int(toman),
            (reason or "")[:400],
            "pending",
            (requested_by or "")[:80],
            now,
            None,
            now + WAIVE_TTL_SEC,
        ),
    )
    rid = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
    row = conn.execute("SELECT * FROM waive_request WHERE id=?", (rid,)).fetchone()
    return dict(row)


def decide_waive(
    conn: sqlite3.Connection,
    *,
    request_id: int,
    approve: bool,
    set_billed: Callable[[int, int, int], None] | None = None,
) -> dict:
    """Approve/reject. On approve, caller should bump ledger billed to limit via set_billed."""
    expire_waives(conn)
    row = conn.execute("SELECT * FROM waive_request WHERE id=?", (request_id,)).fetchone()
    if not row:
        raise ValueError("درخواست پیدا نشد.")
    if row["status"] != "pending":
        raise ValueError(f"این درخواست دیگر pending نیست ({row['status']}).")
    now = time.time()
    if float(row["expires_ts"]) < now:
        conn.execute(
            "UPDATE waive_request SET status='expired', decided_ts=? WHERE id=?",
            (now, request_id),
        )
        raise ValueError("مهلت ۴۸ساعتهٔ این درخواست تمام شده.")
    if approve:
        aid = int(row["admin_id"])
        uid = int(row["user_id"])
        limit = int(row["limit_bytes"])
        if set_billed:
            set_billed(aid, uid, limit)
        # Align track so rebuild stays consistent
        conn.execute(
            "UPDATE user_track SET last_limit=MAX(last_limit, ?) WHERE admin_id=? AND user_id=?",
            (limit, aid, uid),
        )
        conn.execute(
            "INSERT INTO settlement(admin_id, ts, kind, delta_bytes, toman, users, note) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                aid,
                now,
                "waive",
                int(row["delta_bytes"]),
                0,
                1,
                f"بخشش حذف بدون هزینه: {row['username']} (id={uid}) · {int(row['toman']):,} تومان",
            ),
        )
        conn.execute(
            "UPDATE waive_request SET status='approved', decided_ts=? WHERE id=?",
            (now, request_id),
        )
    else:
        conn.execute(
            "UPDATE waive_request SET status='rejected', decided_ts=? WHERE id=?",
            (now, request_id),
        )
    out = conn.execute("SELECT * FROM waive_request WHERE id=?", (request_id,)).fetchone()
    return dict(out)


def list_waives(
    conn: sqlite3.Connection,
    *,
    admin_id: int | None = None,
    status: str | None = "pending",
    limit: int = 50,
) -> list[dict]:
    expire_waives(conn)
    sql = "SELECT * FROM waive_request WHERE 1=1"
    args: list = []
    if admin_id is not None:
        sql += " AND admin_id=?"
        args.append(admin_id)
    if status:
        sql += " AND status=?"
        args.append(status)
    sql += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    out = []
    for r in conn.execute(sql, args).fetchall():
        item = dict(r)
        used = int(item.get("used_bytes") or 0)
        if used <= 0:
            tr = conn.execute(
                "SELECT last_used, last_limit FROM user_track WHERE admin_id=? AND user_id=?",
                (int(item["admin_id"]), int(item["user_id"])),
            ).fetchone()
            if tr:
                used = max(0, int(tr["last_used"] or 0))
                item["used_bytes"] = used
                if int(item.get("limit_bytes") or 0) <= 0:
                    item["limit_bytes"] = int(tr["last_limit"] or 0)
                if item.get("status") == "pending" and used > 0:
                    conn.execute(
                        "UPDATE waive_request SET used_bytes=? WHERE id=? AND used_bytes=0",
                        (used, int(item["id"])),
                    )
        out.append(item)
    return out


def gregorian_to_jalali(gy: int, gm: int, gd: int) -> tuple[int, int, int]:
    g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
    gy2 = gy + 1 if gm > 2 else gy
    days = (
        355666
        + 365 * gy
        + (gy2 + 3) // 4
        - (gy2 + 99) // 100
        + (gy2 + 399) // 400
        + gd
        + g_d_m[gm - 1]
    )
    jy = -1595 + 33 * (days // 12053)
    days %= 12053
    jy += 4 * (days // 1461)
    days %= 1461
    if days > 365:
        jy += (days - 1) // 365
        days = (days - 1) % 365
    if days < 186:
        jm = 1 + days // 31
        jd = 1 + days % 31
    else:
        jm = 7 + (days - 186) // 30
        jd = 1 + (days - 186) % 30
    return jy, jm, jd


def ym_from_ts(ts: float) -> str:
    """Jalali year-month (Asia/Tehran) for a unix timestamp — e.g. 1405-07."""
    local = datetime.fromtimestamp(float(ts), tz=TEHRAN)
    jy, jm, _jd = gregorian_to_jalali(local.year, local.month, local.day)
    return f"{jy}-{jm:02d}"


def current_jalali_ym() -> str:
    return ym_from_ts(time.time())


def normalize_ym_key(year_month: str, *, strict: bool = True) -> str:
    """Accept Jalali YYYY-MM or legacy Gregorian YYYY-MM; return Jalali key."""
    ym = (year_month or "").strip()
    if not (len(ym) == 7 and ym[4] == "-" and ym[:4].isdigit() and ym[5:].isdigit()):
        if strict:
            raise ValueError("ماه باید به صورت YYYY-MM شمسی باشد (مثل 1405-07).")
        return ""
    y, m = int(ym[:4]), int(ym[5:])
    if not (1 <= m <= 12):
        if strict:
            raise ValueError("ماه نامعتبر است.")
        return ""
    # Gregorian years in this system are 2000+; Jalali are 1300–1600.
    if y >= 1700:
        jy, jm, _jd = gregorian_to_jalali(y, m, 1)
        return f"{jy}-{jm:02d}"
    if y < 1200:
        if strict:
            raise ValueError("سال ماه نامعتبر است.")
        return ""
    return f"{y}-{m:02d}"


def ym_label_fa(ym: str) -> str:
    """Human label for a Jalali (or legacy Gregorian) YYYY-MM key."""
    key = normalize_ym_key(ym, strict=False) or (ym or "").strip()
    try:
        y, m = key.split("-", 1)
        jy, jm = int(y), int(m)
    except ValueError:
        return ym
    name = JALALI_MONTHS[jm] if 1 <= jm <= 12 else str(jm)
    return f"{name} {jy}"


def monthly_sales(conn: sqlite3.Connection, months: int = 12, admin_id: int | None = None) -> dict:
    """Aggregate charge settlements and waives by Jalali calendar month (Tehran)."""
    months = max(1, min(36, int(months)))
    cutoff = time.time() - months * 31 * 86400
    args: list = [cutoff]
    where = "WHERE ts >= ?"
    if admin_id is not None:
        where += " AND admin_id=?"
        args.append(admin_id)
    rows = conn.execute(
        f"SELECT admin_id, ts, kind, delta_bytes, toman, users, note FROM settlement {where} ORDER BY ts",
        args,
    ).fetchall()
    by_month: dict[str, dict] = {}
    by_admin: dict[str, dict[int, dict]] = {}
    for r in rows:
        ym = ym_from_ts(float(r["ts"]))
        kind = r["kind"]
        aid = int(r["admin_id"])
        bucket = by_month.setdefault(
            ym,
            {
                "year_month": ym,
                "sales_toman": 0,
                "sales_bytes": 0,
                "charge_count": 0,
                "waive_toman": 0,
                "waive_bytes": 0,
                "waive_count": 0,
            },
        )
        ab = by_admin.setdefault(ym, {}).setdefault(
            aid,
            {
                "admin_id": aid,
                "sales_toman": 0,
                "sales_bytes": 0,
                "charge_count": 0,
                "waive_toman": 0,
                "waive_bytes": 0,
                "waive_count": 0,
            },
        )
        if kind == "charge":
            bucket["sales_toman"] += int(r["toman"] or 0)
            bucket["sales_bytes"] += int(r["delta_bytes"] or 0)
            bucket["charge_count"] += 1
            ab["sales_toman"] += int(r["toman"] or 0)
            ab["sales_bytes"] += int(r["delta_bytes"] or 0)
            ab["charge_count"] += 1
        elif kind == "waive":
            # note embeds estimated toman; prefer row toman (0) + delta for volume
            # Store estimated waived value from note is fragile — use delta_bytes * we don't have price
            # Waive rows store toman=0; keep delta_bytes and count. Optional: parse note.
            bucket["waive_bytes"] += int(r["delta_bytes"] or 0)
            bucket["waive_count"] += 1
            ab["waive_bytes"] += int(r["delta_bytes"] or 0)
            ab["waive_count"] += 1
            # Try extract toman from note "· N تومان"
            note = str(r["note"] or "")
            if "تومان" in note:
                try:
                    part = note.rsplit("·", 1)[-1]
                    digits = "".join(ch for ch in part if ch.isdigit() or ch == ",")
                    digits = digits.replace(",", "")
                    if digits:
                        wt = int(digits)
                        bucket["waive_toman"] += wt
                        ab["waive_toman"] += wt
                except ValueError:
                    pass

    costs: dict[str, dict] = {}
    for r in conn.execute(
        "SELECT year_month, SUM(amount_toman) AS amount_toman, COUNT(*) AS n "
        "FROM month_cost_item GROUP BY year_month"
    ).fetchall():
        costs[str(r["year_month"])] = {
            "amount_toman": int(r["amount_toman"] or 0),
            "n": int(r["n"] or 0),
            "note": f"{int(r['n'] or 0)} ردیف",
        }
    months_out = []
    for ym in sorted(by_month.keys(), reverse=True)[:months]:
        m = by_month[ym]
        cost = int((costs.get(ym) or {}).get("amount_toman") or 0)
        cost_note = str((costs.get(ym) or {}).get("note") or "")
        sales = int(m["sales_toman"])
        months_out.append(
            {
                **m,
                "cost_toman": cost,
                "cost_note": cost_note,
                "profit_toman": sales - cost,
                "admins": sorted(by_admin.get(ym, {}).values(), key=lambda x: -x["sales_toman"]),
            }
        )
    # Include cost-only months with no sales
    if admin_id is None:
        for ym, c in costs.items():
            if ym in by_month:
                continue
            try:
                ym.split("-")
            except ValueError:
                continue
            months_out.append(
                {
                    "year_month": ym,
                    "sales_toman": 0,
                    "sales_bytes": 0,
                    "charge_count": 0,
                    "waive_toman": 0,
                    "waive_bytes": 0,
                    "waive_count": 0,
                    "cost_toman": int(c["amount_toman"] or 0),
                    "cost_note": str(c.get("note") or ""),
                    "profit_toman": -int(c["amount_toman"] or 0),
                    "admins": [],
                }
            )
        months_out.sort(key=lambda x: x["year_month"], reverse=True)
        months_out = months_out[:months]
    return {"months": months_out, "admin_id": admin_id}


def _valid_ym(year_month: str) -> str:
    return normalize_ym_key(year_month, strict=True)


def add_month_cost(conn: sqlite3.Connection, year_month: str, amount: int, note: str = "") -> dict:
    """Append a cost line (does not replace other lines of the same month)."""
    ym = _valid_ym(year_month)
    amount = int(amount)
    if amount <= 0 or amount > 50_000_000_000:
        raise ValueError("مبلغ هزینه باید بزرگ‌تر از صفر باشد.")
    now = time.time()
    conn.execute(
        "INSERT INTO month_cost_item(year_month, amount_toman, note, created_ts) VALUES (?,?,?,?)",
        (ym, amount, (note or "")[:400], now),
    )
    rid = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
    row = conn.execute("SELECT * FROM month_cost_item WHERE id=?", (rid,)).fetchone()
    return dict(row)


def update_month_cost(
    conn: sqlite3.Connection,
    item_id: int,
    *,
    amount: int | None = None,
    note: str | None = None,
    year_month: str | None = None,
) -> dict:
    row = conn.execute("SELECT * FROM month_cost_item WHERE id=?", (item_id,)).fetchone()
    if not row:
        raise ValueError("ردیف هزینه پیدا نشد.")
    ym = _valid_ym(year_month) if year_month is not None else str(row["year_month"])
    amt = int(row["amount_toman"] if amount is None else amount)
    if amt <= 0 or amt > 50_000_000_000:
        raise ValueError("مبلغ هزینه باید بزرگ‌تر از صفر باشد.")
    ntxt = str(row["note"] or "") if note is None else (note or "")[:400]
    conn.execute(
        "UPDATE month_cost_item SET year_month=?, amount_toman=?, note=? WHERE id=?",
        (ym, amt, ntxt, item_id),
    )
    out = conn.execute("SELECT * FROM month_cost_item WHERE id=?", (item_id,)).fetchone()
    return dict(out)


def delete_month_cost(conn: sqlite3.Connection, item_id: int) -> None:
    cur = conn.execute("DELETE FROM month_cost_item WHERE id=?", (item_id,))
    if int(cur.rowcount or 0) < 1:
        raise ValueError("ردیف هزینه پیدا نشد.")


def list_month_costs(conn: sqlite3.Connection, limit: int = 200) -> list[dict]:
    rows = conn.execute(
        "SELECT id, year_month, amount_toman, note, created_ts FROM month_cost_item "
        "ORDER BY year_month DESC, id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]
