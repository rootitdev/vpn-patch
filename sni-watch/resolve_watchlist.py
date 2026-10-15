#!/usr/bin/env python3
"""Resolve Iran watchlist names to PasarGuard id + VLESS UUID. Watched names only.

Also pushes panel user status (active/limited/…) to Iran so sni-watch UI can flag
limited or deleted clients.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

IRAN = "root@193.228.90.107"
REMOTE_MAP = "/etc/sni-watch/usermap.json"
REMOTE_STATUS = "/etc/sni-watch/panel-status.json"
REMOTE_DB = "/var/lib/sni-watch/watch.db"


def ssh_py(code: str) -> str:
    r = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", IRAN, "python3", "-"],
        input=code,
        text=True,
        check=True,
        capture_output=True,
    )
    return r.stdout or ""


def watch_queries() -> list[str]:
    raw = ssh_py(
        "import sqlite3\n"
        f"c=sqlite3.connect('{REMOTE_DB}')\n"
        "for e,l,a in c.execute('select email,label,aliases from watchlist'):\n"
        "    print(e or '')\n"
        "    print(l or '')\n"
        "    for p in (a or '').split(','):\n"
        "        print(p.strip())\n"
    )
    seen: set[str] = set()
    out: list[str] = []
    for ln in raw.splitlines():
        s = ln.strip()
        if not s or s.lower() in seen:
            continue
        seen.add(s.lower())
        out.append(s)
    return out


def resolve(names: list[str]) -> tuple[dict[str, str], dict[str, dict]]:
    """Return (name→id map, id→{username,status})."""
    if not names:
        return {}, {}
    script = Path("/tmp/sni-watch-resolve-inner.py")
    script.write_text(
        """
import json, os, sqlite3
c = sqlite3.connect('/var/lib/pasarguard/db.sqlite3')
want = {x.strip().lower() for x in os.environ.get('SNI_WATCH_WANT','').split('\\n') if x.strip()}
out = {}
status = {}
for uid, username, st, settings in c.execute(
    'select id, username, status, proxy_settings from users'
):
    sid = str(uid)
    uname = (username or '').strip()
    uuid = ''
    try:
        obj = json.loads(settings) if settings else {}
        if isinstance(obj, dict):
            uuid = str((obj.get('vless') or {}).get('id') or '').strip()
    except (json.JSONDecodeError, TypeError, AttributeError):
        uuid = ''
    keys = {sid.lower(), uname.lower(), uuid.lower()}
    keys.discard('')
    if not (keys & want) and want:
        continue
    # Xray access.log email is the panel user id, not the UUID.
    for k in keys:
        out[k] = sid
    status[sid] = {
        "username": uname,
        "status": (st or "?").strip().lower() or "?",
    }
print(json.dumps({"map": out, "status": status}, ensure_ascii=False))
"""
    )
    subprocess.run(
        ["docker", "cp", str(script), "pasarguard:/tmp/sni-watch-resolve-inner.py"],
        check=True,
    )
    env = subprocess.run(
        [
            "docker",
            "exec",
            "-e",
            "SNI_WATCH_WANT=" + "\n".join(names),
            "-w",
            "/code",
            "pasarguard",
            "/code/.venv/bin/python",
            "/tmp/sni-watch-resolve-inner.py",
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    line = (env.stdout or "").strip().splitlines()[-1]
    data = json.loads(line)
    if not isinstance(data, dict):
        return {}, {}
    mapping = data.get("map") if isinstance(data.get("map"), dict) else {}
    status = data.get("status") if isinstance(data.get("status"), dict) else {}
    return mapping, status


def _scp_json(obj: object, remote: str) -> None:
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False)
        fh.write("\n")
        tmp = fh.name
    try:
        subprocess.run(
            ["scp", "-o", "BatchMode=yes", tmp, f"{IRAN}:{remote}.tmp"],
            check=True,
        )
        ssh_py(
            "import os\n"
            f"os.replace('{remote}.tmp', '{remote}')\n"
            f"os.chmod('{remote}', 0o600)\n"
        )
    finally:
        Path(tmp).unlink(missing_ok=True)


def apply_map(mapping: dict[str, str]) -> None:
    if not mapping:
        return
    _scp_json(mapping, REMOTE_MAP)
    ssh_py(
        "import json, sqlite3, os\n"
        f"m=json.load(open('{REMOTE_MAP}'))\n"
        f"c=sqlite3.connect('{REMOTE_DB}')\n"
        "c.execute('pragma busy_timeout=8000')\n"
        "inv={}\n"
        "for k,v in m.items():\n"
        "    inv.setdefault(str(v).lower(), set()).add(str(k).lower())\n"
        "    inv.setdefault(str(v).lower(), set()).add(str(v).lower())\n"
        "rows=list(c.execute('select email,label,aliases from watchlist'))\n"
        "for email,label,aliases in rows:\n"
        "    keys=set(a.strip().lower() for a in (aliases or '').split(',') if a.strip())\n"
        "    uid=(m.get((email or '').lower()) or m.get((label or '').lower()) or '').lower()\n"
        "    for q in (email, label or '', uid):\n"
        "        q=(q or '').lower()\n"
        "        if q in m: keys.add(str(m[q]).lower()); keys.update(inv.get(str(m[q]).lower(), set()))\n"
        "        if q in inv: keys.update(inv[q])\n"
        "    keys.discard((email or '').lower())\n"
        "    c.execute('update watchlist set aliases=? where email=?', (','.join(sorted(keys)), email))\n"
        "c.commit()\n"
        "print('applied', len(rows))\n"
    )


def apply_status(status: dict[str, dict]) -> None:
    """Write panel status for watched users; mark unresolved watch rows as missing."""
    # Enrich with missing markers for watchlist keys that no longer resolve.
    payload = {str(k): v for k, v in status.items() if isinstance(v, dict)}
    raw = ssh_py(
        "import sqlite3, json\n"
        f"c=sqlite3.connect('{REMOTE_DB}')\n"
        "rows=list(c.execute('select email,label,aliases from watchlist'))\n"
        "print(json.dumps(rows, ensure_ascii=False))\n"
    )
    try:
        rows = json.loads(raw.strip() or "[]")
    except json.JSONDecodeError:
        rows = []
    # Load current usermap if present for id lookup of missing detection
    umap_raw = ssh_py(
        f"import pathlib\n"
        f"p=pathlib.Path('{REMOTE_MAP}')\n"
        "print(p.read_text() if p.exists() else '{}')\n"
    )
    try:
        umap = json.loads(umap_raw or "{}")
    except json.JSONDecodeError:
        umap = {}
    if not isinstance(umap, dict):
        umap = {}

    for email, label, aliases in rows:
        keys = [str(email or "").lower(), str(label or "").lower()]
        for part in str(aliases or "").split(","):
            if part.strip():
                keys.append(part.strip().lower())
        uid = ""
        for k in keys:
            if k in umap:
                uid = str(umap[k])
                break
            if k.isdigit():
                uid = k
                break
        if uid and uid in payload:
            continue
        # No live panel row for this watch entry
        miss_key = uid or str(email or label or "unknown").lower()
        payload[miss_key] = {
            "username": str(label or email or miss_key),
            "status": "missing",
            "watch_email": str(email or "").lower(),
        }

    _scp_json(payload, REMOTE_STATUS)
    print("status", len(payload))


def main() -> None:
    names = watch_queries()
    mapping, status = resolve(names)
    apply_map(mapping)
    apply_status(status)
    print("resolved", len(mapping), "queries", len(names), "status", len(status))


if __name__ == "__main__":
    main()
