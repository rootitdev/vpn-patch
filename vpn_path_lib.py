"""Shared panel-core helpers for vpn-path and failover. No secrets printed."""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from urllib.request import Request, urlopen

from vpn_paths import ALL_LIVE, FALLBACK, PANEL_DOMAINS, PANEL_RULE_MARK, PRIORITY, WATCH_ONLY

ENV = Path("/root/.vpn-secrets/.env")
EXPORT = Path("/root/vpn-infra/scripts/iran_sync_export.py")
MODE_FILE = Path("/var/lib/pasarguard/vpn-path-mode.json")
HISTORY_FILE = Path("/var/lib/pasarguard/path-health-history.jsonl")
HISTORY_KEEP = 2000


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for ln in ENV.read_text().splitlines():
        if not ln or ln.startswith("#") or "=" not in ln:
            continue
        k, v = ln.split("=", 1)
        env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def req(method: str, path: str, env: dict, body: dict | None = None):
    key = env.get("PANEL_API_KEY") or ""
    if not key:
        raise SystemExit("missing PANEL_API_KEY")
    data = None if body is None else json.dumps(body).encode()
    r = Request(
        f"http://127.0.0.1:8000{path}",
        data=data,
        method=method,
        headers={"X-Api-Key": key, "Content-Type": "application/json"},
    )
    with urlopen(r, timeout=30) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else {}


def get_core(env: dict) -> dict:
    core_id = env.get("PG_CORE_ID")
    if not core_id:
        raise SystemExit("missing PG_CORE_ID")
    return req("GET", f"/api/core/{core_id}", env)


def put_core(env: dict, core: dict) -> None:
    payload = {
        "name": core["name"],
        "config": core["config"],
        "type": core.get("type") or "xray",
        "exclude_inbound_tags": list(core.get("exclude_inbound_tags") or []),
        "fallbacks_inbound_tags": list(core.get("fallbacks_inbound_tags") or []),
    }
    core_id = env.get("PG_CORE_ID")
    req("PUT", f"/api/core/{core_id}?restart_nodes=false", env, payload)


def put_selector(env: dict, core: dict, selector: list[str]) -> None:
    cfg = core["config"]
    b = cfg["routing"]["balancers"][0]
    b["selector"] = selector
    b["strategy"] = {"type": "leastPing"}
    b["fallbackTag"] = FALLBACK
    obs = cfg.get("observatory") or cfg.get("burstObservatory") or {}
    if isinstance(obs, dict) and "subjectSelector" in obs:
        obs["subjectSelector"] = list(ALL_LIVE)
        obs.pop("probeUrl", None)
        obs["probeURL"] = "https://www.gstatic.com/generate_204"
        if "observatory" in cfg:
            cfg["observatory"] = obs
        else:
            cfg["burstObservatory"] = obs
    # Panel UI must not follow the VPN path pin — otherwise CF/XHTTP pins 502 /settle|/path|/dashboard.
    ensure_panel_via_backhaul(cfg)
    put_core(env, core)


def ensure_panel_via_backhaul(cfg: dict) -> bool:
    """Pin panel.* hostnames to TO-AMS-DIRECT (tunneled), independent of backhaul selector.

    Admin panels on Iran (nginx → subproxy → SOCKS) resolve panel.* and must keep working
    when the operator locks users onto CF/XHTTP/CDN. Cleartext Iran→Exit:2096 is still avoided.
    """
    rules = cfg.setdefault("routing", {}).setdefault("rules", [])
    desired = {
        "type": "field",
        "domain": list(PANEL_DOMAINS),
        "outboundTag": FALLBACK,  # TO-AMS-DIRECT
    }
    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            continue
        if PANEL_RULE_MARK not in (r.get("domain") or []):
            continue
        if (
            r.get("outboundTag") == FALLBACK
            and not r.get("balancerTag")
            and list(r.get("domain") or []) == list(PANEL_DOMAINS)
        ):
            return False
        rules[i] = desired
        return True
    insert_at = 0
    for i, r in enumerate(rules):
        dom = (r.get("domain") or []) if isinstance(r, dict) else []
        if any("category-ir" in str(d) or ".ir$" in str(d) for d in dom):
            insert_at = i
            break
    rules.insert(insert_at, desired)
    return True


def publish() -> None:
    """Push panel core to Iran. Export injects CAT-instagram clones of the live selector."""
    subprocess.run(["python3", str(EXPORT)], check=True)


def read_mode() -> dict:
    """auto: failover picks the path. manual: operator pinned `path`.

    `failover` (manual only): still leave a dead pinned path after FAIL_STREAK.
    """
    try:
        d = json.loads(MODE_FILE.read_text())
    except (OSError, ValueError):
        d = {}
    mode = d.get("mode") if d.get("mode") in ("auto", "manual") else "auto"
    allowed = set(PRIORITY) | set(WATCH_ONLY)
    path = d.get("path") if d.get("path") in allowed else ""
    if mode == "manual" and not path:
        mode = "auto"
    return {
        "mode": mode,
        "path": path,
        "failover": bool(d.get("failover", True)),
        "by": str(d.get("by") or ""),
        "ts": int(d.get("ts") or 0),
        "note": str(d.get("note") or ""),
    }


def write_mode(mode: str, path: str = "", failover: bool = True, by: str = "", note: str = "") -> dict:
    d = {
        "mode": mode,
        "path": path if mode == "manual" else "",
        "failover": bool(failover),
        "by": by,
        "ts": int(time.time()),
        "note": note,
    }
    MODE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = MODE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(d) + "\n")
    tmp.chmod(0o600)
    tmp.replace(MODE_FILE)
    return d


def append_history(health: dict) -> None:
    """One compact line per failover run; trimmed to HISTORY_KEEP lines."""
    paths = health.get("paths") or {}
    row = {
        "ts": int(health.get("ts") or time.time()),
        "in": bool(health.get("inbound_ok")),
        "p": {
            t: [1 if (paths.get(t) or {}).get("ok") else 0, int((paths.get(t) or {}).get("ms") or 0)]
            for t in list(PRIORITY) + list(WATCH_ONLY)
        },
    }
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with HISTORY_FILE.open("a") as f:
        f.write(json.dumps(row, separators=(",", ":")) + "\n")
    try:
        lines = HISTORY_FILE.read_text().splitlines()
    except OSError:
        return
    if len(lines) > HISTORY_KEEP + 200:
        tmp = HISTORY_FILE.with_suffix(".tmp")
        tmp.write_text("\n".join(lines[-HISTORY_KEEP:]) + "\n")
        tmp.replace(HISTORY_FILE)


def read_history(limit: int = 240) -> list[dict]:
    try:
        lines = HISTORY_FILE.read_text().splitlines()[-limit:]
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except ValueError:
            continue
    return out
