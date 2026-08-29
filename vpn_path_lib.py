"""Shared panel-core helpers for vpn-path and failover. No secrets printed."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from urllib.request import Request, urlopen

from vpn_paths import ALL_LIVE, FALLBACK, PANEL_DOMAINS, PANEL_RULE_MARK

ENV = Path("/root/.vpn-secrets/.env")
EXPORT = Path("/root/vpn-infra/scripts/iran_sync_export.py")


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
    put_core(env, core)


def ensure_panel_via_backhaul(cfg: dict) -> bool:
    """Insert panel-hostname → backhaul rule before the .ir DIRECT catch-all."""
    rules = cfg.setdefault("routing", {}).setdefault("rules", [])
    already = any(
        PANEL_RULE_MARK in (r.get("domain") or []) and r.get("balancerTag") == "backhaul"
        for r in rules
        if isinstance(r, dict)
    )
    if already:
        return False
    rule = {
        "type": "field",
        "domain": list(PANEL_DOMAINS),
        "balancerTag": "backhaul",
    }
    insert_at = 0
    for i, r in enumerate(rules):
        dom = r.get("domain") or []
        if any("category-ir" in str(d) or ".ir$" in str(d) for d in dom):
            insert_at = i
            break
    rules.insert(insert_at, rule)
    return True


def publish() -> None:
    """Push panel core to Iran. Export injects CAT-instagram clones of the live selector."""
    subprocess.run(["python3", str(EXPORT)], check=True)
