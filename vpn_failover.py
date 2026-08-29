#!/usr/bin/env python3
"""Pin Iran backhaul to one healthy path from path_health.json.

Policy: fail-forward after 3 consecutive failures. Fail back to a higher-priority
path after 5 consecutive successes (hysteresis, avoid CF flap).
No Telegram exists in this setup. No Germany→Iran /start. No secrets printed.
"""
from __future__ import annotations

import fcntl
import json
import subprocess
import sys
from pathlib import Path
from time import gmtime, strftime

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vpn_path_lib import get_core, load_env, publish, put_selector  # noqa: E402
from vpn_paths import FAIL_STREAK, FAILBACK_STREAK, PRIORITY  # noqa: E402

IRAN = "root@193.228.90.107"
STATE = Path("/var/lib/pasarguard/failover-state.json")
LOG = Path("/var/log/vpn-path/failover.log")
LOCK = Path("/var/lock/vpn-failover.lock")
HEALTH_CACHE = Path("/var/lib/pasarguard/iran-health.json")


def log(msg: str) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    line = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime()) + " " + msg + "\n"
    with LOG.open("a") as f:
        f.write(line)
    print(msg)


def load_state() -> dict:
    if STATE.exists():
        return json.loads(STATE.read_text())
    return {"current": "", "fail": {}, "ok": {}, "last_reason": ""}


def save_state(st: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(st) + "\n")
    STATE.chmod(0o600)


def fetch_health() -> dict:
    subprocess.run(
        ["ssh", "-o", "BatchMode=yes", IRAN, "python3 /usr/local/sbin/path_health.py"],
        check=True,
        capture_output=True,
        text=True,
    )
    r = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", IRAN, "cat /var/lib/pg-node/sync/health.json"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(r.stdout)


def selector_now(env: dict) -> str:
    sel = get_core(env)["config"]["routing"]["balancers"][0].get("selector") or []
    return sel[0] if sel else PRIORITY[0]


def do_switch(env: dict, st: dict, frm: str, to: str, reason: str) -> None:
    put_selector(env, get_core(env), [to])
    st["current"] = to
    st["last_reason"] = reason
    st.setdefault("fail", {})[to] = 0
    save_state(st)
    log(f"SWITCH from={frm} to={to} reason={reason}")
    # publish() rebuilds proto; Instagram CAT-* outbounds are cloned from `to`.
    try:
        publish()
    except Exception as e:
        log(f"PUBLISH_FAIL after switch to={to} err={type(e).__name__}")


def main() -> None:
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with LOCK.open("w") as lf:
        try:
            fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("SKIP locked", flush=True)
            return
        _run()


def _run() -> None:
    env = load_env()
    st = load_state()
    h = fetch_health()
    HEALTH_CACHE.parent.mkdir(parents=True, exist_ok=True)
    HEALTH_CACHE.write_text(json.dumps(h) + "\n")
    if not h.get("inbound_ok"):
        log("SKIP inbound_down")
        return
    paths = h.get("paths") or {}
    sel = get_core(env)["config"]["routing"]["balancers"][0].get("selector") or []
    if len(sel) != 1:
        pick = next((t for t in PRIORITY if bool((paths.get(t) or {}).get("ok"))), PRIORITY[0])
        do_switch(env, st, ",".join(sel), pick, "pin single healthy path (was multi-selector)")
        return
    cur = selector_now(env)
    st["current"] = cur
    fail = st.setdefault("fail", {})
    ok = st.setdefault("ok", {})

    def healthy(tag: str) -> bool:
        return bool((paths.get(tag) or {}).get("ok"))

    if healthy(cur):
        fail[cur] = 0
        ok[cur] = int(ok.get(cur) or 0) + 1
        for tag in PRIORITY:
            if tag == cur:
                break
            if healthy(tag):
                ok[tag] = int(ok.get(tag) or 0) + 1
                if ok[tag] >= FAILBACK_STREAK:
                    do_switch(env, st, cur, tag, f"failback ok_streak={ok[tag]}")
                    return
            else:
                ok[tag] = 0
        save_state(st)
        return

    fail[cur] = int(fail.get(cur) or 0) + 1
    ok[cur] = 0
    log(f"FAIL {cur} streak={fail[cur]} err={(paths.get(cur) or {}).get('err', '')[:80]}")
    if fail[cur] < FAIL_STREAK:
        save_state(st)
        return

    for tag in PRIORITY:
        if tag == cur or not healthy(tag):
            continue
        do_switch(
            env,
            st,
            cur,
            tag,
            f"{cur} failed {fail[cur]}x; {tag} probe ok",
        )
        return

    bits = " ".join(
        f"{t}={'ok' if healthy(t) else 'FAIL'}" for t in PRIORITY
    )
    if fail[cur] == FAIL_STREAK or fail[cur] % 10 == 0:
        log(f"ALERT NO_FALLBACK current={cur} staying_on={cur} {bits}")
    save_state(st)


if __name__ == "__main__":
    main()
