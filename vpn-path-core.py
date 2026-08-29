#!/usr/bin/env python3
"""Set Iran backhaul selector in the panel core (live source of truth).

Live Xray is docker node `xray -c stdin:` after localhost /start.
Never edits /root/.pg_nodes/iran/xray.json. Never Germany→Iran /start.
No secrets printed.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from time import gmtime, strftime

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vpn_path_lib import get_core, load_env, publish, put_selector  # noqa: E402
from vpn_paths import MAP, PRIORITY  # noqa: E402

LOG = Path("/var/log/vpn-path/manual.log")
IRAN = "root@193.228.90.107"


def log(msg: str) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a") as f:
        f.write(strftime("%Y-%m-%dT%H:%M:%SZ", gmtime()) + " " + msg + "\n")


def status(env: dict) -> None:
    core = get_core(env)
    b = core["config"]["routing"]["balancers"][0]
    print("source panel-core id", env.get("PG_CORE_ID"))
    print("selector", ",".join(b.get("selector") or []))
    print("fallback", b.get("fallbackTag"))
    print("strategy", (b.get("strategy") or {}).get("type"))
    print("priority", ",".join(PRIORITY))
    print("live-xray docker-node stdin after /start")
    print("unused-systemd /root/.pg_nodes/iran/xray.json")


def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else "status"
    env = load_env()
    if mode == "status":
        status(env)
        return
    if mode == "publish":
        publish()
        return
    if mode == "test":
        subprocess.run(
            ["ssh", "-o", "BatchMode=yes", IRAN, "python3 /usr/local/sbin/path_health.py"],
            check=False,
        )
        return
    if mode not in MAP:
        raise SystemExit("usage: vpn-path auto|cf|xhttp|direct|tuic|status|publish|test")
    selector = MAP[mode]
    put_selector(env, get_core(env), selector)
    log(f"manual {mode} selector={','.join(selector)}")
    print("SET", mode, selector)
    publish()


if __name__ == "__main__":
    main()
