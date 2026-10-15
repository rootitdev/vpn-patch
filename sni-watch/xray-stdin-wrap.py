#!/usr/bin/python3
"""Inject Xray access log path so SNI (destOverride) is recorded.

PasarGuard node starts `xray -c stdin:` after stripping log.access.
This wrapper restores a dedicated SNI log without changing routing.

Must os.execv into xray.real so the node supervisor's kill hits the core.
Popen+wait leaked a new listener on every /start (SO_REUSEPORT).
"""
from __future__ import annotations

import fcntl
import json
import os
import sys

REAL = os.environ.get("XRAY_REAL", "/usr/local/bin/xray.real")
ACCESS = os.environ.get("XRAY_SNI_ACCESS", "/var/log/xray/sni-access.log")
ERROR = os.environ.get("XRAY_SNI_ERROR", "/var/log/xray/error.log")
F_SETPIPE_SZ = getattr(fcntl, "F_SETPIPE_SZ", 1031)


def inject(raw: bytes) -> bytes:
    try:
        cfg = json.loads(raw)
    except Exception:
        return raw
    if not isinstance(cfg, dict):
        return raw
    log = cfg.setdefault("log", {})
    if not isinstance(log, dict):
        return raw
    log["access"] = ACCESS
    log["error"] = log.get("error") or ERROR
    return json.dumps(cfg, ensure_ascii=False).encode()


def exec_real(args: list[str], data: bytes | None) -> None:
    argv = [REAL, *args]
    if data is None:
        os.execv(REAL, argv)
    r, w = os.pipe()
    try:
        fcntl.fcntl(w, F_SETPIPE_SZ, max(1 << 20, len(data) + 4096))
    except OSError:
        pass
    os.write(w, data)
    os.close(w)
    os.dup2(r, 0)
    os.close(r)
    os.execv(REAL, argv)


def main() -> int:
    args = sys.argv[1:]
    uses_stdin = any(a == "stdin:" or a.endswith("stdin:") for a in args) or not args
    if not uses_stdin:
        exec_real(args, None)
    data = inject(sys.stdin.buffer.read())
    exec_real(args, data)
    return 1


if __name__ == "__main__":
    sys.exit(main())
