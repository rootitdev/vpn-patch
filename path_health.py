#!/usr/bin/env python3
"""Probe Iran inbounds + backhaul paths with TLS/HTTP (not ICMP).

Writes /var/lib/pg-node/sync/health.json. No secrets printed.
"""
from __future__ import annotations

import json
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

OUT = Path("/var/lib/pg-node/sync/health.json")


def tcp_tls(host: str, port: int, sni: str, timeout: float = 5.0) -> dict:
    t0 = time.time()
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(raw, server_hostname=sni) as sock:
            vers = sock.version()
        return {"ok": True, "ms": int((time.time() - t0) * 1000), "tls": vers, "err": ""}
    except Exception as e:
        return {"ok": False, "ms": int((time.time() - t0) * 1000), "tls": "", "err": str(e)[:120]}


def http_get(url: str, timeout: float = 8.0) -> dict:
    t0 = time.time()
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = resp.getcode()
            resp.read(256)
        return {"ok": True, "ms": int((time.time() - t0) * 1000), "http": code, "err": ""}
    except urllib.error.HTTPError as e:
        # 403/404 still means TLS+HTTP to the edge completed (XHTTP is not a public website).
        code = int(getattr(e, "code", 0) or 0)
        return {"ok": 200 <= code < 500, "ms": int((time.time() - t0) * 1000), "http": code, "err": f"HTTP {code}"}
    except Exception as e:
        return {"ok": False, "ms": int((time.time() - t0) * 1000), "http": 0, "err": str(e)[:120]}


def socks_http(proxy: str, url: str, timeout: float = 8.0) -> dict:
    """curl through socks5h; urllib has no socks."""
    t0 = time.time()
    try:
        p = subprocess.run(
            [
                "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                "--connect-timeout", "4", "--max-time", str(int(timeout)),
                "--socks5-hostname", proxy, url,
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 2,
        )
        code = int((p.stdout or "0").strip() or "0")
        ok = code in (200, 204)
        err = (p.stderr or "").strip()[:120]
        return {"ok": ok, "ms": int((time.time() - t0) * 1000), "http": code, "err": err}
    except Exception as e:
        return {"ok": False, "ms": int((time.time() - t0) * 1000), "http": 0, "err": str(e)[:120]}


def port_listen(port: int, proto: str = "tcp") -> bool:
    try:
        out = subprocess.check_output(["ss", "-lntu"], text=True)
    except Exception:
        return False
    needle = f":{port} "
    return needle in out


def main() -> None:
    inbound = {
        "tcp443": tcp_tls("127.0.0.1", 443, "dl.google.com"),
        "tcp2053": tcp_tls("127.0.0.1", 2053, "ir.jetengine.ir"),
        "listen443": port_listen(443),
        "listen2053": port_listen(2053),
    }
    inbound_ok = bool(inbound["listen443"] and inbound["listen2053"])
    # Reality dest fallback may not complete TLS like a normal site; listen+ClientHello path is enough with 2053 TLS.
    paths = {
        "TO-AMS-CF": http_get("https://cdn.jetengine.ir/cdn/v1/assets/"),
        "TO-AMS-XHTTP": http_get("https://xhttp.jahanynegar.ir/cdn/v1/assets/"),
        "TO-AMS-DIRECT": tcp_tls("202.61.249.173", 9443, "cdn.jetengine.ir"),
        "TO-AMS-TUIC": socks_http("127.0.0.1:11082", "https://www.gstatic.com/generate_204"),
    }
    doc = {
        "ts": int(time.time()),
        "inbound_ok": inbound_ok,
        "inbound": inbound,
        "paths": paths,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    tmp = OUT.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc))
    tmp.replace(OUT)
    print("inbound", inbound_ok, "paths", {k: bool(v.get("ok")) for k, v in paths.items()})


if __name__ == "__main__":
    main()
