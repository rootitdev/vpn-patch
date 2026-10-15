#!/usr/bin/env python3
"""Probe Iran inbounds + backhaul paths with TLS/HTTP (not ICMP).

Writes /var/lib/pg-node/sync/health.json. No secrets printed.

XHTTP inbounds answer bare GET with HTTP 400 + x-padding when the edge/origin
is up; that is healthy for our tunnel, not a client failure. Cloudflare
Browser Integrity Check (403 / error 1010) on bot UAs is not a tunnel signal.
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
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


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


def _xhttp_edge_ok(code: int, headers) -> bool:
    """True when the XHTTP inbound (or CF in front of it) is answering."""
    if 200 <= code < 300:
        return True
    # Working Xray XHTTP without a session returns 400 and pads the response.
    if code == 400:
        pad = ""
        try:
            pad = headers.get("X-Padding") or headers.get("x-padding") or ""
        except Exception:
            pad = ""
        return bool(pad)
    return False


def http_xhttp_probe(url: str, timeout: float = 8.0) -> dict:
    """Probe an XHTTP path URL (CF or grey). Not a full tunnel test."""
    t0 = time.time()
    try:
        req = urllib.request.Request(
            url,
            method="GET",
            headers={"User-Agent": BROWSER_UA, "Accept": "*/*"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = int(resp.getcode() or 0)
            hdrs = resp.headers
            resp.read(256)
        ok = _xhttp_edge_ok(code, hdrs)
        return {
            "ok": ok,
            "ms": int((time.time() - t0) * 1000),
            "http": code,
            "err": "" if ok else f"HTTP {code}",
        }
    except urllib.error.HTTPError as e:
        code = int(getattr(e, "code", 0) or 0)
        ok = _xhttp_edge_ok(code, e.headers)
        err = f"HTTP {code}"
        if code == 403:
            body = b""
            try:
                body = e.read(64)
            except Exception:
                body = b""
            if b"1010" in body:
                err = "HTTP 403 (CF browser check)"
        return {
            "ok": ok,
            "ms": int((time.time() - t0) * 1000),
            "http": code,
            "err": "" if ok else err,
        }
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


STATE_BIN = Path("/var/lib/pg-node/sync/state.bin")
TUNNEL_CACHE = Path("/var/lib/pg-node/sync/cforange-tunnel.json")
TUNNEL_CACHE_SEC = 300
TUNNEL_SOCKS_PORT = 18091
XRAY_BIN = Path("/usr/local/bin/xray")


def _outbound_from_state(tag: str) -> dict | None:
    """Pull one outbound object from Iran sync state (protobuf-ish + JSON)."""
    try:
        raw = STATE_BIN.read_bytes()
    except OSError:
        return None
    text = raw.decode("latin1", errors="ignore")
    needle = f'"tag":"{tag}"'
    i = text.find(needle)
    if i < 0:
        needle = f'"tag": "{tag}"'
        i = text.find(needle)
    if i < 0:
        return None
    # Walk back to object start.
    start = text.rfind("{", 0, i)
    if start < 0:
        return None
    depth = 0
    for j in range(start, len(text)):
        ch = text[j]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start : j + 1])
                except ValueError:
                    return None
    return None


def cforange_tunnel_probe(edge: dict) -> dict:
    """Full VLESS+XHTTP via CF orange. Cached — edge HTTP alone is not enough."""
    now = int(time.time())
    cached: dict = {}
    try:
        cached = json.loads(TUNNEL_CACHE.read_text())
    except (OSError, ValueError):
        cached = {}
    age = now - int(cached.get("ts") or 0)
    if cached and age < TUNNEL_CACHE_SEC and "ok" in cached:
        out = {
            "ok": bool(cached.get("ok")),
            "ms": int(cached.get("ms") or 0),
            "http": int(cached.get("http") or 0),
            "err": str(cached.get("err") or ""),
            "edge": bool(edge.get("ok")),
            "tunnel": bool(cached.get("ok")),
            "cached": True,
        }
        return out

    if not edge.get("ok"):
        row = {
            "ok": False,
            "ms": int(edge.get("ms") or 0),
            "http": int(edge.get("http") or 0),
            "err": f"edge:{edge.get('err') or 'down'}",
            "edge": False,
            "tunnel": False,
            "cached": False,
        }
        return row

    ob = _outbound_from_state("TO-AMS-CFORANGE")
    if not ob or not XRAY_BIN.is_file():
        return {
            "ok": False,
            "ms": 0,
            "http": 0,
            "err": "no outbound/xray for tunnel probe",
            "edge": True,
            "tunnel": False,
            "cached": False,
        }

    cfg = {
        "log": {"loglevel": "error"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": TUNNEL_SOCKS_PORT,
                "protocol": "socks",
                "settings": {"udp": False},
            }
        ],
        "outbounds": [
            {
                "protocol": ob.get("protocol") or "vless",
                "settings": ob.get("settings") or {},
                "streamSettings": ob.get("streamSettings") or {},
            }
        ],
    }
    cfg_path = Path("/tmp/probe-cforange-health.json")
    log_path = Path("/tmp/probe-cforange-health.log")
    cfg_path.write_text(json.dumps(cfg))
    proc = None
    t0 = time.time()
    try:
        proc = subprocess.Popen(
            [str(XRAY_BIN), "run", "-c", str(cfg_path)],
            stdout=log_path.open("w"),
            stderr=subprocess.STDOUT,
        )
        time.sleep(1.2)
        sock = socks_http(
            f"127.0.0.1:{TUNNEL_SOCKS_PORT}",
            "https://www.gstatic.com/generate_204",
            timeout=12.0,
        )
        ok = bool(sock.get("ok"))
        row = {
            "ok": ok,
            "ms": int(sock.get("ms") or (time.time() - t0) * 1000),
            "http": int(sock.get("http") or 0),
            "err": "" if ok else (sock.get("err") or "tunnel fail")[:120],
            "edge": True,
            "tunnel": ok,
            "cached": False,
        }
    except Exception as e:
        row = {
            "ok": False,
            "ms": int((time.time() - t0) * 1000),
            "http": 0,
            "err": str(e)[:120],
            "edge": True,
            "tunnel": False,
            "cached": False,
        }
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    try:
        TUNNEL_CACHE.parent.mkdir(parents=True, exist_ok=True)
        TUNNEL_CACHE.write_text(
            json.dumps(
                {
                    "ts": now,
                    "ok": row["ok"],
                    "ms": row["ms"],
                    "http": row["http"],
                    "err": row["err"],
                }
            )
        )
    except OSError:
        pass
    return row


def main() -> None:
    # Import path hosts lazily so this file stays runnable if vpn_paths is older.
    try:
        from vpn_paths import PATH_HOSTS  # type: ignore
    except Exception:
        PATH_HOSTS = {
            "TO-AMS-CF": "cdn.jetengine.ir",
            "TO-AMS-XHTTP": "xhttp.jahanynegar.ir",
            "TO-AMS-GCORE": "standby.pantherpart.com",
            "TO-AMS-BUNNY": "bunny.classword.ir",
            "TO-AMS-CFORANGE": "cf-test.jetengine.ir",
        }
    inbound = {
        "tcp443": tcp_tls("127.0.0.1", 443, "dl.google.com"),
        "tcp2053": tcp_tls("127.0.0.1", 2053, "ir.jetengine.ir"),
        "listen443": port_listen(443),
        "listen2053": port_listen(2053),
    }
    inbound_ok = bool(inbound["listen443"] and inbound["listen2053"])
    # Reality dest fallback may not complete TLS like a normal site; listen+ClientHello path is enough with 2053 TLS.
    edge_orange = http_xhttp_probe(
        f"https://{PATH_HOSTS['TO-AMS-CFORANGE']}/cdn/v1/assets/"
    )
    paths = {
        "TO-AMS-CF": http_xhttp_probe(f"https://{PATH_HOSTS['TO-AMS-CF']}/cdn/v1/assets/"),
        "TO-AMS-XHTTP": http_xhttp_probe(f"https://{PATH_HOSTS['TO-AMS-XHTTP']}/cdn/v1/assets/"),
        "TO-AMS-GCORE": http_xhttp_probe(f"https://{PATH_HOSTS['TO-AMS-GCORE']}/cdn/v1/assets/"),
        "TO-AMS-BUNNY": http_xhttp_probe(f"https://{PATH_HOSTS['TO-AMS-BUNNY']}/cdn/v1/assets/"),
        "TO-AMS-CFORANGE": cforange_tunnel_probe(edge_orange),
        "TO-AMS-DIRECT": tcp_tls("202.61.249.173", 9443, "cdn.jetengine.ir"),
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
