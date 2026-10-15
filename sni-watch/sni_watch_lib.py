#!/usr/bin/env python3
"""Shared helpers for sni-watch CLI (stdlib only)."""
from __future__ import annotations

import re
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

CFG_PATH = Path("/etc/sni-watch/config.env")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
ACCESS_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)?"
    r".*?accepted (?P<net>tcp|udp):(?P<dest>\[[^\]]+\]|[^:\s]+):(?P<port>\d+)"
    r".*?(?:email: (?P<email>\S+))?\s*$"
)


def parse_env(path: Path) -> dict[str, str]:
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


def load_cfg(path: Path = CFG_PATH) -> dict[str, str]:
    defaults = {
        "DB_PATH": "/var/lib/sni-watch/watch.db",
        "DOMAINS_FILE": "/usr/local/lib/sni-watch/adult-domains.txt",
        "EXTRA_DOMAINS": "/etc/sni-watch/extra-domains.txt",
        "ACCESS_LOG": "/var/log/xray/sni-access.log",
        "ACCESS_LOGS": "/var/log/xray/sni-access.log,/var/log/xray/access.log",
        "USERMAP": "/etc/sni-watch/usermap.json",
        "RETENTION_DAYS": "2",
        "COALESCE_SEC": "120",
    }
    defaults.update(parse_env(path))
    return defaults


def log_paths(cfg: dict[str, str]) -> list[Path]:
    raw = cfg.get("ACCESS_LOGS") or cfg.get("ACCESS_LOG") or ""
    out: list[Path] = []
    seen: set[str] = set()
    for part in raw.split(","):
        p = part.strip()
        if p and p not in seen:
            seen.add(p)
            out.append(Path(p))
    return out or [Path("/var/log/xray/sni-access.log")]


def load_domains(cfg: dict[str, str]) -> set[str]:
    names: set[str] = set()
    for key in ("DOMAINS_FILE", "EXTRA_DOMAINS"):
        path = Path(cfg.get(key) or "")
        if not path.exists():
            continue
        for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
            s = ln.strip().lower().rstrip(".")
            if s and not s.startswith("#"):
                names.add(s)
    return names


def is_adult(host: str, domains: set[str]) -> bool:
    host = host.lower().rstrip(".")
    if not host or IPV4_RE.match(host) or ":" in host:
        return False
    parts = host.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in domains:
            return True
    return False


def parse_access_line(line: str) -> dict | None:
    m = ACCESS_RE.search(line.strip())
    if not m:
        return None
    email = (m.group("email") or "").strip().rstrip(",")
    dest = (m.group("dest") or "").strip().strip("[]").lower().rstrip(".")
    if not email or not dest:
        return None
    if IPV4_RE.match(dest) or dest.startswith("::") or dest.count(":") >= 2:
        return None
    return {
        "log_ts": m.group("ts"),
        "email": email.lower(),
        "domain": dest,
    }


def load_usermap(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    import json

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return {str(k).strip().lower(): str(v).strip().lower() for k, v in raw.items()}


@dataclass
class WatchClient:
    email: str
    label: str
    enabled: bool
    ids: set[str] = field(default_factory=set)

    @property
    def primary_id(self) -> str:
        for x in sorted(self.ids, key=lambda s: (not s.isdigit(), s)):
            if x.isdigit():
                return x
        return self.email


def load_watch_clients(cfg: dict[str, str]) -> list[WatchClient]:
    db_path = Path(cfg["DB_PATH"])
    umap = load_usermap(Path(cfg.get("USERMAP") or "/etc/sni-watch/usermap.json"))
    conn = sqlite3.connect(str(db_path), timeout=10)
    try:
        rows = conn.execute(
            "SELECT email, label, enabled, aliases FROM watchlist ORDER BY email"
        ).fetchall()
    finally:
        conn.close()

    clients: list[WatchClient] = []
    for email, label, enabled, aliases in rows:
        keys: set[str] = set()
        seeds = [email or "", label or ""]
        for part in (aliases or "").split(","):
            if part.strip():
                seeds.append(part.strip())
        for s in seeds:
            sl = str(s).strip().lower()
            if not sl:
                continue
            keys.add(sl)
            mapped = umap.get(sl, "")
            if mapped:
                keys.add(mapped)
        inv: dict[str, set[str]] = {}
        for k, v in umap.items():
            inv.setdefault(v, set()).add(k)
        for sl in list(keys):
            if sl in umap:
                vid = umap[sl]
                keys.add(vid)
                keys.update(inv.get(vid, set()))
        wc = WatchClient(
            email=str(email).lower(),
            label=str(label or email),
            enabled=bool(enabled),
            ids={k for k in keys if k},
        )
        clients.append(wc)
    return clients


def watched_id_map(clients: list[WatchClient]) -> dict[str, WatchClient]:
    out: dict[str, WatchClient] = {}
    for c in clients:
        if not c.enabled:
            continue
        for kid in c.ids:
            out[kid] = c
    return out


@dataclass
class DomainCount:
    domain: str
    hits: int = 0


@dataclass
class ClientStats:
    client: WatchClient
    hits: int = 0
    domains: dict[str, int] = field(default_factory=dict)


def aggregate_db_hits(cfg: dict[str, str], since_ts: float) -> tuple[list[ClientStats], list[tuple[str, int]]]:
    db_path = Path(cfg["DB_PATH"])
    clients = load_watch_clients(cfg)
    by_email = {c.email: ClientStats(client=c) for c in clients if c.enabled}
    domain_totals: dict[str, int] = {}

    conn = sqlite3.connect(str(db_path), timeout=10)
    try:
        rows = conn.execute(
            "SELECT email, domain, SUM(count) FROM hits WHERE ts >= ? "
            "GROUP BY email, domain ORDER BY SUM(count) DESC",
            (since_ts,),
        ).fetchall()
    finally:
        conn.close()

    for email, domain, count in rows:
        st = by_email.get(str(email).lower())
        if not st:
            continue
        n = int(count)
        st.hits += n
        st.domains[str(domain)] = st.domains.get(str(domain), 0) + n
        domain_totals[str(domain)] = domain_totals.get(str(domain), 0) + n

    top_domains = sorted(domain_totals.items(), key=lambda x: (-x[1], x[0]))
    return sorted(by_email.values(), key=lambda s: (-s.hits, s.client.label)), top_domains


def scan_log_hits(
    cfg: dict[str, str],
    since_ts: float,
    *,
    max_lines: int = 0,
) -> tuple[list[ClientStats], list[tuple[str, int]], int]:
    domains = load_domains(cfg)
    clients = load_watch_clients(cfg)
    id_map = watched_id_map(clients)
    by_client: dict[str, ClientStats] = {c.email: ClientStats(client=c) for c in clients if c.enabled}
    domain_totals: dict[str, int] = {}
    lines_read = 0
    cutoff = time.strftime("%Y/%m/%d %H:%M:%S", time.localtime(since_ts))

    for path in log_paths(cfg):
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                lines_read += 1
                if max_lines and lines_read > max_lines:
                    break
                ev = parse_access_line(line)
                if not ev:
                    continue
                if ev["log_ts"] < cutoff:
                    continue
                wc = id_map.get(ev["email"])
                if not wc or not is_adult(ev["domain"], domains):
                    continue
                st = by_client[wc.email]
                st.hits += 1
                st.domains[ev["domain"]] = st.domains.get(ev["domain"], 0) + 1
                domain_totals[ev["domain"]] = domain_totals.get(ev["domain"], 0) + 1
        if max_lines and lines_read > max_lines:
            break

    top_domains = sorted(domain_totals.items(), key=lambda x: (-x[1], x[0]))
    stats = sorted(by_client.values(), key=lambda s: (-s.hits, s.client.label))
    return stats, top_domains, lines_read


def domain_check(hosts: list[str], cfg: dict[str, str]) -> list[tuple[str, bool, str]]:
    domains = load_domains(cfg)
    out: list[tuple[str, bool, str]] = []
    for raw in hosts:
        host = raw.strip().lower().rstrip(".")
        if not host:
            continue
        matched = is_adult(host, domains)
        suffix = ""
        if matched:
            parts = host.split(".")
            for i in range(len(parts) - 1):
                cand = ".".join(parts[i:])
                if cand in domains:
                    suffix = cand
                    break
        out.append((host, matched, suffix))
    return out


def retention_sec(cfg: dict[str, str]) -> int:
    try:
        days = float(cfg.get("RETENTION_DAYS") or 2)
    except ValueError:
        days = 2.0
    return max(1, int(days * 86400))
