"""Backhaul path names shared by vpn-path, health, and failover.

HY2/TUIC removed: UDP from Iranian DCs is reliably filtered.
CDN standbys (Gcore/Bunny) carry the same XHTTP origin as grey hosts.
CF orange is watched via TO-AMS-CFORANGE (not in auto failover until proven).
"""
from __future__ import annotations

# Live failover order. CFORANGE is intentionally excluded from auto switching.
PRIORITY = [
    "TO-AMS-DIRECT",
    "TO-AMS-XHTTP",
    "TO-AMS-BUNNY",
    "TO-AMS-GCORE",
    "TO-AMS-CF",
]
# Probe + UI only: Cloudflare orange canary. Manual lock allowed; auto never picks it.
WATCH_ONLY = ["TO-AMS-CFORANGE"]
REMOVED = ["TO-AMS-HY2", "TO-AMS-TUIC"]
ALL_LIVE = list(PRIORITY) + list(WATCH_ONLY)
MAP = {
    "auto": list(PRIORITY),
    "direct": ["TO-AMS-DIRECT"],
    "xhttp": ["TO-AMS-XHTTP"],
    "gcore": ["TO-AMS-GCORE"],
    "bunny": ["TO-AMS-BUNNY"],
    "cf": ["TO-AMS-CF"],
    "cforange": ["TO-AMS-CFORANGE"],
}
FALLBACK = "TO-AMS-DIRECT"
FAIL_STREAK = 3
FAILBACK_STREAK = 5
HEALTH_INTERVAL_SEC = 12
SYNC_INTERVAL_SEC = 10

# Admin panel hostnames. From Iran must use tunneled TO-AMS-DIRECT (not the VPN
# path selector): cleartext :2096 is DPI-dropped, but pinning panel.* to CF/XHTTP
# with the user path causes nginx 502 on /dashboard|/settle|/path when that path dies.
PANEL_DOMAINS = [
    "full:panel.jetengine.ir",
    "full:panel.jahanynegar.ir",
    "full:panel.rootit.online",
]
PANEL_RULE_MARK = "full:panel.jetengine.ir"

# Public hostnames for XHTTP CDN / grey probes (Iran → edge → Exit :443).
PATH_HOSTS = {
    "TO-AMS-CF": "cdn.jetengine.ir",
    "TO-AMS-XHTTP": "xhttp.jahanynegar.ir",
    "TO-AMS-GCORE": "standby.pantherpart.com",
    "TO-AMS-BUNNY": "bunny.classword.ir",
    "TO-AMS-CFORANGE": "cf-test.jetengine.ir",
}
