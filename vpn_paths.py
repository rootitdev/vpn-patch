"""Backhaul path names shared by vpn-path, health, and failover.

HY2 is excluded: Shetaban UDP to Exit:4443 times out (http3), not a trivial fix.
"""
from __future__ import annotations

PRIORITY = [
    "TO-AMS-CF",
    "TO-AMS-XHTTP",
    "TO-AMS-DIRECT",
    "TO-AMS-TUIC",
]
REMOVED = ["TO-AMS-HY2"]
ALL_LIVE = list(PRIORITY)
MAP = {
    "auto": list(PRIORITY),
    "cf": ["TO-AMS-CF"],
    "xhttp": ["TO-AMS-XHTTP"],
    "direct": ["TO-AMS-DIRECT"],
    "tuic": ["TO-AMS-TUIC"],
}
FALLBACK = "TO-AMS-XHTTP"
FAIL_STREAK = 3
FAILBACK_STREAK = 5
HEALTH_INTERVAL_SEC = 12
SYNC_INTERVAL_SEC = 10

# Admin panel hostnames. Must go via backhaul from Iran (direct :2096 HTTP is DPI-dropped).
PANEL_DOMAINS = [
    "full:panel.jetengine.ir",
    "full:panel.jahanynegar.ir",
    "full:panel.rootit.online",
]
PANEL_RULE_MARK = "full:panel.jetengine.ir"
