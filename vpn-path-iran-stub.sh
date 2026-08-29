#!/bin/bash
# DEPRECATED. Live Xray is docker `xray -c stdin:` from /var/lib/pg-node/generated
# after localhost /start. This host's systemd json is unused.
# Path changes: run `vpn-path` on the Exit (Germany) server.
echo "DEPRECATED: vpn-path on Iran does not control live Docker Xray." >&2
echo "Source of truth: panel core iran-xray + /var/lib/pg-node/sync (applied by iran-sync-apply)." >&2
echo "Run on Exit: vpn-path status|auto|cf|xhttp|direct|tuic" >&2
if [[ "${1:-}" == "status" || "${1:-}" == "" ]]; then
  python3 - << 'PY'
import json
from pathlib import Path
p=Path("/var/lib/pg-node/generated/xray.json")
if not p.exists():
    print("generated missing"); raise SystemExit(1)
c=json.loads(p.read_text())
b=(c.get("routing") or {}).get("balancers") or [{}]
print("live-generated selector", ",".join((b[0] or {}).get("selector") or []))
print("fallback", (b[0] or {}).get("fallbackTag"))
PY
  exit 0
fi
exit 2
