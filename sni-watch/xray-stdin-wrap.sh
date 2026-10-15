#!/bin/sh
# Keep Xray access logging (node clears log.access). Memory only — no temp config file.
#
# Must exec-replace this process with xray.real. A leftover shell + pipe lets
# pg-node kill the wrapper while xray.real keeps listening (SO_REUSEPORT).
# iran-stats then only sees the newest API and panel used_traffic looks frozen.
REAL=/usr/local/bin/xray.real
buf=$(cat)
buf=$(printf '%s' "$buf" | sed 's|"access": ""|"access": "/var/log/xray/sni-access.log"|g')
buf=$(printf '%s' "$buf" | sed 's|"access":""|"access": "/var/log/xray/sni-access.log"|g')
exec "$REAL" "$@" <<EOF
$buf
EOF
