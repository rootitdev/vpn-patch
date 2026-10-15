#!/bin/sh
# Reinstall Xray stdin wrap if the node container was recreated.
set -e
WRAP=/usr/local/bin/xray-stdin-wrap.sh
REAL=/usr/local/bin/xray.real
HOST_WRAP=/var/lib/pg-node/xray-wrap/xray-stdin-wrap.sh
if ! docker exec node true 2>/dev/null; then
  exit 0
fi
if docker exec node test -x "$WRAP" && docker exec node test -x "$REAL"; then
  sz=$(docker exec node wc -c < /usr/local/bin/xray | tr -d " ")
  has_exec=$(docker exec node grep -c 'exec "$REAL"' "$WRAP" 2>/dev/null || true)
  if [ -n "$sz" ] && [ "$sz" -lt 2000 ] && [ "${has_exec:-0}" -ge 1 ]; then
    exit 0
  fi
fi
if [ ! -f "$HOST_WRAP" ]; then
  exit 0
fi
docker cp "$HOST_WRAP" "node:$WRAP"
docker exec node chmod 755 "$WRAP"
if ! docker exec node test -x "$REAL"; then
  docker exec node cp -a /usr/local/bin/xray "$REAL"
  docker exec node chmod 755 "$REAL"
fi
docker exec node sh -c "printf '%s\n' '#!/bin/sh' 'exec /bin/sh /usr/local/bin/xray-stdin-wrap.sh \"\$@\"' > /usr/local/bin/xray.new && chmod 755 /usr/local/bin/xray.new && mv -f /usr/local/bin/xray.new /usr/local/bin/xray"
# bounce xray so wrap is used. Only PIDs inside the node container: a host-wide
# pgrep also matches the host xray-subproxy (Iran panel/sub proxy).
pid=$(docker top node -eo pid,comm 2>/dev/null | awk '$2 == "xray.real" || $2 == "xray" { p = $1 } END { print p }')
if [ -n "$pid" ]; then
  kill "$pid" || true
fi
sleep 1
python3 /usr/local/sbin/iran_sync_apply.py
