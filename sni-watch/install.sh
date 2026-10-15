#!/bin/bash
# نصب دیده‌بان SNI (sni-watch) روی نود ورود (معمولاً ایران)
# Usage:
#   sudo bash install.sh
#   PANEL_BASE=https://panel.example.com:2096 ACCESS_LOG=/var/log/xray/access.log ./install.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../lib/panel_install_lib.sh
source "$DIR/../lib/panel_install_lib.sh"

panel_need_root

LIB=/usr/local/lib/sni-watch
ETC=/etc/sni-watch
VAR=/var/lib/sni-watch
SECRETS=/root/.vpn-secrets/sni-watch.env
LISTEN="${LISTEN:-}"
AUTH_USER="${AUTH_USER:-}"
AUTH_PASS="${AUTH_PASS:-}"
PANEL_BASE="${PANEL_BASE:-}"
ACCESS_LOG="${ACCESS_LOG:-}"
KEEP_AUTH=0

if [[ ! -f "$DIR/app.py" ]]; then
  echo "app.py کنار install.sh نیست." >&2
  exit 2
fi
if [[ ! -f "$DIR/../lib/panel_install_lib.sh" ]]; then
  echo "lib/panel_install_lib.sh لازم است — کل ریپو vpn-patch را کلون کنید." >&2
  exit 2
fi

echo "=== نصب sni-watch (دیده‌بان SNI) ==="
echo "روی نودی اجرا کنید که access.log پر-کاربر دارد (معمولاً ایران)."
echo "از Exit معمولاً با تونل SSH به 127.0.0.1:8787 پراکسی می‌شود (/watch/)."
echo

panel_prompt PANEL_BASE "آدرس عمومی پنل Exit برای لینک (اختیاری)" "https://panel.example.com:2096"
PANEL_BASE="$(panel_normalize_base "$PANEL_BASE")"
panel_prompt AUTH_USER "نام کاربری ورود" "watch"
panel_prompt LISTEN "آدرس listen داخلی" "127.0.0.1:8787"
panel_prompt ACCESS_LOG "مسیر access.log اکسری" "/var/log/xray/access.log"

if [[ -z "${AUTH_PASS}" && -f "$ETC/admin.pass" && -f "$ETC/config.env" ]]; then
  if panel_is_tty; then
    keep_ans=""
    panel_prompt_yn keep_ans "رمز قبلی پیدا شد — همان را نگه دارم؟" "y"
    if [[ "$keep_ans" == "y" ]]; then
      AUTH_PASS="$(cat "$ETC/admin.pass")"
      KEEP_AUTH=1
    fi
  else
    AUTH_PASS="$(cat "$ETC/admin.pass")"
    KEEP_AUTH=1
  fi
fi
if [[ -z "${AUTH_PASS}" ]]; then
  panel_prompt_secret AUTH_PASS "رمز ورود"
fi
if [[ -z "${AUTH_PASS}" ]]; then
  AUTH_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
  echo "رمز تصادفی ساخته شد → $ETC/admin.pass"
fi

install -d -m 755 "$LIB" "$ETC" "$VAR"
install -m 644 "$DIR/app.py" "$DIR/adult-domains.txt" "$DIR/sni_watch_lib.py" "$LIB/"
install -m 755 "$DIR/sni-watch" /usr/local/sbin/sni-watch
install -m 644 "$DIR/sni-watch.service" /etc/systemd/system/sni-watch.service

if [[ ! -f "$ETC/extra-domains.txt" ]]; then
  cat > "$ETC/extra-domains.txt" << 'EOF'
# Extra hostnames, one per line (suffix match).
EOF
  chmod 644 "$ETC/extra-domains.txt"
fi

export PANEL_CFG="$ETC/config.env"
export PANEL_LISTEN="$LISTEN"
export PANEL_USER="$AUTH_USER"
export PANEL_PASS="$AUTH_PASS"
export PANEL_COOKIE="sniwatch"
export PANEL_KEEP="$KEEP_AUTH"
export PANEL_CFG_EXTRA="$(cat <<EOF
ACCESS_LOG=${ACCESS_LOG}
DB_PATH=${VAR}/watch.db
DOMAINS_FILE=${LIB}/adult-domains.txt
EXTRA_DOMAINS=${ETC}/extra-domains.txt
COALESCE_SEC=120
USERMAP=/etc/sni-watch/usermap.json
EOF
)"
panel_write_auth_config
AUTH_USER="$(tr -d '\n' < "$ETC/.user.tmp")"
rm -f "$ETC/.user.tmp"

install -d -m 700 /root/.vpn-secrets
panel_save_creds "$ETC" "$AUTH_USER" "$AUTH_PASS" "$SECRETS" \
  "URL=${PANEL_BASE}/watch/" \
  "PANEL_BASE=${PANEL_BASE}" \
  "LISTEN=${LISTEN}"

echo
echo "نکته nginx: معمولاً location /watch/ روی Exit به تونل 127.0.0.1:8787 اشاره می‌کند,"
echo "نه مستقیم روی این سرور ایران. اگر همین‌جا nginx دارید:"
panel_nginx_maybe "/watch/" "http://${LISTEN}/"

panel_finish sni-watch.service "${PANEL_BASE}/watch/" "$ETC/admin.pass"
echo "  log:     $ACCESS_LOG"
