#!/bin/bash
# نصب پنل تسویه / فروش مشتری (settle-web) روی Exit
# Usage:
#   sudo bash install.sh
#   PANEL_BASE=https://panel.example.com:2096 AUTH_USER=settle AUTH_PASS='...' ./install.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../lib/panel_install_lib.sh
source "$DIR/../lib/panel_install_lib.sh"

panel_need_root

LIB=/usr/local/lib/settle-web
ETC=/etc/settle-web
VAR=/var/lib/settle-web
SECRETS=/root/.vpn-secrets/settle-web.env
LISTEN="${LISTEN:-}"
AUTH_USER="${AUTH_USER:-}"
AUTH_PASS="${AUTH_PASS:-}"
PANEL_BASE="${PANEL_BASE:-}"
KEEP_AUTH=0

if [[ ! -f "$DIR/app.py" ]]; then
  echo "app.py کنار install.sh نیست. از داخل پوشه scripts/settle-web در ریپو اجرا کنید." >&2
  exit 2
fi
if [[ ! -f "$DIR/../lib/panel_install_lib.sh" ]]; then
  echo "lib/panel_install_lib.sh لازم است — کل ریپو vpn-patch را کلون کنید." >&2
  exit 2
fi

echo "=== نصب settle-web (تسویه + /pay/) ==="
echo "روی سرور Exit اجرا کنید (کنار PasarGuard)."
echo

panel_prompt PANEL_BASE "آدرس عمومی پنل (بدون اسلش آخر)" "https://panel.example.com:2096"
PANEL_BASE="$(panel_normalize_base "$PANEL_BASE")"

panel_prompt AUTH_USER "نام کاربری ورود مدیر settle" "settle"
panel_prompt LISTEN "آدرس listen داخلی" "127.0.0.1:8789"

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

if [[ ! -f /root/.vpn-secrets/.env ]] || ! grep -q '^PANEL_API_KEY=' /root/.vpn-secrets/.env 2>/dev/null; then
  echo
  echo "هشدار: PANEL_API_KEY در /root/.vpn-secrets/.env نیست."
  echo "برای شارژ خودکار /pay/ و API پنل لازم است. بعداً اضافه کنید."
  echo
fi

install -d -m 755 "$LIB" "$ETC" "$VAR"
install -m 644 "$DIR/app.py" "$DIR/settle_ledger.py" "$DIR/pay_orders.py" "$LIB/"
install -m 644 "$DIR/pay_portal.html" "$LIB/"
install -d -m 755 "$LIB/static"
if [[ -d "$DIR/static" ]]; then
  cp -a "$DIR/static/." "$LIB/static/" 2>/dev/null || true
fi
install -m 644 "$DIR/settle-web.service" /etc/systemd/system/settle-web.service

export PANEL_CFG="$ETC/config.env"
export PANEL_LISTEN="$LISTEN"
export PANEL_USER="$AUTH_USER"
export PANEL_PASS="$AUTH_PASS"
export PANEL_COOKIE="settleweb"
export PANEL_KEEP="$KEEP_AUTH"
export PANEL_CFG_EXTRA="DB_PATH=$VAR/settle.db"
panel_write_auth_config
AUTH_USER="$(tr -d '\n' < "$ETC/.user.tmp")"
rm -f "$ETC/.user.tmp"

panel_save_creds "$ETC" "$AUTH_USER" "$AUTH_PASS" "$SECRETS" \
  "URL=${PANEL_BASE}/settle/" \
  "PAY_URL=${PANEL_BASE}/pay/" \
  "PANEL_BASE=${PANEL_BASE}"

panel_nginx_maybe \
  "/settle/" "http://${LISTEN}/" \
  "/pay/" "http://${LISTEN}/pay/"

panel_finish settle-web.service "${PANEL_BASE}/settle/" "$ETC/admin.pass"
echo "  pay:     ${PANEL_BASE}/pay/"
