#!/bin/bash
# نصب پنل مسیر بک‌هال (path-web) روی Exit
# Usage:
#   sudo bash install.sh
#   PANEL_BASE=https://panel.example.com:2096 AUTH_USER=path AUTH_PASS='...' ./install.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../lib/panel_install_lib.sh
source "$DIR/../lib/panel_install_lib.sh"

panel_need_root

LIB=/usr/local/lib/path-web
ETC=/etc/path-web
SECRETS=/root/.vpn-secrets/path-web.env
LISTEN="${LISTEN:-}"
AUTH_USER="${AUTH_USER:-}"
AUTH_PASS="${AUTH_PASS:-}"
PANEL_BASE="${PANEL_BASE:-}"
KEEP_AUTH=0
REPO_ROOT="$(cd "$DIR/.." && pwd)"

if [[ ! -f "$DIR/app.py" ]]; then
  echo "app.py کنار install.sh نیست." >&2
  exit 2
fi
if [[ ! -f "$DIR/../lib/panel_install_lib.sh" ]]; then
  echo "lib/panel_install_lib.sh لازم است — کل ریپو vpn-patch را کلون کنید." >&2
  exit 2
fi

echo "=== نصب path-web (انتخاب مسیر بک‌هال) ==="
echo "روی سرور Exit اجرا کنید (کنار vpn-path)."
echo

panel_prompt PANEL_BASE "آدرس عمومی پنل (بدون اسلش آخر)" "https://panel.example.com:2096"
PANEL_BASE="$(panel_normalize_base "$PANEL_BASE")"
panel_prompt AUTH_USER "نام کاربری ورود" "path"
panel_prompt LISTEN "آدرس listen داخلی" "127.0.0.1:8790"

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

if [[ ! -x /usr/local/sbin/vpn-path && -f "$REPO_ROOT/vpn-path" ]]; then
  install -m 755 "$REPO_ROOT/vpn-path" /usr/local/sbin/vpn-path
  echo "vpn-path به /usr/local/sbin نصب شد."
fi

install -d -m 755 "$LIB"
install -d -m 700 "$ETC"
install -m 644 "$DIR/app.py" "$LIB/"
install -m 644 "$DIR/path-web.service" /etc/systemd/system/path-web.service

# path-web imports from VPN_SCRIPTS / repo scripts
if ! grep -q '^Environment=VPN_SCRIPTS=' /etc/systemd/system/path-web.service 2>/dev/null; then
  if grep -q '^Environment=PYTHONDONTWRITEBYTECODE=1' /etc/systemd/system/path-web.service; then
    sed -i "/^Environment=PYTHONDONTWRITEBYTECODE=1/a Environment=VPN_SCRIPTS=${REPO_ROOT}" \
      /etc/systemd/system/path-web.service
  fi
fi

export PANEL_CFG="$ETC/config.env"
export PANEL_LISTEN="$LISTEN"
export PANEL_USER="$AUTH_USER"
export PANEL_PASS="$AUTH_PASS"
export PANEL_COOKIE="vpnpath"
export PANEL_KEEP="$KEEP_AUTH"
export PANEL_CFG_EXTRA=""
panel_write_auth_config
AUTH_USER="$(tr -d '\n' < "$ETC/.user.tmp")"
rm -f "$ETC/.user.tmp"

panel_save_creds "$ETC" "$AUTH_USER" "$AUTH_PASS" "$SECRETS" \
  "URL=${PANEL_BASE}/path/" \
  "PANEL_BASE=${PANEL_BASE}"

panel_nginx_maybe "/path/" "http://${LISTEN}/"

panel_finish path-web.service "${PANEL_BASE}/path/" "$ETC/admin.pass"
