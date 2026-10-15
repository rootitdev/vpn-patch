#!/bin/bash
# نصب پنل ضریب اینستا (ig-mult-web) روی Exit
# Usage:
#   sudo bash install.sh
#   PANEL_BASE=https://panel.example.com:2096 AUTH_USER=ig AUTH_PASS='...' ./install.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../lib/panel_install_lib.sh
source "$DIR/../lib/panel_install_lib.sh"

panel_need_root

LIB=/usr/local/lib/ig-mult-web
ETC=/etc/ig-mult-web
SECRETS=/root/.vpn-secrets/ig-mult-web.env
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

echo "=== نصب ig-mult-web (ضریب اینستا) ==="
echo "روی سرور Exit اجرا کنید."
echo

panel_prompt PANEL_BASE "آدرس عمومی پنل (بدون اسلش آخر)" "https://panel.example.com:2096"
PANEL_BASE="$(panel_normalize_base "$PANEL_BASE")"
panel_prompt AUTH_USER "نام کاربری ورود" "ig"
panel_prompt LISTEN "آدرس listen داخلی" "127.0.0.1:8788"

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

install -d -m 755 "$LIB" "$ETC"
install -m 644 "$DIR/app.py" "$LIB/"
install -m 644 "$DIR/ig-mult-web.service" /etc/systemd/system/ig-mult-web.service
if [[ -f "$REPO_ROOT/instagram-multiplier" ]]; then
  install -m 755 "$REPO_ROOT/instagram-multiplier" /usr/local/sbin/instagram-multiplier
elif [[ -f /root/vpn-infra/scripts/instagram-multiplier ]]; then
  install -m 755 /root/vpn-infra/scripts/instagram-multiplier /usr/local/sbin/instagram-multiplier
fi

export PANEL_CFG="$ETC/config.env"
export PANEL_LISTEN="$LISTEN"
export PANEL_USER="$AUTH_USER"
export PANEL_PASS="$AUTH_PASS"
export PANEL_COOKIE="igmult"
export PANEL_KEEP="$KEEP_AUTH"
export PANEL_CFG_EXTRA=""
panel_write_auth_config
AUTH_USER="$(tr -d '\n' < "$ETC/.user.tmp")"
rm -f "$ETC/.user.tmp"

panel_save_creds "$ETC" "$AUTH_USER" "$AUTH_PASS" "$SECRETS" \
  "URL=${PANEL_BASE}/ig/" \
  "PANEL_BASE=${PANEL_BASE}"

panel_nginx_maybe "/ig/" "http://${LISTEN}/"

panel_finish ig-mult-web.service "${PANEL_BASE}/ig/" "$ETC/admin.pass"
