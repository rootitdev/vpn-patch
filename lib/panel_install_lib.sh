# Shared helpers for interactive panel installers.
# Sourced by scripts/*/install.sh — not meant to run alone.
# shellcheck shell=bash

panel_need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "این اسکریپت را با root اجرا کنید: sudo bash install.sh" >&2
    exit 1
  fi
}

panel_is_tty() {
  [[ -t 0 && -t 1 ]]
}

# prompt VAR "Question" "default"
panel_prompt() {
  local __var="$1" __q="$2" __def="${3:-}" __ans=""
  if [[ -n "${!__var:-}" ]]; then
    return 0
  fi
  if ! panel_is_tty; then
    if [[ -n "$__def" ]]; then
      printf -v "$__var" '%s' "$__def"
      return 0
    fi
    echo "مقدار $__var لازم است (یا اسکریپت را در ترمینال تعاملی اجرا کنید)." >&2
    exit 2
  fi
  if [[ -n "$__def" ]]; then
    read -r -p "$__q [$__def]: " __ans || true
    __ans="${__ans:-$__def}"
  else
    read -r -p "$__q: " __ans || true
  fi
  printf -v "$__var" '%s' "$__ans"
}

panel_prompt_secret() {
  local __var="$1" __q="$2" __ans=""
  if [[ -n "${!__var:-}" ]]; then
    return 0
  fi
  if ! panel_is_tty; then
    echo "مقدار $__var لازم است یا خالی بگذارید تا تصادفی ساخته شود در حالت TTY." >&2
    return 0
  fi
  read -r -s -p "$__q (خالی = تصادفی): " __ans || true
  echo
  printf -v "$__var" '%s' "$__ans"
}

panel_prompt_yn() {
  local __var="$1" __q="$2" __def="${3:-n}" __ans=""
  if [[ -n "${!__var:-}" ]]; then
    return 0
  fi
  if ! panel_is_tty; then
    printf -v "$__var" '%s' "$__def"
    return 0
  fi
  read -r -p "$__q [y/N]: " __ans || true
  __ans="$(echo "${__ans:-$__def}" | tr '[:upper:]' '[:lower:]')"
  if [[ "$__ans" == "y" || "$__ans" == "yes" ]]; then
    printf -v "$__var" '%s' "y"
  else
    printf -v "$__var" '%s' "n"
  fi
}

# Normalize public base: strip trailing slash
panel_normalize_base() {
  local b="${1%/}"
  b="${b%/}"
  printf '%s' "$b"
}

panel_write_auth_config() {
  # Args via env:
  # PANEL_CFG PANEL_LISTEN PANEL_USER PANEL_PASS PANEL_COOKIE PANEL_KEEP
  # optional extra lines in PANEL_CFG_EXTRA (newline-separated KEY=VAL)
  python3 << 'PY'
import hashlib, os, secrets
from pathlib import Path

path = Path(os.environ["PANEL_CFG"])
keep = os.environ.get("PANEL_KEEP") == "1"
old = {}
if keep and path.exists():
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = ln.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        old[k.strip()] = v.strip()

password = os.environ["PANEL_PASS"]
if keep and old.get("AUTH_HASH") and old.get("SESSION_SECRET"):
    auth_hash = old["AUTH_HASH"]
    secret = old["SESSION_SECRET"]
    user = old.get("AUTH_USER") or os.environ["PANEL_USER"]
else:
    salt = secrets.token_bytes(16)
    iters = 200_000
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters)
    auth_hash = "pbkdf2_sha256$%d$%s$%s" % (iters, salt.hex(), dk.hex())
    secret = secrets.token_hex(32)
    user = os.environ["PANEL_USER"]

lines = [
    "LISTEN=" + os.environ["PANEL_LISTEN"],
    "AUTH_USER=" + user,
    "AUTH_HASH=" + auth_hash,
    "SESSION_SECRET=" + secret,
    "COOKIE_NAME=" + os.environ.get("PANEL_COOKIE", "panelsess"),
]
extra = os.environ.get("PANEL_CFG_EXTRA") or ""
for ln in extra.splitlines():
    ln = ln.strip()
    if ln and "=" in ln:
        lines.append(ln)
lines.append("")
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text("\n".join(lines))
path.chmod(0o600)
path.with_name(".user.tmp").write_text(user + "\n")
PY
}

# Build nginx location block(s).
# panel_nginx_snippet PREFIX UPSTREAM_URL [PREFIX2 UPSTREAM2 ...]
# PREFIX like /settle/  UPSTREAM like http://127.0.0.1:8789/
panel_nginx_snippet() {
  local out="" prefix upstream bare
  while [[ $# -ge 2 ]]; do
    prefix="$1"
    upstream="$2"
    shift 2
    bare="${prefix%/}"
    out+="
    location = ${bare} {
        return 301 ${prefix};
    }
    location ${prefix} {
        proxy_pass ${upstream};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 120;
    }
"
  done
  printf '%s' "$out"
}

panel_nginx_print() {
  echo
  echo "===== nginx snippet (داخل server { } پنل) ====="
  panel_nginx_snippet "$@"
  echo "===== end snippet ====="
  echo
}

# Replace or insert location blocks for given prefixes before "location / {"
# Usage: panel_nginx_apply FILE PREFIX UPSTREAM [PREFIX2 UPSTREAM2 ...]
panel_nginx_apply() {
  local conf="$1"
  shift
  if [[ ! -f "$conf" ]]; then
    echo "فایل nginx پیدا نشد: $conf" >&2
    return 1
  fi
  local snippet markers=() tmp
  snippet="$(panel_nginx_snippet "$@")"
  while [[ $# -ge 2 ]]; do
    markers+=("${1%/}")
    shift 2
  done
  tmp="$(mktemp)"
  export PANEL_NGINX_CONF="$conf"
  export PANEL_NGINX_OUT="$tmp"
  export PANEL_NGINX_SNIPPET="$snippet"
  export PANEL_NGINX_MARKERS="$(IFS=,; echo "${markers[*]}")"
  python3 << 'PY'
import os, re
from pathlib import Path

conf = Path(os.environ["PANEL_NGINX_CONF"])
out = Path(os.environ["PANEL_NGINX_OUT"])
text = conf.read_text(encoding="utf-8", errors="replace")
snippet = os.environ["PANEL_NGINX_SNIPPET"].strip("\n") + "\n"
markers = [m for m in os.environ.get("PANEL_NGINX_MARKERS", "").split(",") if m]

for m in markers:
    text = re.sub(
        rf"\n[ \t]*location\s+=\s+{re.escape(m)}\s*\{{(?:[^{{}}]|\n)*\}}\n?",
        "\n",
        text,
    )
    text = re.sub(
        rf"\n[ \t]*location\s+{re.escape(m)}/\s*\{{(?:[^{{}}]|\n)*\}}\n?",
        "\n",
        text,
    )

m = re.search(r"\n[ \t]*location\s+/\s*\{", text)
if not m:
    text = text.rstrip() + "\n" + snippet + "\n"
else:
    text = text[: m.start()] + "\n" + snippet + text[m.start() :]

out.write_text(text)
PY
  if nginx -t -c /etc/nginx/nginx.conf 2>/dev/null; then
    # test with include: copy then nginx -t against live after install
    :
  fi
  # Validate by temporarily swapping is risky; write then nginx -t
  cp -a "$conf" "${conf}.bak.panel-install"
  cat "$tmp" > "$conf"
  rm -f "$tmp"
  if nginx -t 2>/dev/null; then
    systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null || true
    echo "nginx به‌روز شد: $conf (بکاپ: ${conf}.bak.panel-install)"
    return 0
  fi
  echo "nginx -t رد شد؛ کانفیگ قبلی برگردانده شد." >&2
  mv "${conf}.bak.panel-install" "$conf"
  return 1
}

panel_nginx_maybe() {
  # PANEL_NGINX_APPLY=y|n  PANEL_NGINX_CONF=path  then same args as snippet
  local apply="${PANEL_NGINX_APPLY:-}"
  local conf="${PANEL_NGINX_CONF:-/etc/nginx/sites-available/vpn-panel}"
  panel_nginx_print "$@"
  if [[ -z "$apply" ]]; then
    panel_prompt_yn apply "همین الان این locationها را در nginx بنویسم؟" "n"
  else
    apply="$PANEL_NGINX_APPLY"
  fi
  if [[ "$apply" != "y" ]]; then
    echo "nginx را دستی با snippet بالا تنظیم کنید."
    return 0
  fi
  if [[ -z "${PANEL_NGINX_CONF:-}" ]]; then
    panel_prompt conf "مسیر فایل nginx پنل" "/etc/nginx/sites-available/vpn-panel"
  else
    conf="$PANEL_NGINX_CONF"
  fi
  panel_nginx_apply "$conf" "$@"
}

panel_save_creds() {
  local etc="$1" user="$2" pass="$3" secrets="$4"
  shift 4
  # remaining: lines for secrets file body after AUTH
  install -d -m 700 "$(dirname "$secrets")"
  install -d -m 700 "$etc" 2>/dev/null || install -d -m 755 "$etc"
  umask 077
  printf '%s\n' "$user" > "$etc/admin.user"
  printf '%s\n' "$pass" > "$etc/admin.pass"
  chmod 600 "$etc/admin.user" "$etc/admin.pass"
  {
    echo "AUTH_USER=$user"
    echo "AUTH_PASS=$pass"
    for line in "$@"; do
      echo "$line"
    done
  } > "$secrets"
  chmod 600 "$secrets"
}

panel_finish() {
  local unit="$1" url="$2" passfile="$3"
  systemctl daemon-reload
  systemctl enable --now "$unit"
  systemctl restart "$unit"
  echo
  echo "نصب تمام شد."
  echo "  service: $(systemctl is-active "$unit" 2>/dev/null || echo unknown)"
  echo "  url:     $url"
  echo "  pass:    $passfile"
}
