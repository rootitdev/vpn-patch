# path-web — انتخاب مسیر بک‌هال

UI برای `vpn-path` (CF-grey / XHTTP / Bunny / Direct / auto). لاگین جدا از PasarGuard.

**کجا:** سرور Exit (کنار vpn-path و پنل)

## نصب سریع

```bash
git clone https://github.com/rootitdev/vpn-patch.git
cd vpn-patch/path-web
sudo bash install.sh
```

بدون سؤال:

```bash
sudo PANEL_BASE='https://panel.example.com:2096' AUTH_USER=path AUTH_PASS='رمز' \
  PANEL_NGINX_APPLY=n bash install.sh
```

## پیش‌نیاز

- `vpn-path` و دسترسی API پنل (`PANEL_API_KEY` / `PG_CORE_ID` در secrets)
- ریپو در مسیری که `VPN_SCRIPTS` به `scripts/` اشاره کند (نصب‌کننده تنظیم می‌کند)

## بعد از نصب

| مورد | مسیر |
|------|------|
| سرویس | `systemctl status path-web` |
| رمز | `/etc/path-web/admin.pass` |
| UI | `https://…/path/` |
