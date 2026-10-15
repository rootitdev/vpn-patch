# sni-watch — دیده‌بان SNI کاربران انتخابی

لاگ دسترسی Xray را برای دامنه‌های لیست‌شده و کاربران watchlist دنبال می‌کند.

**کجا:** نود ورود کلاینت (معمولاً **ایران**)، جایی که `access.log` پر-کاربر است.  
از Exit معمولاً با تونل SSH به `127.0.0.1:8787` و location `/watch/` سرو می‌شود.

## نصب سریع

```bash
git clone https://github.com/rootitdev/vpn-patch.git
cd vpn-patch/sni-watch
sudo bash install.sh
```

بدون سؤال:

```bash
sudo PANEL_BASE='https://panel.example.com:2096' \
  ACCESS_LOG=/var/log/xray/access.log AUTH_USER=watch AUTH_PASS='رمز' \
  PANEL_NGINX_APPLY=n bash install.sh
```

## پیش‌نیاز

- فایل access.log اکسری با `email:` کاربر
- برای UI عمومی از دامنه پنل: تونل/پراکسی از Exit (جدا از این اسکریپت)

## بعد از نصب

| مورد | مسیر |
|------|------|
| سرویس | `systemctl status sni-watch` |
| رمز | `/etc/sni-watch/admin.pass` |
| CLI | `sni-watch status` |
