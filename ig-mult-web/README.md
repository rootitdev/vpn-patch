# ig-mult-web — ضریب ترافیک اینستا

برای چند کاربر پنل، ترافیک دامنه‌های تنظیم‌شده با ضریب به `used_traffic` اضافه می‌شود. لاگین جدا از PasarGuard.

**کجا:** سرور Exit

## نصب سریع

```bash
git clone https://github.com/rootitdev/vpn-patch.git
cd vpn-patch/ig-mult-web
sudo bash install.sh
```

بدون سؤال:

```bash
sudo PANEL_BASE='https://panel.example.com:2096' AUTH_USER=ig AUTH_PASS='رمز' \
  PANEL_NGINX_APPLY=n bash install.sh
```

## پیش‌نیاز

- CLI `instagram-multiplier` (اسکریپت نصب در صورت وجود در ریپو کپی می‌کند)
- معمولاً `iran-sync-export` / آمار برای اثر روی هسته

## بعد از نصب

| مورد | مسیر |
|------|------|
| سرویس | `systemctl status ig-mult-web` |
| رمز | `/etc/ig-mult-web/admin.pass` |
| UI | `https://…/ig/` |
