# settle-web — تسویه نمایندگی و فروش مشتری

صورتحساب سقف حجم برای ادمین‌های PasarGuard + صفحهٔ عمومی `/pay/` برای شارژ مشتری.

**کجا:** سرور Exit (کنار پنل PasarGuard)

## نصب سریع

```bash
git clone https://github.com/rootitdev/vpn-patch.git
cd vpn-patch/settle-web
sudo bash install.sh
```

اسکریپت می‌پرسد: آدرس عمومی پنل، کاربر/رمز، listen، و اختیاریاً nginx.

بدون سؤال (اتوماسیون):

```bash
sudo PANEL_BASE='https://panel.example.com:2096' AUTH_USER=settle AUTH_PASS='رمز' \
  PANEL_NGINX_APPLY=n bash install.sh
```

## پیش‌نیاز

- PasarGuard در Docker روی همین سرور
- ترجیحاً `PANEL_API_KEY` در `/root/.vpn-secrets/.env` (برای `/pay/`)
- nginx روی پورت عمومی پنل (مثلاً 2096) تا locationهای `/settle/` و `/pay/` را پراکسی کند

## بعد از نصب

| مورد | مسیر |
|------|------|
| سرویس | `systemctl status settle-web` |
| رمز | `/etc/settle-web/admin.pass` |
| UI | `https://…/settle/` |
| فروش | `https://…/pay/` |
