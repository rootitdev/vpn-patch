# vpn-patch

ابزار **مسیر بک‌هال** (`vpn-path`) + **سورس پنل‌های وب** برای نصب مجدد سریع.

ریپوی کامل خصوصی: [vpn-infra](https://github.com/rootitdev/vpn-infra).

## ساختار

| مسیر | کار |
|------|-----|
| `vpn-path*` / `vpn_path_*.py` / `path_health.py` / `vpn_failover*` | CLI و failover مسیر |
| `path-web/` | UI مسیر بک‌هال (`/path/`) — Exit |
| `settle-web/` | تسویه + `/pay/` — Exit |
| `ig-mult-web/` | ضریب اینستا (`/ig/`) — Exit |
| `sni-watch/` | دیده‌بان SNI (`/watch/`) — معمولاً ایران |
| `lib/panel_install_lib.sh` | توابع مشترک نصب تعاملی |

## نصب پنل وب (مثال)

```bash
git clone https://github.com/rootitdev/vpn-patch.git
cd vpn-patch/settle-web    # یا path-web / ig-mult-web / sni-watch
sudo bash install.sh
```

اسکریپت آدرس پنل، کاربر/رمز و اختیاریاً nginx را می‌پرسد.

## نصب vpn-path (Exit)

```bash
cd vpn-patch
install -m 755 vpn-path /usr/local/sbin/vpn-path
install -m 644 vpn-path-core.py vpn_path_lib.py vpn_paths.py vpn_failover.py path_health.py /usr/local/lib/vpn-path/
# یا بگذارید کلون در /root/vpn-patch بماند و VPN_SCRIPTS=/root/vpn-patch
install -m 644 vpn-failover.service vpn-failover.timer /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now vpn-failover.timer
vpn-path status
```

`path-web` برای import به `VPN_SCRIPTS` نیاز دارد که به همین کلون (ریشهٔ ریپو) اشاره کند.

## پنل admin و مسیر VPN

`panel.*` روی تونل **TO-AMS-DIRECT** پین می‌شود تا قفل CF/XHTTP داشبورد را 502 نکند.
