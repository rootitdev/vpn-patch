# vpn-path

Backhaul path control for a PasarGuard + Xray **2-hop** stack (Iran relay → Exit).

Runs on the **Exit** host. Changes the panel-core balancer selector
(`TO-AMS-DIRECT` / `XHTTP` / `Bunny` / `Gcore` / `CF-grey` / `auto`).
Iran live Xray picks changes up via desired-state sync — not by editing
systemd JSON on Iran.

Related: full stack lives in [vpn-infra](https://github.com/rootitdev/vpn-infra)
(private). Web UI: `path-web` under `scripts/path-web/` there.

## Files

| File | Role |
|---|---|
| `vpn-path` | CLI entrypoint → `vpn-path-core.py` |
| `vpn-path-core.py` | `status` / `auto` / `cf` / `xhttp` / `direct` / `bunny` / `gcore` / `cforange` / `publish` / `test` |
| `vpn_path_lib.py` | Panel-core read/write helpers |
| `vpn_paths.py` | Priority map and path names |
| `path_health.py` | Health probe (run on Iran; used by failover) |
| `vpn_failover.py` | Auto failover daemon |
| `vpn-failover.service` / `.timer` | systemd units |

## DPI vs reliability (rough)

More resistant to DPI → less: **CF orange (canary)** → **CDN grey (ex-CF)** → **Bunny** → **Gcore** → **XHTTP** → **Direct**.

Failover prefers what is healthy; after 3 consecutive probe failures it moves
(e.g. CF-grey SSL timeout → Direct).

## Panel admin UI

`panel.*` hostnames are pinned to **`TO-AMS-DIRECT`** (tunneled), independent of
the user VPN path lock. Otherwise locking users onto CF/XHTTP can 502
`/dashboard`, `/settle`, `/path` on Iran while VPN clients still work.

## Install (Exit)

```bash
git clone https://github.com/rootitdev/vpn-patch.git
cd vpn-patch
install -m 755 vpn-path /usr/local/sbin/vpn-path
install -m 644 vpn-path-core.py vpn_path_lib.py vpn_paths.py vpn_failover.py path_health.py \
  /root/vpn-infra/scripts/   # or set PYTHONPATH / VPN_SCRIPTS to this clone
install -m 644 vpn-failover.service vpn-failover.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vpn-failover.timer
vpn-path status
```

Needs `/root/.vpn-secrets/.env` with `PANEL_API_KEY` and `PG_CORE_ID`, and
`iran_sync_export.py` for `publish`.

## CLI

```bash
vpn-path status
vpn-path auto
vpn-path cf          # CDN grey (cdn.jetengine.ir)
vpn-path bunny
vpn-path xhttp
vpn-path direct
vpn-path direct --no-failover   # pin even if probes fail
vpn-path publish
```
