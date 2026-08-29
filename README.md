# vpn-path

Backhaul path control for a PasarGuard + Xray **2-hop** stack (Iran relay → Exit).

Runs on the **Exit** host. Changes the panel-core balancer selector
(`TO-AMS-CF` / `XHTTP` / `DIRECT` / `TUIC` / `auto`). Iran live Xray picks
changes up via desired-state sync — not by editing systemd JSON on Iran.

Related tool (separate repo): [instagram-multiplier](https://github.com/rootitdev/instagram-multiplier).

## Files

| File | Role |
|---|---|
| `vpn-path` | CLI entrypoint → `vpn-path-core.py` |
| `vpn-path-core.py` | `status` / `auto` / `cf` / `xhttp` / `direct` / `tuic` / `publish` / `test` |
| `vpn_path_lib.py` | Panel-core read/write helpers |
| `vpn_paths.py` | Priority map and path names |
| `path_health.py` | Health probe (run on Iran; used by failover) |
| `vpn_failover.py` | Auto failover daemon |
| `vpn-failover.service` + `.timer` | systemd units |
| `vpn-path-iran-stub.sh` | Optional stub if `/usr/local/sbin/vpn-path` exists on Iran |

## Install (Exit)

```bash
mkdir -p /root/vpn-infra/scripts /var/log/vpn-path
install -m 644 vpn_path_lib.py vpn_paths.py vpn-path-core.py \
  vpn_failover.py path_health.py /root/vpn-infra/scripts/
install -m 755 vpn-path /usr/local/sbin/vpn-path
install -m 644 vpn-failover.service vpn-failover.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vpn-failover.timer
vpn-path status
```

Adapt hardcoded Iran SSH / IPs for your stack. Secrets stay in
`/root/.vpn-secrets/.env` only (`PG_CORE_ID`, panel API key, etc.).

```bash
vpn-path status|auto|cf|xhttp|direct|tuic|publish|test
```

## Notes

- Do not commit `.env` secrets.
- On Iran, use the stub or nothing; real control is on Exit.
