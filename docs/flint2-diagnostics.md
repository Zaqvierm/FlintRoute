# Flint 2 Phase 0: Read-Only Diagnostics

This phase is intentionally read-only. Do not install, start, enable, activate,
reload, restart, copy files into `/etc`, or touch nftables/fw4/dnsmasq/UCI.

## Allowed

- SSH into the router.
- Copy only the diagnostic script to `/tmp`.
- Run the diagnostic script.
- Read the generated report.
- Delete the temporary script/report.

## Forbidden In Phase 0

- `install.sh --install`
- `install.sh --activate`
- `install.sh --test-apply`
- `adapter.sh apply-candidate`
- `adapter.sh commit`
- `fw4 reload`
- `/etc/init.d/dnsmasq restart`
- `uci set`, `uci commit`
- `nft -f`
- `ip rule add`, `ip route add`
- Xray config activation

## Safe Command Sequence

From your PC, after manually deciding the router host:

```powershell
scp .\scripts\diagnose-openwrt.sh root@ROUTER_IP:/tmp/router-policy-diagnose.sh
ssh root@ROUTER_IP 'sh /tmp/router-policy-diagnose.sh > /tmp/router-policy-diagnostics.txt'
scp root@ROUTER_IP:/tmp/router-policy-diagnostics.txt .\flint2-diagnostics.txt
ssh root@ROUTER_IP 'rm -f /tmp/router-policy-diagnose.sh /tmp/router-policy-diagnostics.txt'
```

Replace `ROUTER_IP` yourself. Do not paste secrets into the terminal.

## What The Script Does

The script prints:

- OpenWrt/GL.iNet board info;
- kernel and date;
- storage and memory summary;
- selected binary availability;
- selected version strings;
- route and interface shape;
- nft table names, not the full ruleset;
- router-policy path existence;
- selected installed package names.

The script does not print:

- full `uci show`;
- full `logread`;
- full `fw4 print`;
- full `nft list ruleset`;
- secret files;
- VPN subscription URL;
- Telegram tokens;
- full VLESS/Xray configs.

Output is redacted for IP-like, MAC-like, token-like, and key-like strings, but
you should still inspect the report before sharing it.

## Required Result Before Phase 1

Phase 1 can start only after the report confirms:

- exact firmware and architecture;
- firewall4/fw4 availability;
- nftables availability;
- dnsmasq version and nftset feasibility;
- `ip`/policy routing capability;
- available RAM and overlay space;
- whether Xray exists or must be installed;
- whether GL.iNet GUI may overwrite custom firewall includes;
- IPv6 state and likely leak surface.
