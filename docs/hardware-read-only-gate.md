# Flint 2 read-only validation gate

This is a checklist, not an installation script. The first hardware pass must
not install, restart, reboot, or change firewall/routing state.

## Preconditions

- Record the exact FlintRoute commit SHA and build hash.
- Confirm an independent recovery path before connecting to the router.
- Keep the current management session open while collecting evidence.
- Store output outside the router; redact credentials, tokens, UUIDs, and
  private endpoints.

## Read-only baseline

Run the following over the already-approved SSH path and save the raw output.

```sh
ubus call system board
ubus call system info
ubus call service list
cat /etc/openwrt_release
uname -a
df -h
free
ps w
```

Record process ownership for FlintRoute, Xray, Zapret/nfqws, dnsmasq,
netifd, procd, ubusd, rpcd, uhttpd/nginx, and dropbear. For each relevant PID:

```sh
pid=<pid>
cat /proc/$pid/stat
readlink /proc/$pid/exe
tr '\0' ' ' < /proc/$pid/cmdline; echo
ls /proc/$pid/fd | wc -l
```

Record listeners and sockets without terminating anything:

```sh
ss -lntup 2>/dev/null || netstat -lntup
ss -tan 2>/dev/null || netstat -tan
```

Record the current data plane:

```sh
ip -o addr
ip -o rule
ip -o route show table all
nft list ruleset
ubus call network.interface dump
ubus call dhcp ipv4leases
ubus call network.wireless status
```

## Permission invariant

Before any deployment, record the numeric mode, owner, and group of every
critical parent. Compare with `/rom` when that tree exists:

```sh
for p in / /etc /usr /usr/bin /usr/lib /etc/init.d /etc/hotplug.d; do
  stat -c '%a %u %g %n' "$p"
done
for p in / /etc /usr /usr/bin /usr/lib /etc/init.d /etc/hotplug.d; do
  [ -e "/rom$p" ] && stat -c '%a %u %g %n' "/rom$p"
done
```

Any missing or suspicious parent blocks deployment. Do not repair it
automatically and do not reboot to “see what happens”.

## Resource baseline

Collect two one-minute samples without generating traffic:

```sh
top -bn1 2>/dev/null || top -n 1
cat /proc/loadavg
cat /proc/stat | head -n 1
```

Save the FlintRoute process CPU, thread count, open-FD count, established
loopback sockets, and any active probe count. The post-deployment read-only
comparison must show no unexplained growth while idle.

## Deployment boundary

Only after this baseline is reviewed may deployment be planned. After an
installation, repeat the permission loop above manually and verify the same
critical modes before any reboot. Reboot is a separate gate and is forbidden
until those checks and management/data-plane proofs are recorded.
