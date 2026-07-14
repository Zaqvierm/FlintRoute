#!/bin/sh
# shellcheck disable=SC2016
set -eu

section() {
  printf '\n## %s\n' "$1"
}

redact() {
  sed -E \
    -e 's#https?://[^[:space:]"]+#URL_REDACTED#g' \
    -e 's/"(password|token|secret|key|uuid|shortId|privateKey|subscription)"[[:space:]]*:[[:space:]]*"[^"]*"/"\1":"REDACTED"/g' \
    -e 's/([Pp]assword|[Tt]oken|[Ss]ecret|[Kk]ey|uuid|shortId|publicKey|privateKey|subscription)[=:][^[:space:]]+/\1=REDACTED/g' \
    -e 's/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}/UUID_REDACTED/g' \
    -e 's/([0-9]{1,3}\.){3}[0-9]{1,3}/IP_REDACTED/g' \
    -e 's/([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}/MAC_REDACTED/g' \
    -e 's/([0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:]{0,39}/IPV6_REDACTED/g'
}

run() {
  printf '\n$ %s\n' "$*"
  if "$@" 2>&1 | redact; then
    :
  else
    code="$?"
    printf 'command_failed=%s\n' "$code"
  fi
}

run_sh() {
  label="$1"
  script="$2"
  printf '\n$ %s\n' "$label"
  if sh -c "$script" 2>&1 | redact; then
    :
  else
    code="$?"
    printf 'command_failed=%s\n' "$code"
  fi
}

section "diagnostic contract"
printf 'mode=read_only\n'
printf 'unsafe_commands=not_run\n'
printf 'full_uci_dump=not_run\n'
printf 'full_logread=not_run\n'
printf 'full_nft_ruleset=not_run\n'
printf 'process_argv=not_run\n'

section "system"
run uname -a
run uname -m
run date -u
if command -v ubus >/dev/null 2>&1; then
  run ubus call system board
  run ubus call system info
else
  printf 'ubus=missing\n'
fi
if [ -f /etc/openwrt_release ]; then
  run cat /etc/openwrt_release
else
  printf 'openwrt_release=missing\n'
fi
run_sh "GL.iNet release files" 'for p in /etc/glversion /etc/glinet/glversion /etc/glinet_version /etc/version; do if [ -f "$p" ]; then printf "%s=" "$p"; sed -n "1p" "$p"; fi; done'
run_sh "opkg architectures" 'opkg print-architecture 2>/dev/null || true'

section "storage and memory"
run_sh "df -h / /overlay /tmp" 'df -h / /overlay /tmp 2>/dev/null'
run free
run_sh "cpu summary" 'sed -n -E "/^(system type|machine|model name|processor|cpu model|BogoMIPS|Hardware)[[:space:]]*:/p" /proc/cpuinfo 2>/dev/null | head -n 24'
run_sh "load and uptime" 'cat /proc/loadavg; cut -d" " -f1 /proc/uptime'
run_sh "thermal zones" 'for p in /sys/class/thermal/thermal_zone*/temp; do [ -r "$p" ] || continue; printf "%s=" "$p"; cat "$p"; done'

section "binaries"
run_sh "command allowlist" 'for x in sh ash jq jsonfilter curl wget drill nslookup nft ip bridge ss netstat timeout openssl sha256sum xray fw4 uci ubus opkg dnsmasq iwinfo; do printf "%s=" "$x"; command -v "$x" || printf "missing\n"; done'

section "versions"
run_sh "dnsmasq --version" 'dnsmasq --version 2>&1 | sed -n "1,5p"'
run_sh "nft --version" 'nft --version'
run_sh "fw4 -V" 'fw4 -V 2>/dev/null || fw4 -v 2>/dev/null'
run_sh "xray version" 'xray version 2>/dev/null | sed -n "1,3p"'
run_sh "ubus version" 'ubus -V 2>&1 || true'
run_sh "opkg version" 'opkg --version 2>&1 | sed -n "1,2p"'

section "network shape"
run_sh "ip rule show" 'ip rule show'
run_sh "ip -6 rule show" 'ip -6 rule show 2>/dev/null'
run_sh "ip route default" 'ip route show default'
run_sh "ip -6 route default" 'ip -6 route show default 2>/dev/null'
run_sh "interfaces names" 'ip -o link show | awk -F": " "{print \$2}" | sort'
run_sh "interface address families" 'ip -o addr show 2>/dev/null | awk "{print \$2, \$3}" | sort -u'
run_sh "bridge links" 'bridge link show 2>/dev/null || true'
run_sh "LAN status" 'ubus call network.interface.lan status 2>/dev/null || true'
run_sh "WAN status" 'ubus call network.interface.wan status 2>/dev/null || true'
run_sh "WAN6 status" 'ubus call network.interface.wan6 status 2>/dev/null || true'
run_sh "safe network UCI" 'uci -q show network 2>/dev/null | grep -E "\.(proto|device|ifname|type|ip6assign|delegate|metric|disabled)=" || true'

section "firewall shape"
run_sh "fw4 includes" 'ls -l /etc/nftables.d 2>/dev/null'
run_sh "nft tables" 'nft list tables 2>/dev/null'
run_sh "firewall defaults and zones" 'uci -q show firewall 2>/dev/null | grep -E "^firewall\.@(defaults|zone|forwarding)\[[0-9]+\]\.(name|network|input|output|forward|masq|mtu_fix|family|src|dest|enabled|flow_offloading|flow_offloading_hw)=" || true'
run_sh "flow offloading" 'printf "software="; uci -q get firewall.@defaults[0].flow_offloading 2>/dev/null || printf "unset\n"; printf "hardware="; uci -q get firewall.@defaults[0].flow_offloading_hw 2>/dev/null || printf "unset\n"'
run_sh "kernel nft/tproxy modules" 'grep -E "(^| )(nf_tables|nft_tproxy|nf_tproxy|xt_TPROXY|nf_conntrack|nft_socket|nft_fib)( |$)" /proc/modules 2>/dev/null || true'
run_sh "nft tproxy expression" 'nft describe tproxy 2>/dev/null | sed -n "1,12p" || true'
run_sh "policy routing support" 'ip rule help 2>&1 | sed -n "1,8p"; ip route help 2>&1 | sed -n "1,8p"'

section "DNS and DHCP shape"
run_sh "safe DHCP UCI" 'uci -q show dhcp 2>/dev/null | grep -E "\.(interface|ignore|port|noresolv|localuse|filter_aaaa|rebind_protection|authoritative|readethers)=" || true'
run_sh "resolv ownership" 'for p in /etc/resolv.conf /tmp/resolv.conf.d/resolv.conf.auto; do if [ -e "$p" ]; then ls -l "$p"; fi; done'

section "management and services"
run_sh "safe dropbear UCI" 'uci -q show dropbear 2>/dev/null | grep -E "\.(Interface|Port|PasswordAuth|RootPasswordAuth|GatewayPorts)=" || true'
run_sh "init service state" 'for s in dropbear uhttpd dnsmasq firewall xray zapret router-policy; do if [ -x "/etc/init.d/$s" ]; then printf "%s=" "$s"; /etc/init.d/$s running >/dev/null 2>&1 && printf "running" || printf "stopped"; /etc/init.d/$s enabled >/dev/null 2>&1 && printf ",enabled\n" || printf ",disabled\n"; else printf "%s=not-installed\n" "$s"; fi; done'
run_sh "listening sockets" 'ss -lntu 2>/dev/null || netstat -lntu 2>/dev/null || true'

section "router-policy files"
run_sh "router-policy paths" 'for p in /usr/bin/router-policy /usr/lib/router-policy /etc/router-policy /var/lib/router-policy /tmp/router-policy; do if [ -e "$p" ]; then ls -ld "$p"; else echo "$p missing"; fi; done'
run_sh "router-policy services" 'for s in /etc/init.d/router-policy /etc/init.d/router-policy-watchdog; do if [ -e "$s" ]; then ls -l "$s"; else echo "$s missing"; fi; done'

section "package hints"
run_sh "selected packages" 'opkg list-installed 2>/dev/null | grep -E "^(firewall4|dnsmasq|dnsmasq-full|nftables|kmod-nft|kmod-nf-tproxy|kmod-nft-tproxy|kmod-nft-socket|xray|zapret|curl|wget|jq|ip-full|ip-tiny|iwinfo|uhttpd|dropbear)" || true'

section "backup scope fingerprints"
run_sh "config metadata and SHA-256" 'for p in /etc/config/network /etc/config/firewall /etc/config/dhcp /etc/config/dropbear /etc/config/uhttpd; do [ -e "$p" ] || continue; ls -ld "$p"; if command -v sha256sum >/dev/null 2>&1; then sha256sum "$p"; elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 "$p"; else printf "%s hash-tool-missing\n" "$p"; fi; done'

section "done"
printf 'diagnostics_completed=true\n'
exit 0
