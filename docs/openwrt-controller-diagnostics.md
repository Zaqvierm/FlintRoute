# Production OpenWrt diagnostics

The production controller runs as the unprivileged `daemon` user. Its
OpenWrt inventory reader may use only the read-only UBus methods granted by
`openwrt/acl.d/router-policy-provider.json`: system board/info, interface
dump, device status and wireless status.

Dataplane mutation still goes only through the root helper Unix socket. If
the ACL is missing or a read fails, diagnostics remain `UNVERIFIED`; the UI
must not claim that a candidate is deployable. The installer and uninstaller
track the ACL as an exact owned file and include it in the rollback backup.

The same boundary applies to `ProbeRoute`: route lookup, policy/rule reads,
NFT policy counters, managed-process liveness and conntrack mark evidence use
generation-bound `probe.*` helper requests. The controller never receives
`CAP_NET_ADMIN` and never executes `nft` or `ip` directly on production.
