import fs from "node:fs";

const [planPath, manifestHash, outputPath] = process.argv.slice(2);
if (!planPath || !manifestHash || !outputPath) {
  throw new Error("usage: build-data-plane-evidence.mjs PLAN MANIFEST_HASH OUTPUT");
}

const plan = JSON.parse(fs.readFileSync(planPath, "utf8"));
const checkedAt = new Date().toISOString();
const routes = plan.required_route_proofs.map((required, index) => {
  const drop = required.type === "drop";
  return {
    route_tag: required.tag,
    route_type: required.type,
    adapter_revision: plan.binding.revision_id,
    candidate_hash: plan.binding.candidate_hash,
    artifact_manifest_hash: manifestHash,
    nft_mark: required.mark ?? "",
    conntrack_mark: required.mark ?? "",
    ip_rule_priority: required.rule_priority ?? 0,
    route_table: required.table ?? 0,
    interface: drop ? "" : required.type === "direct" ? "wan" : "lo",
    dns_resolver: drop ? "" : "127.0.0.1:53",
    dns_protocol: drop ? "" : "udp",
    dns_response_safe: !drop,
    resolved_ip: drop ? "" : `192.0.2.${index + 10}`,
    connected_ip: drop ? "" : `192.0.2.${index + 10}`,
    local_ip: drop ? "" : "192.0.2.2",
    address_family: drop ? "" : "ipv4",
    transport:
      required.type === "vless" || required.type === "tg_ws_proxy" ? "socks5" : "direct",
    host_preserved: !drop,
    sni_preserved: !drop,
    xray_outbound_tag:
      required.type === "vless" ? required.tag : "",
    socks5_endpoint: required.type === "vless" ? `127.0.0.1:${19000 + index}` : "",
    socks5_loopback: required.type === "vless",
    direct_bypass_xray: required.type === "direct",
    direct_bypass_zapret: required.type === "direct",
    inherited_mark_cleared: required.type === "direct",
    zapret_installed: required.type === "zapret",
    zapret_flow_processed: required.type === "zapret",
    tcp_443_verified: required.type === "zapret",
    quic_policy: required.type === "zapret" ? "forced_tcp" : "",
    proxy_flow_processed: required.type === "tg_ws_proxy",
    ipv4_verified: !drop,
    ipv6_verified: !drop,
    drop_ipv4_enforced: drop,
    drop_ipv6_enforced: drop,
    drop_dns_enforced: drop,
    external_ip_hash:
      drop || required.type === "smart_dns" ? "" : `sha256:test-egress-${index}`,
    external_country:
      drop || required.type === "smart_dns" ? "" : required.type === "direct" ? "RU" : "DE",
    latency_ms: drop ? 0 : 10 + index,
    tls_result: drop ? "" : "OK",
    http_result: drop ? "" : "OK",
    content_result: drop ? "" : "OK",
    failure_stage: "",
    reason_code: drop ? "POLICY_DROP" : "TEST_ROUTE_PROVEN",
    status: "OK",
    evidence_source: "mock-openwrt-command",
    simulation: true,
    checked_at: checkedAt,
  };
});

const report = {
  binding: plan.binding,
  artifact_manifest_hash: manifestHash,
  dns_leak_free: true,
  ipv6_leak_free: true,
  geo_locked_kill_switch: true,
  routes,
  checked_at: checkedAt,
};

fs.writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
