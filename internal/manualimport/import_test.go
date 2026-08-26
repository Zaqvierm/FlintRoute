package manualimport

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"router-policy/internal/xraybundle"
)

const testUUID1 = "11111111-1111-4111-8111-111111111111"
const testUUID2 = "22222222-2222-4222-8222-222222222222"

func TestInspectBuildsCandidateWithoutSecretsInReport(t *testing.T) {
	dir := t.TempDir()
	xrayPath := filepath.Join(dir, "xray.json")
	q205Path := filepath.Join(dir, "q205.args")
	q208Path := filepath.Join(dir, "q208.args")
	outPath := filepath.Join(dir, "candidate.json")
	writeManualFile(t, xrayPath, `{
  "inbounds": [
    {"tag":"router-policy-tproxy-v4","listen":"127.0.0.1","port":12345,"protocol":"dokodemo-door"},
    {"tag":"router-policy-dns","listen":"127.0.0.1","port":14010,"protocol":"dokodemo-door"},
    {"tag":"socks-proxy-1","listen":"127.0.0.1","port":12000,"protocol":"socks","settings":{"udp":true}},
    {"tag":"socks-proxy-2","listen":"127.0.0.1","port":12001,"protocol":"socks","settings":{"udp":true}}
  ],
  "outbounds": [
    {"tag":"proxy-1","protocol":"vless","settings":{"vnext":[{"address":"vc9.example.com","port":22231,"users":[{"id":"`+testUUID1+`","encryption":"none","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"tls"}},
    {"tag":"proxy-2","protocol":"vless","settings":{"vnext":[{"address":"vc10.example.com","port":22231,"users":[{"id":"`+testUUID2+`","encryption":"none","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"tls"}},
    {"tag":"direct","protocol":"freedom"}
  ],
  "routing":{"rules":[
    {"type":"field","inboundTag":["socks-proxy-1"],"outboundTag":"proxy-1"},
    {"type":"field","inboundTag":["socks-proxy-2"],"outboundTag":"proxy-2"},
    {"type":"field","inboundTag":["router-policy-tproxy-v4"],"outboundTag":"direct"}
  ]}
}`)
	writeManualFile(t, q205Path, "--qnum=205\n--filter-tcp=443\n--dpi-desync=fake\n")
	writeManualFile(t, q208Path, "/usr/bin/nfqws\x00--qnum=208\x00--filter-tcp=443\x00--dpi-desync=fake\x00multidisorder\x00")

	report, err := Inspect(Options{
		XrayPath: xrayPath, ZapretArgs: []string{q205Path, q208Path}, OutputBundle: outPath,
		GeneratedAt: fixedTime(),
	})
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if !report.Xray.BundleReady || report.Xray.VLESSCount != 2 || report.Xray.SOCKSCount != 2 {
		t.Fatalf("unexpected Xray report: %+v", report.Xray)
	}
	if report.MigrationState != "blocked_on_ownership_handoff" {
		t.Fatalf("migration state = %q", report.MigrationState)
	}
	if !report.Xray.BundleReady || report.Xray.BundleScope != "loopback_socks_vless_only" {
		t.Fatalf("candidate scope was not explicit: %+v", report.Xray)
	}
	if len(report.Zapret) != 2 || report.Zapret[0].Queue != 205 || report.Zapret[1].Queue != 208 {
		t.Fatalf("unexpected Zapret report: %+v", report.Zapret)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), testUUID1) || strings.Contains(string(encoded), testUUID2) {
		t.Fatal("redacted report contains a VLESS credential")
	}
	bundle, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(bundle), testUUID1) {
		t.Fatal("candidate does not contain the credential required by the Xray runtime")
	}
	var root struct {
		Inbounds  []json.RawMessage `json:"inbounds"`
		Outbounds []json.RawMessage `json:"outbounds"`
		Routing   struct {
			Rules []json.RawMessage `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(bundle, &root); err != nil {
		t.Fatal(err)
	}
	if len(root.Inbounds) != 2 || len(root.Outbounds) != 2 || len(root.Routing.Rules) != 2 {
		t.Fatalf("candidate topology = inbounds:%d outbounds:%d rules:%d", len(root.Inbounds), len(root.Outbounds), len(root.Routing.Rules))
	}
}

func TestInspectRejectsReservedSystemQueue(t *testing.T) {
	dir := t.TempDir()
	xrayPath := filepath.Join(dir, "xray.json")
	qPath := filepath.Join(dir, "q.args")
	writeManualFile(t, xrayPath, minimalXray(testUUID1))
	writeManualFile(t, qPath, "--qnum=1\n--filter-tcp=443\n")
	report, err := Inspect(Options{XrayPath: xrayPath, ZapretArgs: []string{qPath}, GeneratedAt: fixedTime()})
	if err != nil || len(report.Zapret) != 1 || report.Zapret[0].QueueSafe {
		t.Fatalf("reserved queue was not marked unsafe: report=%+v err=%v", report, err)
	}
	if len(report.Conflicts) == 0 {
		t.Fatal("reserved queue did not produce a conflict")
	}
}

func TestInspectMarksHostScopedNFTQueueWithoutLeakingSourceIdentity(t *testing.T) {
	dir := t.TempDir()
	xrayPath := filepath.Join(dir, "xray.json")
	q205Path := filepath.Join(dir, "q205.args")
	q208Path := filepath.Join(dir, "q208.args")
	nftPath := filepath.Join(dir, "nft.txt")
	writeManualFile(t, xrayPath, minimalXray(testUUID1))
	writeManualFile(t, q205Path, "--qnum=205\n--filter-tcp=443\n")
	writeManualFile(t, q208Path, "--qnum=208\n--filter-tcp=443\n")
	writeManualFile(t, nftPath, `table inet app_zapret {
  chain postrouting {
    ip saddr 192.168.0.0/24 tcp dport 443 queue flags bypass to 205 comment "LAN"
    ip saddr 192.168.0.162 udp dport 443 drop comment "TV-QUIC"
    ip saddr 192.168.0.162 tcp dport 443 queue flags bypass to 208 comment "TV-TCP"
  }
}`)

	report, err := Inspect(Options{
		XrayPath: xrayPath, ZapretArgs: []string{q205Path, q208Path}, NFTPaths: []string{nftPath},
		GeneratedAt: fixedTime(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Zapret) != 2 || report.Zapret[0].DeviceScoped || !report.Zapret[1].DeviceScoped {
		t.Fatalf("host-scoped q208 evidence was not isolated: %+v", report.Zapret)
	}
	if scope := report.Zapret[1].DeviceScope; scope == nil || scope.Queue != 208 || scope.ScopeFingerprint == "" || !contains(scope.TCPPorts, "443") || !contains(scope.UDPDropPorts, "443") || scope.ScopeConflict {
		t.Fatalf("typed q208 scope evidence is incomplete: %+v", report.Zapret[1].DeviceScope)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "192.168.0.162") || strings.Contains(string(encoded), "TV-TCP") {
		t.Fatal("redacted report leaked nft source identity")
	}
	plan, err := BuildAdoptionPlan(report)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, resource := range plan.Resources {
		if resource.Kind == "device-scope" && resource.Identifier == "queue:208" {
			found = resource.OwnershipState == ownershipCollision
		}
	}
	if !found {
		t.Fatalf("device-scoped queue was not fenced in adoption plan: %+v", plan.Resources)
	}
}

func TestInspectRecognizesOnlyAuditedTypedDeviceStrategy(t *testing.T) {
	dir := t.TempDir()
	xrayPath := filepath.Join(dir, "xray.json")
	q208Path := filepath.Join(dir, "q208.args")
	writeManualFile(t, xrayPath, minimalXray(testUUID1))
	writeManualFile(t, q208Path, "/usr/bin/nfqws\x00--qnum=208\x00--filter-tcp=443\x00--dpi-desync=fake\x00multidisorder\x00--dpi-desync-split-pos=1,midsld\x00--dpi-desync-fooling=badseq\x00md5sig\x00")
	report, err := Inspect(Options{XrayPath: xrayPath, ZapretArgs: []string{q208Path}, GeneratedAt: fixedTime()})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Zapret) != 1 || !report.Zapret[0].TypedModelReady || report.Zapret[0].TypedStrategy != "tv-fake-multidisorder-v1" {
		t.Fatalf("q208 typed strategy was not recognized: %+v", report.Zapret)
	}
	plan, err := BuildAdoptionPlan(report)
	if err != nil {
		t.Fatal(err)
	}
	var typedResource *AdoptionResource
	for index := range plan.Resources {
		if plan.Resources[index].Kind == "profile-model" && plan.Resources[index].Identifier == "queue:208" {
			typedResource = &plan.Resources[index]
			break
		}
	}
	if typedResource == nil || typedResource.OwnershipState != ownershipCollision || !contains(typedResource.Evidence, "typed strategy: tv-fake-multidisorder-v1") {
		t.Fatalf("typed q208 handoff was not fenced in the plan: %+v", plan.Resources)
	}

	q205Path := filepath.Join(dir, "q205.args")
	writeManualFile(t, q205Path, "--qnum=205\n--hostlist=/etc/flint-manual/list.txt\n--dpi-desync=fake\n--new\n--filter-tcp=443\n")
	report, err = Inspect(Options{XrayPath: xrayPath, ZapretArgs: []string{q205Path}, GeneratedAt: fixedTime()})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Zapret) != 1 || report.Zapret[0].TypedModelReady || len(report.Zapret[0].ModelBlockers) == 0 {
		t.Fatalf("q205 unsupported strategy was not fenced: %+v", report.Zapret)
	}
	if !containsConflict(report.Conflicts, "Zapret profile model 205") {
		t.Fatalf("q205 typed-model blocker was not surfaced: %+v", report.Conflicts)
	}
}

func TestInspectRecognizesAuditedTypedDeviceStrategyWithProcExportBOM(t *testing.T) {
	dir := t.TempDir()
	xrayPath := filepath.Join(dir, "xray.json")
	q208Path := filepath.Join(dir, "q208.proc.args")
	writeManualFile(t, xrayPath, minimalXray(testUUID1))
	writeManualFile(t, q208Path, "\ufeff/usr/bin/nfqws\x00--qnum=208\x00--filter-tcp=443\x00--dpi-desync=fake\x00multidisorder\x00--dpi-desync-split-pos=1,midsld\x00--dpi-desync-fooling=badseq\x00md5sig\x00")

	report, err := Inspect(Options{XrayPath: xrayPath, ZapretArgs: []string{q208Path}, GeneratedAt: fixedTime()})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Zapret) != 1 || !report.Zapret[0].TypedModelReady || report.Zapret[0].TypedStrategy != "tv-fake-multidisorder-v1" {
		t.Fatalf("BOM-prefixed proc export was not recognized: %+v", report.Zapret)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsConflict(values []Conflict, resource string) bool {
	for _, value := range values {
		if value.Resource == resource {
			return true
		}
	}
	return false
}

func TestInspectRejectsPrivateVLESSEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "xray.json")
	writeManualFile(t, path, strings.Replace(minimalXray(testUUID1), "vc9.example.com", "192.168.1.2", 1))
	if _, err := Inspect(Options{XrayPath: path}); err == nil || !strings.Contains(err.Error(), "not a public endpoint") {
		t.Fatalf("expected private endpoint rejection, got %v", err)
	}
}

func TestInspectBuildsFullTopologyReviewCandidateWithoutReportingSecrets(t *testing.T) {
	dir := t.TempDir()
	xrayPath := filepath.Join(dir, "xray.json")
	outPath := filepath.Join(dir, "full-candidate.json")
	writeManualFile(t, xrayPath, fullXray(testUUID1))

	report, err := Inspect(Options{XrayPath: xrayPath, OutputFullBundle: outPath, GeneratedAt: fixedTime()})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Xray.FullBundleReady || report.Xray.FullBundleSHA256 == "" {
		t.Fatalf("full candidate was not recorded: %+v", report.Xray)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), testUUID1) {
		t.Fatal("full-topology report contains a VLESS credential")
	}
	bundle, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(bundle), testUUID1) || !strings.Contains(string(bundle), "router-policy-tproxy-v4") || !strings.Contains(string(bundle), "router-policy-dns") || !strings.Contains(string(bundle), "router-policy-tproxy-drop") {
		t.Fatalf("full candidate did not preserve reviewed topology: %s", bundle)
	}
	if got := xraybundle.Hash(bundle); got != report.Xray.FullBundleSHA256 {
		t.Fatalf("full candidate hash mismatch: got=%s want=%s", got, report.Xray.FullBundleSHA256)
	}
}

func TestInspectSummarizesManualPolicyRulesWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	xrayPath := filepath.Join(dir, "xray.json")
	dnsPath := filepath.Join(dir, "dnsmasq.conf")
	writeManualFile(t, xrayPath, fullXray(testUUID1))
	writeManualFile(t, dnsPath, "# ignored\nserver=/chatgpt.com/openai.com/127.0.0.1#14010\nnftset=/chatgpt.com/4#inet#flintroute_lite#vpn_dns4\n")

	report, err := Inspect(Options{XrayPath: xrayPath, DNSMasqPath: dnsPath, GeneratedAt: fixedTime()})
	if err != nil {
		t.Fatal(err)
	}
	var xrayRoute, dnsServer, dnsSet bool
	for _, policy := range report.Policies {
		switch policy.Kind + ":" + policy.Domain {
		case "xray-route:domain:example.com":
			xrayRoute = policy.OutboundTag == "proxy-1"
		case "dnsmasq-server:domain:chatgpt.com":
			dnsServer = policy.Target == "127.0.0.1#14010"
		case "dnsmasq-server:domain:openai.com":
			dnsServer = dnsServer && policy.Target == "127.0.0.1#14010"
		case "dnsmasq-nftset:domain:chatgpt.com":
			dnsSet = policy.Target == "4#inet#flintroute_lite#vpn_dns4"
		}
	}
	if !xrayRoute || !dnsServer || !dnsSet {
		t.Fatalf("manual policy inventory is incomplete: %+v", report.Policies)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), testUUID1) {
		t.Fatal("policy inventory contains a VLESS credential")
	}
	plan, err := BuildAdoptionPlan(report)
	if err != nil {
		t.Fatal(err)
	}
	var foundInventory bool
	for _, resource := range plan.Resources {
		if resource.Kind == "policy-inventory" && resource.Identifier == "manual-policy-rules" {
			foundInventory = true
		}
	}
	if !foundInventory {
		t.Fatalf("adoption plan omitted policy inventory: %+v", plan.Resources)
	}
}

func TestInspectPolicyInventoryRejectsUnsafeTagsAndTargets(t *testing.T) {
	dir := t.TempDir()
	xrayPath := filepath.Join(dir, "xray.json")
	dnsPath := filepath.Join(dir, "dnsmasq.conf")
	unsafeTag := strings.Replace(fullXray(testUUID1), `"outboundTag":"proxy-1"`, `"outboundTag":"`+testUUID1+`"`, 1)
	writeManualFile(t, xrayPath, unsafeTag)
	if _, err := Inspect(Options{XrayPath: xrayPath, GeneratedAt: fixedTime()}); err == nil || !strings.Contains(err.Error(), "unsafe outbound tag") {
		t.Fatalf("expected unsafe Xray tag rejection, got %v", err)
	}
	writeManualFile(t, xrayPath, fullXray(testUUID1))
	writeManualFile(t, dnsPath, "server=/example.com/10.0.0.1#53\n")
	report, err := Inspect(Options{XrayPath: xrayPath, DNSMasqPath: dnsPath, GeneratedAt: fixedTime()})
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range report.Policies {
		if policy.Kind == "dnsmasq-server" {
			t.Fatalf("unsafe DNS target was included in inventory: %+v", policy)
		}
	}
}

func TestFullTopologyCandidateRejectsLANInboundAndMissingFailClosed(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(string) string
		want   string
	}{
		{name: "lan inbound", mutate: func(raw string) string {
			return strings.Replace(raw, `"listen":"127.0.0.1","port":12345`, `"listen":"192.168.0.1","port":12345`, 1)
		}, want: "must listen on loopback"},
		{name: "no fail closed", mutate: func(raw string) string {
			return strings.Replace(raw, `,{"type":"field","inboundTag":["router-policy-tproxy-v4"],"outboundTag":"router-policy-tproxy-drop"}`, "", 1)
		}, want: "no explicit fail-closed rule"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			xrayPath := filepath.Join(dir, "xray.json")
			writeManualFile(t, xrayPath, test.mutate(fullXray(testUUID1)))
			_, err := Inspect(Options{XrayPath: xrayPath, OutputFullBundle: filepath.Join(dir, "candidate.json")})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q, got %v", test.want, err)
			}
		})
	}
}

func TestInspectPreservesDualStackListenerEndpoints(t *testing.T) {
	dir := t.TempDir()
	xrayPath := filepath.Join(dir, "xray.json")
	raw := strings.Replace(fullXray(testUUID1), `{"tag":"router-policy-dns"`, `{"tag":"router-policy-tproxy-v6","listen":"::1","port":12345,"protocol":"dokodemo-door","settings":{"followRedirect":true,"network":"tcp,udp"},"streamSettings":{"sockopt":{"tproxy":"tproxy"}}},{"tag":"router-policy-dns"`, 1)
	raw = strings.Replace(raw, `"inboundTag":["router-policy-tproxy-v4"]`, `"inboundTag":["router-policy-tproxy-v4","router-policy-tproxy-v6"]`, 1)
	writeManualFile(t, xrayPath, raw)
	report, err := Inspect(Options{XrayPath: xrayPath, OutputFullBundle: filepath.Join(dir, "candidate.json")})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"127.0.0.1:12000", "127.0.0.1:12345", "127.0.0.1:14010", "[::1]:12345"}
	if !reflect.DeepEqual(report.Xray.ListenerEndpoints, want) {
		t.Fatalf("listener endpoints lost address-family identity: got=%v want=%v", report.Xray.ListenerEndpoints, want)
	}
	if len(report.Xray.ListenerPorts) != len(want) {
		t.Fatalf("legacy listener port count mismatch: got=%v", report.Xray.ListenerPorts)
	}
}

func TestBuildAdoptionPlanUsesFullCandidateAndFencesHandoff(t *testing.T) {
	plan, err := BuildAdoptionPlan(Report{
		GeneratedAt: fixedTime().Format(time.RFC3339),
		Xray: XrayReport{
			Transparent:       1,
			DNSInbounds:       1,
			FullBundleReady:   true,
			FullBundleSHA256:  "sha256:full",
			ListenerEndpoints: []string{"127.0.0.1:12345"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ApplyAllowed || plan.CandidateSHA256 != "sha256:full" {
		t.Fatalf("full candidate was not carried as fenced review input: %+v", plan)
	}
	var foundHandoff, foundOldScope bool
	for _, blocker := range plan.Blockers {
		foundHandoff = foundHandoff || blocker.Resource == "manual Xray topology handoff"
		foundOldScope = foundOldScope || blocker.Resource == "manual Xray candidate scope"
	}
	if !foundHandoff || foundOldScope {
		t.Fatalf("full candidate received the wrong blocker set: %+v", plan.Blockers)
	}
}

func TestBuildAdoptionPlanNeverAllowsApplyFromReadableManualDataplane(t *testing.T) {
	dir := t.TempDir()
	xrayPath := filepath.Join(dir, "xray.json")
	q205Path := filepath.Join(dir, "q205.args")
	dnsPath := filepath.Join(dir, "dnsmasq.conf")
	nftPath := filepath.Join(dir, "nft.txt")
	writeManualFile(t, xrayPath, minimalXray(testUUID1))
	writeManualFile(t, q205Path, "--qnum=205\n--filter-tcp=443\n")
	writeManualFile(t, dnsPath, "server=/example.test/127.0.0.1#14010\n")
	writeManualFile(t, nftPath, "table inet app_zapret { }\n")
	report, err := Inspect(Options{
		XrayPath: xrayPath, ZapretArgs: []string{q205Path}, DNSMasqPath: dnsPath,
		NFTPaths: []string{nftPath}, OutputBundle: filepath.Join(dir, "candidate.json"), GeneratedAt: fixedTime(),
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildAdoptionPlan(report)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ApplyAllowed || plan.MigrationState != "blocked_on_ownership_handoff" {
		t.Fatalf("readable manual dataplane became applyable: %+v", plan)
	}
	if plan.CandidateSHA256 == "" {
		t.Fatal("candidate hash was not carried into the plan")
	}
	var foundQueue, foundDNS, foundNFT, foundLifecycle bool
	for _, resource := range plan.Resources {
		switch resource.Kind + ":" + resource.Identifier {
		case "nfqueue:queue:205":
			foundQueue = resource.OwnershipState == ownershipForeign
		case "file:manual-dnsmasq-include":
			foundDNS = resource.OwnershipState == ownershipForeign
		case "nft:manual-nft-snapshot":
			foundNFT = resource.OwnershipState == ownershipForeign
		case "lifecycle:manual-cron-procd":
			foundLifecycle = resource.OwnershipState == ownershipForeign
		}
	}
	if !foundQueue || !foundDNS || !foundNFT || !foundLifecycle {
		t.Fatalf("ownership boundaries were not represented: queue=%v dns=%v nft=%v lifecycle=%v", foundQueue, foundDNS, foundNFT, foundLifecycle)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), testUUID1) {
		t.Fatal("adoption plan contains a VLESS credential")
	}
}

func TestInspectAndPlanBindConcreteLifecycleEvidenceWithoutLeakingPath(t *testing.T) {
	dir := t.TempDir()
	xrayPath := filepath.Join(dir, "xray.json")
	lifecyclePath := filepath.Join(dir, "manual-init.sh")
	writeManualFile(t, xrayPath, minimalXray(testUUID1))
	writeManualFile(t, lifecyclePath, "#!/bin/sh\nexec /usr/bin/nfqws --qnum=205\n")

	report, err := Inspect(Options{
		XrayPath:       xrayPath,
		LifecyclePaths: []string{lifecyclePath},
		GeneratedAt:    fixedTime(),
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildAdoptionPlan(report)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), lifecyclePath) {
		t.Fatalf("absolute lifecycle path leaked into adoption plan: %s", encoded)
	}
	var found bool
	for _, resource := range plan.Resources {
		if resource.Kind == "file" && strings.HasPrefix(resource.Identifier, "manual-lifecycle/file-") {
			found = resource.OwnershipState == ownershipForeign && len(resource.Evidence) == 1 && strings.Contains(resource.Evidence[0], "manual lifecycle evidence hash:")
		}
	}
	if !found {
		t.Fatalf("concrete lifecycle evidence was not represented: %+v", plan.Resources)
	}
}

func TestBuildAdoptionPlanRejectsSecretBearingReport(t *testing.T) {
	if _, err := BuildAdoptionPlan(Report{SecretsPrinted: true}); err == nil {
		t.Fatal("secret-bearing report was accepted")
	}
}

func TestBuildAdoptionPlanFencesSOCKSCandidateWhenManualXrayHasTransparentOrDNSInbounds(t *testing.T) {
	plan, err := BuildAdoptionPlan(Report{
		GeneratedAt: fixedTime().Format(time.RFC3339),
		Xray:        XrayReport{Transparent: 1, DNSInbounds: 1, BundleReady: true, BundleSHA256: "sha256:candidate"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, blocker := range plan.Blockers {
		if blocker.Resource == "manual Xray candidate scope" && blocker.Severity == "SEV-1" {
			return
		}
	}
	t.Fatalf("transparent/DNS candidate scope was not fenced: %+v", plan.Blockers)
}

func minimalXray(uuid string) string {
	return `{"inbounds":[{"tag":"socks-proxy-1","listen":"127.0.0.1","port":12000,"protocol":"socks"}],"outbounds":[{"tag":"proxy-1","protocol":"vless","settings":{"vnext":[{"address":"vc9.example.com","port":22231,"users":[{"id":"` + uuid + `","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls"}}],"routing":{"rules":[{"type":"field","inboundTag":["socks-proxy-1"],"outboundTag":"proxy-1"}]}}`
}

func fullXray(uuid string) string {
	return `{"log":{"loglevel":"warning"},"inbounds":[{"tag":"router-policy-tproxy-v4","listen":"127.0.0.1","port":12345,"protocol":"dokodemo-door","settings":{"followRedirect":true,"network":"tcp,udp"},"streamSettings":{"sockopt":{"tproxy":"tproxy"}}},{"tag":"router-policy-dns","listen":"127.0.0.1","port":14010,"protocol":"dokodemo-door","settings":{"address":"1.1.1.1","port":53,"network":"tcp,udp"}},{"tag":"socks-proxy-1","listen":"127.0.0.1","port":12000,"protocol":"socks"}],"outbounds":[{"tag":"proxy-1","protocol":"vless","settings":{"vnext":[{"address":"vc9.example.com","port":443,"users":[{"id":"` + uuid + `","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls"}},{"tag":"direct","protocol":"freedom"},{"tag":"router-policy-tproxy-drop","protocol":"blackhole"}],"routing":{"domainStrategy":"AsIs","rules":[{"type":"field","inboundTag":["router-policy-tproxy-v4"],"outboundTag":"proxy-1","domain":["domain:example.com"]},{"type":"field","inboundTag":["router-policy-tproxy-v4"],"outboundTag":"router-policy-tproxy-drop"},{"type":"field","inboundTag":["router-policy-dns"],"outboundTag":"proxy-1"},{"type":"field","inboundTag":["socks-proxy-1"],"outboundTag":"proxy-1"}]}}`
}

func writeManualFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func fixedTime() (value time.Time) {
	return time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)
}
