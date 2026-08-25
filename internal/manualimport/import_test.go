package manualimport

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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

func TestInspectRejectsPrivateVLESSEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "xray.json")
	writeManualFile(t, path, strings.Replace(minimalXray(testUUID1), "vc9.example.com", "192.168.1.2", 1))
	if _, err := Inspect(Options{XrayPath: path}); err == nil || !strings.Contains(err.Error(), "not a public endpoint") {
		t.Fatalf("expected private endpoint rejection, got %v", err)
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

func TestBuildAdoptionPlanRejectsSecretBearingReport(t *testing.T) {
	if _, err := BuildAdoptionPlan(Report{SecretsPrinted: true}); err == nil {
		t.Fatal("secret-bearing report was accepted")
	}
}

func minimalXray(uuid string) string {
	return `{"inbounds":[{"tag":"socks-proxy-1","listen":"127.0.0.1","port":12000,"protocol":"socks"}],"outbounds":[{"tag":"proxy-1","protocol":"vless","settings":{"vnext":[{"address":"vc9.example.com","port":22231,"users":[{"id":"` + uuid + `","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls"}}],"routing":{"rules":[{"type":"field","inboundTag":["socks-proxy-1"],"outboundTag":"proxy-1"}]}}`
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
