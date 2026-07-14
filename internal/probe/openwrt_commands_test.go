package probe

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRouteGetAndRules(t *testing.T) {
	route, err := parseRouteGet([]byte(`[{"dst":"203.0.113.10","dev":"wan","table":100}]`))
	if err != nil {
		t.Fatal(err)
	}
	if route.Interface != "wan" || route.Table != 100 {
		t.Fatalf("unexpected route: %+v", route)
	}
	rules, err := parseRules([]byte(`[{"priority":10010,"fwmark":"0x41/0xffffffff","table":100}]`), "4")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Mark != "0x41" || rules[0].Table != 100 || rules[0].Priority != 10010 {
		t.Fatalf("unexpected rules: %+v", rules)
	}
}

func TestParseNFTPolicyUsesExactRouteToken(t *testing.T) {
	raw := []byte(`{"nftables":[
		{"rule":{"comment":"rp route=direct-extra action=direct_bypass","expr":[{"counter":{"packets":900}}]}},
		{"rule":{"comment":"rp route=direct action=direct_bypass","expr":[{"counter":{"packets":12}}]}},
		{"rule":{"comment":"rp route=direct action=classify","expr":[{"counter":{"packets":3}}]}}
	]}`)
	policy, err := parseNFTPolicy(raw, "direct")
	if err != nil {
		t.Fatal(err)
	}
	if policy.Counter != 15 || !policy.Actions["direct_bypass"] || !policy.Actions["classify"] {
		t.Fatalf("unexpected nft policy: %+v", policy)
	}
}

func TestConntrackMarkRequiresMatchingTuple(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "nf_conntrack")
	content := "ipv4 2 tcp 6 120 ESTABLISHED src=192.0.2.2 dst=203.0.113.10 sport=50000 dport=443 mark=65 use=1\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	commands := &ExecOpenWrtCommands{conntrackPath: path}
	mark, err := commands.ConntrackMark("192.0.2.2", "203.0.113.10")
	if err != nil || mark != "0x41" {
		t.Fatalf("unexpected conntrack proof: mark=%q err=%v", mark, err)
	}
	if _, err := commands.ConntrackMark("192.0.2.3", "203.0.113.10"); err == nil {
		t.Fatal("foreign conntrack tuple was accepted")
	}
}

func TestMalformedCommandJSONIsRejected(t *testing.T) {
	if _, err := parseRouteGet([]byte(`{"dev":"wan"}`)); err == nil {
		t.Fatal("non-array route output was accepted")
	}
	if _, err := parseNFTPolicy([]byte(`{"nftables":`), "direct"); err == nil {
		t.Fatal("truncated nft output was accepted")
	}
}
