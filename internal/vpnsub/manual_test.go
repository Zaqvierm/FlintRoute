package vpnsub

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testManualVLESSURI = "vless://33333333-3333-4333-8333-333333333333@manual.example:443?encryption=none&security=reality&type=tcp&sni=www.example.com&fp=chrome&pbk=public-key&sid=abcd&flow=xtls-rprx-vision#Home%20VPS"

func TestManualVLESSStoreIsBoundedSafeAndIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "xray", "manual-servers.json")
	servers, changed, err := AddManualServer(path, testManualVLESSURI)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || len(servers) != 1 || servers[0].Address != "manual.example" || servers[0].Port != 443 || !strings.HasPrefix(servers[0].ID, "manual-home-vps-") {
		t.Fatalf("unexpected safe manual server view: changed=%v servers=%+v", changed, servers)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("manual store mode=%o", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "33333333-3333-4333-8333-333333333333") {
		t.Fatal("manual store did not retain the credential needed by Xray")
	}
	_, changed, err = AddManualServer(path, testManualVLESSURI)
	if err != nil || changed {
		t.Fatalf("identical manual server caused a rewrite: changed=%v err=%v", changed, err)
	}
	servers, changed, err = DeleteManualServer(path, servers[0].ID)
	if err != nil || !changed || len(servers) != 0 {
		t.Fatalf("manual server delete failed: changed=%v servers=%+v err=%v", changed, servers, err)
	}
}

func TestManualVLESSRejectsUnsafeOrIncompleteURI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "xray", "manual-servers.json")
	for _, uri := range []string{
		"http://example.com",
		"vless://bad-uuid@example.com:443?security=tls&type=tcp",
		"vless://33333333-3333-4333-8333-333333333333@example.com:443?security=none&type=tcp",
		"vless://33333333-3333-4333-8333-333333333333@example.com:443?security=reality&type=tcp&sni=example.com",
	} {
		if _, _, err := AddManualServer(path, uri); err == nil {
			t.Fatalf("unsafe URI accepted: %s", uri)
		}
	}
}
