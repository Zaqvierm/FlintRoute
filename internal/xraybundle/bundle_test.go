package xraybundle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-policy/internal/config"
)

func TestStoreLoadAndValidateRoutes(t *testing.T) {
	root := t.TempDir()
	raw := validBundle()
	source := filepath.Join(root, "source.json")
	if err := os.WriteFile(source, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := Hash(raw)
	stored, err := Store(root, source, digest)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := Path(root, digest)
	if err != nil {
		t.Fatal(err)
	}
	if stored != expected {
		t.Fatalf("bundle stored outside content-addressed path: got=%s want=%s", stored, expected)
	}
	bundle, err := Load(root, digest)
	if err != nil {
		t.Fatal(err)
	}
	routes := []config.Route{{Type: "vless", Tag: "server-a", SOCKS5: "127.0.0.1:12000"}}
	if err := ValidateRoutes(bundle, routes); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRejectsWrongHash(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.json")
	if err := os.WriteFile(source, validBundle(), 0o600); err != nil {
		t.Fatal(err)
	}
	wrong := "sha256:" + strings.Repeat("0", 64)
	if _, err := Store(root, source, wrong); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("wrong bundle hash was accepted: %v", err)
	}
}

func TestValidateRoutesRejectsWrongPortAndTag(t *testing.T) {
	root := t.TempDir()
	raw := validBundle()
	source := filepath.Join(root, "source.json")
	if err := os.WriteFile(source, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := Hash(raw)
	if _, err := Store(root, source, digest); err != nil {
		t.Fatal(err)
	}
	bundle, err := Load(root, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRoutes(bundle, []config.Route{{Type: "vless", Tag: "server-a", SOCKS5: "127.0.0.1:12001"}}); err == nil {
		t.Fatal("route with wrong SOCKS port was accepted")
	}
	if err := ValidateRoutes(bundle, []config.Route{{Type: "vless", Tag: "server-b", SOCKS5: "127.0.0.1:12000"}}); err == nil {
		t.Fatal("route with wrong outbound tag was accepted")
	}
}

func TestLoadRejectsCorruption(t *testing.T) {
	root := t.TempDir()
	raw := validBundle()
	source := filepath.Join(root, "source.json")
	if err := os.WriteFile(source, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := Hash(raw)
	stored, err := Store(root, source, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stored, append(raw, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root, digest); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("corrupted bundle was accepted: %v", err)
	}
}

func validBundle() []byte {
	return []byte(`{"log":{"loglevel":"warning"},"inbounds":[{"tag":"socks-server-a","listen":"127.0.0.1","port":12000,"protocol":"socks","settings":{"auth":"noauth","udp":true,"ip":"127.0.0.1"}}],"outbounds":[{"tag":"server-a","protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"11111111-1111-4111-8111-111111111111","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls"}}],"routing":{"domainStrategy":"AsIs","rules":[{"type":"field","inboundTag":["socks-server-a"],"outboundTag":"server-a"}]}}`)
}
