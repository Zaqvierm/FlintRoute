package security

import (
	"os"
	"path/filepath"
	"testing"

	"router-policy/internal/config"
)

func TestAuditFailsWithoutAuthStore(t *testing.T) {
	cfg := auditConfig(t)
	report := Audit(cfg)
	if !hasCheck(report, "auth-users", "fail") {
		t.Fatalf("expected auth-users fail, got %+v", report.Checks)
	}
	if report.Status != "fail" {
		t.Fatalf("expected fail summary, got %s", report.Status)
	}
}

func TestListenerBindClassificationNeverTreatsWildcardAsSafe(t *testing.T) {
	tests := []struct {
		bind, class, exposure string
		wan                   bool
	}{
		{"127.0.0.1", "loopback", "not-exposed", false},
		{"::1", "loopback", "not-exposed", false},
		{"0.0.0.0", "wildcard", "unresolved", true},
		{"::", "wildcard", "unresolved", true},
		{"192.168.1.1", "non-loopback", "unresolved", true},
		{"203.0.113.10", "non-loopback", "unresolved", true},
		{"malformed", "unknown", "unresolved", true},
	}
	for _, test := range tests {
		class, exposure, wan := classifyListenerBind(test.bind)
		if class != test.class || exposure != test.exposure || wan != test.wan {
			t.Fatalf("bind %s: got %s/%s/%v want %s/%s/%v", test.bind, class, exposure, wan, test.class, test.exposure, test.wan)
		}
	}
}

func TestWildcardAPIListenerFailsClosed(t *testing.T) {
	check := checkAPIBind([]OpenPort{{Bind: "0.0.0.0", Port: 8787, Protocol: "tcp", BindClass: "wildcard", ExposureStatus: "unresolved", WANExposed: true}}, nil)
	if check.Status != "fail" || check.Level != "critical" {
		t.Fatalf("wildcard API listener was not critical: %+v", check)
	}
}

func TestProcSocketReaderCoversTCPAndUDPWildcardListeners(t *testing.T) {
	dir := t.TempDir()
	tcpPath := filepath.Join(dir, "tcp")
	udpPath := filepath.Join(dir, "udp")
	header := "  sl  local_address rem_address   st\n"
	if err := os.WriteFile(tcpPath, []byte(header+"   0: 00000000:2253 00000000:0000 0A\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(udpPath, []byte(header+"   1: 00000000:0035 00000000:0000 07\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		path, protocol string
		port           int
	}{{tcpPath, "tcp", 8787}, {udpPath, "udp", 53}} {
		ports, err := readProcNetSockets(item.path, false, item.protocol)
		if err != nil || len(ports) != 1 {
			t.Fatalf("%s socket parse failed: ports=%+v err=%v", item.protocol, ports, err)
		}
		if ports[0].Port != item.port || ports[0].BindClass != "wildcard" || !ports[0].WANExposed {
			t.Fatalf("%s wildcard listener was misclassified: %+v", item.protocol, ports[0])
		}
	}
}

func TestProcSocketReaderSkipsConnectedUDP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "udp")
	data := "  sl  local_address rem_address   st\n" +
		"   0: 0100007F:C350 08080808:0035 01\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	ports, err := readProcNetSockets(path, false, "udp")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 0 {
		t.Fatalf("connected UDP socket was reported as listener: %+v", ports)
	}
}

func TestAuditDetectsGeoLockedDirectLeak(t *testing.T) {
	cfg := auditConfig(t)
	cfg.Policy.GeoLockedAllowDirect = true
	cfg.Routes = append(cfg.Routes, config.Route{Type: "direct", Tag: "direct"})
	cfg.Services = map[string]config.Service{
		"geo": {Category: "GEO_LOCKED", Domains: []string{"geo.test"}, AllowedPaths: []string{"direct"}},
	}
	report := Audit(cfg)
	if !hasCheck(report, "geo-locked-policy", "fail") {
		t.Fatalf("expected geo-locked-policy fail, got %+v", report.Checks)
	}
}

func hasCheck(report AuditReport, id, status string) bool {
	for _, check := range report.Checks {
		if check.ID == id && check.Status == status {
			return true
		}
	}
	return false
}

func auditConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Version:  2,
		Storage:  config.Storage{StateDir: t.TempDir()},
		Policy:   config.Policy{},
		Routes:   []config.Route{{Type: "smart_dns", Tag: "smart"}},
		Services: map[string]config.Service{},
	}
}
