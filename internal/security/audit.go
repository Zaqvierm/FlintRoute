package security

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"router-policy/internal/config"
)

type AuditReport struct {
	Status      string       `json:"status"`
	Checks      []AuditCheck `json:"checks"`
	OpenPorts   []OpenPort   `json:"open_ports"`
	Boundaries  []string     `json:"trust_boundaries"`
	AttackNotes []string     `json:"attack_notes"`
}

type AuditCheck struct {
	ID       string `json:"id"`
	Level    string `json:"level"`
	Status   string `json:"status"`
	Message  string `json:"message"`
	Requires string `json:"requires,omitempty"`
}

type OpenPort struct {
	Bind       string `json:"bind"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	Purpose    string `json:"purpose"`
	WANExposed bool   `json:"wan_exposed"`
}

func Audit(cfg *config.Config) AuditReport {
	openPorts, portErr := readSystemOpenPorts()
	if openPorts == nil {
		openPorts = []OpenPort{}
	}
	checks := []AuditCheck{
		checkProcNet(portErr),
		checkAPIBind(openPorts, portErr),
		checkAuthFiles(cfg),
		checkSetupToken(cfg),
		checkGeoLockedPolicy(cfg),
		{ID: "flint2-diagnostics", Level: "high", Status: "requires-device", Message: "activation needs real Flint 2 diagnostics", Requires: "ubus, fw4, nft, dnsmasq, ip route, ip -6 route"},
		{ID: "tls", Level: "high", Status: "requires-device", Message: "LAN HTTPS certificate is not verified on this host", Requires: "router TLS config"},
		{ID: "ipv6-leak", Level: "critical", Status: "requires-device", Message: "IPv6 route and nft guard need target route tables", Requires: "ip -6 route and fw4 print"},
	}
	return AuditReport{
		Status:      summarize(checks),
		Checks:      checks,
		OpenPorts:   openPorts,
		Boundaries:  []string{"LAN admin browser -> API", "API -> control plane", "control plane -> OpenWrt adapter", "data plane -> nft/dnsmasq/Xray"},
		AttackNotes: []string{"Do not expose API listener on WAN", "Do not return VPN URL/UUID/Telegram token through API", "Do not execute subscription content as commands"},
	}
}

func checkProcNet(err error) AuditCheck {
	if err != nil {
		return AuditCheck{ID: "proc-net", Level: "medium", Status: "unavailable", Message: err.Error(), Requires: "/proc/net/tcp or equivalent ss/netstat"}
	}
	return AuditCheck{ID: "proc-net", Level: "medium", Status: "pass", Message: "open TCP listeners read from system"}
}

func checkAPIBind(ports []OpenPort, err error) AuditCheck {
	if err != nil {
		return AuditCheck{ID: "api-bind", Level: "critical", Status: "unavailable", Message: "cannot inspect API listener bind", Requires: "/proc/net/tcp"}
	}
	for _, p := range ports {
		if p.Port == 8787 && p.WANExposed {
			return AuditCheck{ID: "api-bind", Level: "critical", Status: "fail", Message: fmt.Sprintf("router-policy API port is exposed on %s", p.Bind)}
		}
	}
	return AuditCheck{ID: "api-bind", Level: "critical", Status: "pass", Message: "no WAN-exposed router-policy API listener found"}
}

func checkAuthFiles(cfg *config.Config) AuditCheck {
	path := filepath.Join(cfg.Storage.StateDir, "auth", "users.json")
	info, err := os.Stat(path)
	if err != nil {
		return AuditCheck{ID: "auth-users", Level: "critical", Status: "fail", Message: "no administrator user store found"}
	}
	if info.IsDir() {
		return AuditCheck{ID: "auth-users", Level: "critical", Status: "fail", Message: "user store path is a directory"}
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return AuditCheck{ID: "auth-users", Level: "critical", Status: "fail", Message: "user store is readable by group/other"}
	}
	return AuditCheck{ID: "auth-users", Level: "critical", Status: "pass", Message: "administrator user store exists with restricted permissions"}
}

func checkSetupToken(cfg *config.Config) AuditCheck {
	path := filepath.Join(cfg.Storage.StateDir, "auth", "setup-token.json")
	info, err := os.Stat(path)
	if err != nil {
		return AuditCheck{ID: "setup-token", Level: "high", Status: "pass", Message: "setup token is absent"}
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return AuditCheck{ID: "setup-token", Level: "high", Status: "fail", Message: "setup token permissions are too broad"}
	}
	return AuditCheck{ID: "setup-token", Level: "high", Status: "warning", Message: "setup token exists; LAN listener must remain disabled until setup is complete"}
}

func checkGeoLockedPolicy(cfg *config.Config) AuditCheck {
	for name, svc := range cfg.Services {
		if svc.Category != "GEO_LOCKED" {
			continue
		}
		for _, route := range cfg.Routes {
			if (route.Type == "direct" || route.Type == "zapret") && config.PathAllowed(svc, route, cfg.Policy) {
				return AuditCheck{ID: "geo-locked-policy", Level: "critical", Status: "fail", Message: "GEO_LOCKED service can use unsafe path: " + name + " -> " + route.Type}
			}
		}
	}
	return AuditCheck{ID: "geo-locked-policy", Level: "critical", Status: "pass", Message: "GEO_LOCKED services cannot use direct/zapret by policy"}
}

func summarize(checks []AuditCheck) string {
	status := "pass"
	for _, c := range checks {
		switch c.Status {
		case "fail":
			return "fail"
		case "warning":
			if status == "pass" {
				status = "warning"
			}
		case "unavailable", "requires-device":
			if status == "pass" {
				status = "incomplete"
			}
		}
	}
	return status
}

func readSystemOpenPorts() ([]OpenPort, error) {
	var out []OpenPort
	var errs []string
	for _, item := range []struct {
		path  string
		ipv6  bool
		proto string
	}{
		{"/proc/net/tcp", false, "tcp"},
		{"/proc/net/tcp6", true, "tcp6"},
	} {
		ports, err := readProcNetTCP(item.path, item.ipv6, item.proto)
		if err != nil {
			errs = append(errs, item.path+": "+err.Error())
			continue
		}
		out = append(out, ports...)
	}
	if len(out) == 0 && len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return out, nil
}

func readProcNetTCP(path string, ipv6 bool, proto string) ([]OpenPort, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []OpenPort
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		host, port, err := parseProcAddress(fields[1], ipv6)
		if err != nil {
			continue
		}
		out = append(out, OpenPort{Bind: host, Port: port, Protocol: proto, Purpose: classifyPort(port), WANExposed: isWANExposed(host)})
	}
	return out, sc.Err()
}

func parseProcAddress(raw string, ipv6 bool) (string, int, error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("bad address")
	}
	port64, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0, err
	}
	if ipv6 {
		return parseProcIPv6(parts[0]), int(port64), nil
	}
	if len(parts[0]) != 8 {
		return "", 0, fmt.Errorf("bad ipv4")
	}
	b := make([]byte, 4)
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseUint(parts[0][i*2:i*2+2], 16, 8)
		if err != nil {
			return "", 0, err
		}
		b[3-i] = byte(v)
	}
	return net.IP(b).String(), int(port64), nil
}

func parseProcIPv6(raw string) string {
	if len(raw) != 32 {
		return raw
	}
	// /proc/net/tcp6 stores 4 little-endian uint32 words.
	var b [16]byte
	for word := 0; word < 4; word++ {
		chunk := raw[word*8 : word*8+8]
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(chunk[(3-i)*2:(3-i)*2+2], 16, 8)
			if err == nil {
				b[word*4+i] = byte(v)
			}
		}
	}
	return net.IP(b[:]).String()
}

func isWANExposed(bind string) bool {
	ip := net.ParseIP(bind)
	if ip == nil {
		return true
	}
	return !ip.IsLoopback() && !ip.IsUnspecified()
}

func classifyPort(port int) string {
	switch port {
	case 53:
		return "dns"
	case 8787:
		return "router-policy-api"
	case 1080, 1180, 12000:
		return "proxy"
	default:
		return "unknown"
	}
}
