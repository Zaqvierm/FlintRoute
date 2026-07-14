package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeOpenWrtRunner struct {
	mu      sync.Mutex
	outputs map[string][]byte
	errors  map[string]error
	calls   map[string]int
}

func (f *fakeOpenWrtRunner) Run(_ context.Context, command OpenWrtCommand, parameter string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := fakeCommandKey(command, parameter)
	f.calls[key]++
	if err := f.errors[key]; err != nil {
		return nil, err
	}
	output, ok := f.outputs[key]
	if !ok {
		return nil, fmt.Errorf("fixture missing for %s", key)
	}
	return append([]byte(nil), output...), nil
}

func fakeCommandKey(command OpenWrtCommand, parameter string) string {
	return string(command) + "|" + parameter
}

func newOpenWrtFixtureRunner() *fakeOpenWrtRunner {
	runner := &fakeOpenWrtRunner{outputs: map[string][]byte{}, errors: map[string]error{}, calls: map[string]int{}}
	put := func(command OpenWrtCommand, parameter, output string) {
		runner.outputs[fakeCommandKey(command, parameter)] = []byte(output)
	}
	put(commandSystemBoard, "", `{"kernel":"6.6.110","hostname":"router","system":"ARMv8","model":"GL.iNet GL-MT6000","board_name":"glinet,gl-mt6000","rootfs_type":"squashfs","release":{"distribution":"OpenWrt","version":"24.10.4","target":"mediatek/filogic","description":"OpenWrt 24.10.4 test"}}`)
	put(commandSystemInfo, "", `{"uptime":3600,"load":[65536,32768,0],"memory":{"total":1000000,"free":200000,"available":750000,"cached":100000,"buffered":50000},"root":{"total":7000000,"free":6000000,"used":1000000},"tmp":{"total":500000,"free":450000,"used":50000}}`)
	put(commandInterfaceStatus, "lan", `{"up":true,"available":true,"uptime":3500,"l3_device":"br-lan","proto":"static","device":"br-lan","ipv4-address":[{"address":"192.0.2.1","mask":24}],"ipv6-address":[],"dns-server":[]}`)
	put(commandInterfaceStatus, "wan", `{"up":true,"available":true,"uptime":3000,"l3_device":"eth1","proto":"dhcp","device":"eth1","ipv4-address":[{"address":"198.51.100.44","mask":24}],"ipv6-address":[],"dns-server":["203.0.113.53"]}`)
	put(commandInterfaceStatus, "wan6", `{"up":false,"available":true,"proto":"dhcpv6","device":"eth1","ipv4-address":[],"ipv6-address":[],"dns-server":[]}`)
	put(commandLinkList, "", `[{"ifname":"eth1","operstate":"UP","address":"02:00:00:00:00:01","flags":["UP"],"stats64":{"rx":{"bytes":1000,"packets":10},"tx":{"bytes":2000,"packets":20}}},{"ifname":"br-lan","operstate":"UP","address":"02:00:00:00:00:02","flags":["UP"]},{"ifname":"lan1","operstate":"UP","master":"br-lan","address":"02:00:00:00:00:03","flags":["UP"]}]`)
	put(commandDeviceStatus, "eth1", `{"up":true,"carrier":true,"speed":2500,"duplex":"full","statistics":{"rx_bytes":1100,"tx_bytes":2200}}`)
	put(commandDeviceStatus, "br-lan", `{"up":true,"carrier":true,"speed":0,"duplex":"unknown","statistics":{"rx_bytes":3000,"tx_bytes":4000}}`)
	put(commandDeviceStatus, "lan1", `{"up":true,"carrier":true,"speed":1000,"duplex":"full","statistics":{"rx_bytes":5000,"tx_bytes":6000}}`)
	put(commandRoutes4, "", `[{"dst":"default","gateway":"198.51.100.1","dev":"eth1","table":"main"},{"dst":"192.0.2.0/24","dev":"br-lan","table":"main"}]`)
	put(commandRoutes6, "", `[]`)
	put(commandRules4, "", `[{"priority":0,"table":"local"},{"priority":32766,"table":"main"}]`)
	put(commandRules6, "", `[{"priority":0,"table":"local"},{"priority":32766,"table":"main"}]`)
	put(commandWirelessStatus, "", `{"radio0":{"up":true,"interfaces":[{"section":"default_radio0","ifname":"wlan0","config":{"mode":"ap","ssid":"Test WiFi","network":["lan"],"encryption":"sae-mixed","disabled":false,"isolate":false}}]}}`)
	put(commandNeighbors, "", `[{"dst":"192.0.2.10","dev":"lan1","lladdr":"02:11:22:33:44:55","state":["REACHABLE"]}]`)
	put(commandDHCPLeases, "", "1893456000 02:11:22:33:44:55 192.0.2.10 workstation *\n")
	put(commandODHCPDHosts, "", "")
	put(commandFlowSoftware, "", "1\n")
	put(commandFlowHardware, "", "1\n")
	put(commandThermal, "", "53000\n")
	put(commandProcModules, "", "nft_tproxy 1 0 - Live 0x0\nnft_socket 1 0 - Live 0x0\n")
	put(commandFirewallCheck, "", "")
	put(commandNFTTables, "", "table inet fw4\ntable inet router_policy\n")
	for _, component := range []string{"dnsmasq", "uhttpd"} {
		put(commandComponentPresent, component, "present")
		put(commandProcess, component, "123")
	}
	for _, component := range []string{"xray", "zapret", "router-policy"} {
		runner.errors[fakeCommandKey(commandComponentPresent, component)] = os.ErrNotExist
		runner.errors[fakeCommandKey(commandProcess, component)] = errors.New("not running")
	}
	return runner
}

func TestOpenWrtProviderCollectsLiveFactsWithoutExposingWANIP(t *testing.T) {
	runner := newOpenWrtFixtureRunner()
	provider := NewOpenWrtProvider(WithOpenWrtRunner(runner), WithOpenWrtCacheTTL(time.Hour))

	overview := provider.Overview(nil)
	if overview["status"] != "OK" || overview["internet"] != "ROUTE_AVAILABLE" {
		t.Fatalf("unexpected overview status: %#v", overview)
	}
	if overview["data_plane"] != "UNVERIFIED" || overview["simulation"] != false {
		t.Fatalf("provider claimed unproved data plane: %#v", overview)
	}
	if overview["wan_speed_mbps"] != int64(2500) {
		t.Fatalf("WAN speed was not parsed: %#v", overview["wan_speed_mbps"])
	}
	encoded, err := json.Marshal(overview)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "198.51.100.44") || !strings.Contains(string(encoded), "sha256:") {
		t.Fatalf("external IP was exposed or not hashed: %s", encoded)
	}

	system := provider.System(nil)
	if system["model"] != "GL.iNet GL-MT6000" || system["kernel"] != "6.6.110" {
		t.Fatalf("board facts were not parsed: %#v", system)
	}
	devices := provider.Devices(nil)
	if len(devices) != 1 || devices[0]["interface"] != "lan1" || devices[0]["connected"] != true {
		t.Fatalf("device evidence was not merged: %#v", devices)
	}
	deviceJSON, _ := json.Marshal(devices)
	if strings.Contains(string(deviceJSON), "02:11:22:33:44:55") || !strings.Contains(string(deviceJSON), "**:**:**:**:44:55") {
		t.Fatalf("raw LAN MAC leaked or mask missing: %s", deviceJSON)
	}

	diagnostics := provider.Diagnostics(nil)
	capabilities := diagnostics["capabilities"].(map[string]any)
	if capabilities["tproxy"] != true || capabilities["nft_socket"] != true || capabilities["flow_offloading"] != "ENABLED" {
		t.Fatalf("capabilities were not parsed: %#v", capabilities)
	}
	topology := provider.Topology(nil)
	if len(topology["nodes"].([]map[string]any)) < 5 || topology["status"] != "OK" {
		t.Fatalf("topology did not use collected data: %#v", topology)
	}
}

func TestOpenWrtProviderBuildsVerifiedArtifactNetworkDiagnostics(t *testing.T) {
	runner := newOpenWrtFixtureRunner()
	provider := NewOpenWrtProvider(WithOpenWrtRunner(runner), WithOpenWrtCacheTTL(time.Hour))

	diagnostics := provider.NetworkDiagnostics(nil)
	if diagnostics.Status != "VERIFIED" || diagnostics.Reason != "" || diagnostics.Simulation {
		t.Fatalf("network diagnostics were not hardware-verifiable: %+v", diagnostics)
	}
	if diagnostics.WANInterface != "eth1" || len(diagnostics.LANInterfaces) != 1 || diagnostics.LANInterfaces[0] != "br-lan" {
		t.Fatalf("wrong live interfaces: %+v", diagnostics)
	}
	if diagnostics.IPv4Gateway != "198.51.100.1" || diagnostics.IPv6Available || diagnostics.IPv6Gateway != "" {
		t.Fatalf("wrong gateway evidence: %+v", diagnostics)
	}
	if diagnostics.FlowOffloadingStatus != "VERIFIED" || !diagnostics.SoftwareFlowOffload || !diagnostics.HardwareFlowOffload {
		t.Fatalf("flow offloading evidence was lost: %+v", diagnostics)
	}
	if diagnostics.TransparentProxyMode != "tproxy" || len(diagnostics.DNSResolvers) != 1 || diagnostics.DNSResolvers[0] != "203.0.113.53" {
		t.Fatalf("DNS or TPROXY evidence was lost: %+v", diagnostics)
	}
	if !diagnostics.ExpiresAt.After(diagnostics.CollectedAt) {
		t.Fatalf("network diagnostics have no bounded freshness: %+v", diagnostics)
	}
}

func TestOpenWrtProviderArtifactDiagnosticsFailClosedOnWrongGatewayDevice(t *testing.T) {
	runner := newOpenWrtFixtureRunner()
	runner.outputs[fakeCommandKey(commandRoutes4, "")] = []byte(`[{"dst":"default","gateway":"198.51.100.1","dev":"br-lan","table":"main"}]`)
	provider := NewOpenWrtProvider(WithOpenWrtRunner(runner), WithOpenWrtCacheTTL(time.Hour))

	diagnostics := provider.NetworkDiagnostics(nil)
	if diagnostics.Status != "UNVERIFIED" || diagnostics.Reason != "ipv4_gateway_unverified" {
		t.Fatalf("wrong-route diagnostics did not fail closed: %+v", diagnostics)
	}
}

func TestOpenWrtProviderMalformedUbusFailsHonestlyAndRedactsRunnerError(t *testing.T) {
	runner := newOpenWrtFixtureRunner()
	runner.outputs[fakeCommandKey(commandSystemBoard, "")] = []byte(`{"model":`)
	runner.errors[fakeCommandKey(commandInterfaceStatus, "wan")] = errors.New("token=must-not-leak")
	provider := NewOpenWrtProvider(WithOpenWrtRunner(runner), WithOpenWrtCacheTTL(time.Hour))

	system := provider.System(nil)
	if system["status"] != "ERROR" || system["model"] != "" {
		t.Fatalf("malformed board data did not fail closed: %#v", system)
	}
	encoded, err := json.Marshal(map[string]any{"system": system, "diagnostics": provider.Diagnostics(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "must-not-leak") || strings.Contains(string(encoded), "adapter-required") {
		t.Fatalf("runner error or production placeholder leaked: %s", encoded)
	}
	if !strings.Contains(string(encoded), "malformed_output") || !strings.Contains(string(encoded), "unavailable") {
		t.Fatalf("safe reason codes are missing: %s", encoded)
	}
}

func TestOpenWrtProviderCachesOneCollectionAcrossEndpoints(t *testing.T) {
	runner := newOpenWrtFixtureRunner()
	provider := NewOpenWrtProvider(WithOpenWrtRunner(runner), WithOpenWrtCacheTTL(time.Hour))
	_ = provider.Overview(nil)
	_ = provider.System(nil)
	_ = provider.Topology(nil)

	runner.mu.Lock()
	defer runner.mu.Unlock()
	if got := runner.calls[fakeCommandKey(commandSystemBoard, "")]; got != 1 {
		t.Fatalf("system board command called %d times, want 1", got)
	}
}

func TestFixedOpenWrtCommandsRejectUntrustedParameters(t *testing.T) {
	for _, test := range []struct {
		command   OpenWrtCommand
		parameter string
	}{
		{commandDeviceStatus, "eth0;reboot"},
		{commandDeviceStatus, "../../etc/shadow"},
		{commandInterfaceStatus, "wan;reboot"},
		{commandProcess, "xray --config /tmp/evil"},
		{commandComponentPresent, "../../xray"},
		{OpenWrtCommand("unknown"), ""},
	} {
		if _, _, err := fixedOpenWrtCommand(test.command, test.parameter); err == nil {
			t.Fatalf("accepted command=%q parameter=%q", test.command, test.parameter)
		}
	}
}

func TestDHCPLeaseParserRejectsMalformedOrOversizedInput(t *testing.T) {
	if _, err := parseDHCPLeases([]byte("not-a-lease\n")); err == nil {
		t.Fatal("malformed lease accepted")
	}
	oversized := []byte(strings.Repeat("x", (1<<20)+1))
	if _, err := parseDHCPLeases(oversized); err == nil {
		t.Fatal("oversized lease file accepted")
	}
}

func TestNeighborStateAcceptsIPRouteArrayAndFailsClosed(t *testing.T) {
	var reachable neighborInfo
	if err := json.Unmarshal([]byte(`{"dst":"192.0.2.10","dev":"lan1","state":["STALE","DELAY"]}`), &reachable); err != nil {
		t.Fatal(err)
	}
	if !neighborIsConnected(reachable.State) || string(reachable.State) != "STALE,DELAY" {
		t.Fatalf("valid iproute2 state array was not normalized: %q", reachable.State)
	}
	var failed neighborInfo
	if err := json.Unmarshal([]byte(`{"dst":"192.0.2.11","dev":"lan1","state":["FAILED"]}`), &failed); err != nil {
		t.Fatal(err)
	}
	if neighborIsConnected(failed.State) {
		t.Fatalf("FAILED neighbor was reported connected: %q", failed.State)
	}
	if err := json.Unmarshal([]byte(`{"dst":"192.0.2.12","dev":"lan1","state":["reachable"]}`), &failed); err == nil {
		t.Fatal("lowercase/untrusted neighbor state was accepted")
	}
}
