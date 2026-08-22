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
	put(commandSystemBoard, "", `{"kernel":"6.6.110","hostname":"router","system":"ARMv8","model":"OpenWrt reference router","board_name":"vendor,reference","rootfs_type":"squashfs","release":{"distribution":"OpenWrt","version":"24.10.4","target":"mediatek/filogic","description":"OpenWrt 24.10.4 test"}}`)
	put(commandSystemInfo, "", `{"uptime":3600,"load":[65536,32768,0],"memory":{"total":1000000,"free":200000,"available":750000,"cached":100000,"buffered":50000},"root":{"total":7000000,"free":6000000,"used":1000000},"tmp":{"total":500000,"free":450000,"used":50000}}`)
	put(commandInterfaceDump, "", `{"interface":[{"interface":"home_net","up":true,"available":true,"uptime":3500,"l3_device":"home0","proto":"static","device":"home0","ipv4-address":[{"address":"192.0.2.1","mask":24}],"ipv6-address":[],"dns-server":[]},{"interface":"uplink_primary","up":true,"available":true,"uptime":3000,"l3_device":"uplink0","proto":"dhcp","device":"uplink0","ipv4-address":[{"address":"198.51.100.44","mask":24}],"ipv6-address":[],"dns-server":["203.0.113.53"]}]}`)
	put(commandLinkList, "", `[{"ifname":"uplink0","operstate":"UP","address":"02:00:00:00:00:01","flags":["UP"],"stats64":{"rx":{"bytes":1000,"packets":10},"tx":{"bytes":2000,"packets":20}}},{"ifname":"home0","operstate":"UP","address":"02:00:00:00:00:02","flags":["UP"]},{"ifname":"port-a","operstate":"UP","master":"home0","address":"02:00:00:00:00:03","flags":["UP"]},{"ifname":"radio-ap0","operstate":"UP","master":"home0","address":"02:00:00:00:00:04","flags":["UP"]}]`)
	put(commandDeviceStatus, "uplink0", `{"up":true,"carrier":true,"speed":2500,"duplex":"full","statistics":{"rx_bytes":1100,"tx_bytes":2200}}`)
	put(commandDeviceStatus, "home0", `{"up":true,"carrier":true,"speed":0,"duplex":"unknown","statistics":{"rx_bytes":3000,"tx_bytes":4000}}`)
	put(commandDeviceStatus, "port-a", `{"up":true,"carrier":true,"speed":1000,"duplex":"full","statistics":{"rx_bytes":5000,"tx_bytes":6000}}`)
	put(commandDeviceStatus, "radio-ap0", `{"up":true,"carrier":true,"speed":1200,"duplex":"full","statistics":{"rx_bytes":7000,"tx_bytes":8000}}`)
	put(commandRoutes4, "", `[{"dst":"default","gateway":"198.51.100.1","dev":"uplink0","table":"main"},{"dst":"192.0.2.0/24","dev":"home0","table":"main"}]`)
	put(commandRoutes6, "", `[]`)
	put(commandRules4, "", `[{"priority":0,"table":"local"},{"priority":32766,"table":"main"}]`)
	put(commandRules6, "", `[{"priority":0,"table":"local"},{"priority":32766,"table":"main"}]`)
	put(commandWirelessStatus, "", `{"radio0":{"up":true,"interfaces":[{"section":"default_radio0","ifname":"radio-ap0","config":{"mode":"ap","ssid":"Test WiFi","network":["home_net"],"encryption":"sae-mixed","disabled":false,"isolate":false}}]}}`)
	put(commandWirelessClients, "radio-ap0", `{"clients":{"02:11:22:33:44:66":{"authorized":true,"signal":-54,"signal_avg":-52,"connected_time":120,"rx":{"bytes":700},"tx":{"bytes":900}}}}`)
	put(commandBridgeFDB, "", `[{"mac":"02:11:22:33:44:55","dev":"port-a","master":"home0","state":"reachable"}]`)
	put(commandNeighbors, "", `[{"dst":"192.0.2.10","dev":"home0","lladdr":"02:11:22:33:44:55","state":["REACHABLE"]},{"dst":"192.0.2.20","dev":"home0","lladdr":"02:11:22:33:44:66","state":["REACHABLE"]}]`)
	put(commandDHCPLeases, "", "1893456000 02:11:22:33:44:55 192.0.2.10 workstation *\n1893456000 02:11:22:33:44:66 192.0.2.20 phone *\n")
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
	if system["model"] != "OpenWrt reference router" || system["kernel"] != "6.6.110" {
		t.Fatalf("board facts were not parsed: %#v", system)
	}
	devices := provider.Devices(nil)
	if len(devices) != 2 || devices[0]["interface"] != "radio-ap0" || devices[0]["kind"] != "wifi" || devices[1]["interface"] != "port-a" || devices[1]["kind"] != "ethernet" {
		t.Fatalf("device evidence was not merged: %#v", devices)
	}
	deviceJSON, _ := json.Marshal(devices)
	if strings.Contains(string(deviceJSON), "02:11:22:33:44:55") || strings.Contains(string(deviceJSON), "192.0.2.10") ||
		!strings.Contains(string(deviceJSON), "**:**:**:**:44:55") || !strings.Contains(string(deviceJSON), "192.0.*.*") {
		t.Fatalf("raw LAN address leaked or mask missing: %s", deviceJSON)
	}
	for _, device := range devices {
		if device["ip"] != nil || device["mac"] != nil {
			t.Fatalf("privacy response placed decorative text in raw identity fields: %#v", device)
		}
		if device["ip_display"] == nil || device["mac_display"] == nil || device["identity_available"] != true {
			t.Fatalf("privacy display semantics are incomplete: %#v", device)
		}
	}
	revealed := provider.DevicesWithPrivacy(nil, true)
	revealedJSON, _ := json.Marshal(revealed)
	if !strings.Contains(string(revealedJSON), "02:11:22:33:44:55") || !strings.Contains(string(revealedJSON), "192.0.2.10") || !strings.Contains(string(revealedJSON), "Test WiFi") {
		t.Fatalf("explicit address reveal did not return live inventory: %s", revealedJSON)
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
	for _, node := range topology["nodes"].([]map[string]any) {
		if node["type"] == "device" && node["ip"] != nil {
			t.Fatalf("topology leaked a raw client identity: %#v", node)
		}
	}
}

func TestDevelopmentProviderNeverFabricatesNetworkIdentity(t *testing.T) {
	provider := DevelopmentMockProvider{}
	for _, reveal := range []bool{false, true} {
		for _, device := range provider.DevicesWithPrivacy(nil, reveal) {
			if device["simulation"] != true || device["ip"] != nil || device["mac"] != nil || device["identity_available"] != false || device["addresses_revealed"] != false {
				t.Fatalf("simulation device masquerades as production identity: %#v", device)
			}
			if device["ip_display"] == nil || device["mac_display"] == nil {
				t.Fatalf("simulation display placeholder is missing: %#v", device)
			}
		}
	}
}

func TestDeviceInventoryTracksDynamicClientAddress(t *testing.T) {
	runner := newOpenWrtFixtureRunner()
	provider := NewOpenWrtProvider(WithOpenWrtRunner(runner), WithOpenWrtCacheTTL(0))
	before := provider.DevicesWithPrivacy(nil, true)
	if !deviceInventoryContainsIP(before, "192.0.2.10") {
		t.Fatalf("initial dynamic lease is missing: %#v", before)
	}
	runner.outputs[fakeCommandKey(commandDHCPLeases, "")] = []byte("1893456000 02:11:22:33:44:55 192.0.2.77 workstation *\n")
	runner.outputs[fakeCommandKey(commandNeighbors, "")] = []byte(`[{"dst":"192.0.2.77","dev":"home0","lladdr":"02:11:22:33:44:55","state":["REACHABLE"]}]`)
	after := provider.DevicesWithPrivacy(nil, true)
	if deviceInventoryContainsIP(after, "192.0.2.10") || !deviceInventoryContainsIP(after, "192.0.2.77") {
		t.Fatalf("device inventory retained a stale client address: %#v", after)
	}
}

func TestOpenWrtProviderFallsBackToBrctlFDB(t *testing.T) {
	runner := newOpenWrtFixtureRunner()
	runner.errors[fakeCommandKey(commandBridgeFDB, "")] = os.ErrNotExist
	runner.outputs[fakeCommandKey(commandBridgeFDBLegacy, "home0")] = []byte("PORT 0x3 port-a\nport no mac addr is local? ageing timer\n  3 02:11:22:33:44:55 no 2.07\n")
	provider := NewOpenWrtProvider(WithOpenWrtRunner(runner), WithOpenWrtCacheTTL(time.Hour))
	devices := provider.DevicesWithPrivacy(nil, true)
	for _, device := range devices {
		if device["ip"] == "192.0.2.10" && device["kind"] == "ethernet" && device["interface"] == "port-a" {
			return
		}
	}
	t.Fatalf("legacy bridge FDB did not identify the wired client: %#v", devices)
}

func TestDeviceInventoryCollapsesStaleRandomizedMACLeaseByHostname(t *testing.T) {
	now := time.Now().UTC()
	snapshot := &openWrtSnapshot{
		CollectedAt: now,
		DHCPLeases: []dhcpLease{
			{ExpiresAt: now.Add(time.Hour), MAC: "02:00:00:00:00:02", IP: "192.0.2.20", Hostname: "phone"},
			{ExpiresAt: now.Add(2 * time.Hour), MAC: "02:00:00:00:00:01", IP: "192.0.2.10", Hostname: "phone"},
		},
		Neighbors: []neighborInfo{
			{Dst: "192.0.2.10", State: neighborState("FAILED")},
			{Dst: "192.0.2.20", State: neighborState("FAILED")},
		},
	}
	devices := buildDeviceItems(snapshot, "test", true)
	if len(devices) != 1 || devices[0]["ip"] != "192.0.2.10" {
		t.Fatalf("stale randomized MAC lease was not collapsed: %#v", devices)
	}
}

func deviceInventoryContainsIP(items []map[string]any, expected string) bool {
	for _, item := range items {
		if item["ip"] == expected {
			return true
		}
	}
	return false
}

func TestOpenWrtProviderBuildsVerifiedArtifactNetworkDiagnostics(t *testing.T) {
	runner := newOpenWrtFixtureRunner()
	provider := NewOpenWrtProvider(WithOpenWrtRunner(runner), WithOpenWrtCacheTTL(time.Hour))

	diagnostics := provider.NetworkDiagnostics(nil)
	if diagnostics.Status != "VERIFIED" || diagnostics.Reason != "" || diagnostics.Simulation {
		t.Fatalf("network diagnostics were not hardware-verifiable: %+v", diagnostics)
	}
	if diagnostics.WANInterface != "uplink0" || len(diagnostics.WANInterfaces) != 1 || diagnostics.WANInterfaces[0] != "uplink0" || len(diagnostics.LANInterfaces) != 1 || diagnostics.LANInterfaces[0] != "home0" {
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

func TestOpenWrtProviderArtifactDiagnosticsFailClosedOnUnknownGatewayDevice(t *testing.T) {
	runner := newOpenWrtFixtureRunner()
	runner.outputs[fakeCommandKey(commandRoutes4, "")] = []byte(`[{"dst":"default","gateway":"198.51.100.1","dev":"missing0","table":"main"}]`)
	provider := NewOpenWrtProvider(WithOpenWrtRunner(runner), WithOpenWrtCacheTTL(time.Hour))

	diagnostics := provider.NetworkDiagnostics(nil)
	if diagnostics.Status != "UNVERIFIED" || diagnostics.Reason != "wan_interface_unverified" {
		t.Fatalf("wrong-route diagnostics did not fail closed: %+v", diagnostics)
	}
}

func TestOpenWrtProviderMalformedUbusFailsHonestlyAndRedactsRunnerError(t *testing.T) {
	runner := newOpenWrtFixtureRunner()
	runner.outputs[fakeCommandKey(commandSystemBoard, "")] = []byte(`{"model":`)
	runner.errors[fakeCommandKey(commandInterfaceDump, "")] = errors.New("token=must-not-leak")
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
		{commandWirelessClients, "wlan0;reboot"},
		{commandBridgeFDBLegacy, "br-lan;reboot"},
		{commandInterfaceDump, "wan;reboot"},
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

func TestDefaultRouteIgnoresPolicyFailClosedTables(t *testing.T) {
	routes := []routeInfo{
		{Dst: "default", Dev: "lo", Type: "unreachable", Table: float64(100)},
		{Dst: "default", Dev: "lo", Type: "local", Table: float64(102)},
	}
	if hasDefaultRoute(routes) {
		t.Fatal("policy fail-closed routes were mistaken for WAN IPv6")
	}
	routes = append(routes, routeInfo{Dst: "default", Gateway: "192.0.2.1", Dev: "wan", Table: float64(254)})
	if !hasDefaultRoute(routes) {
		t.Fatal("main unicast default route was not detected")
	}
}

func TestOpenWrtInterfaceClassificationUsesRoutesAndAddresses(t *testing.T) {
	for _, test := range []struct {
		name    string
		address string
		mask    int
	}{
		{"common-192-168-0", "192.168.0.93", 24},
		{"common-192-168-1", "192.168.1.1", 24},
		{"common-192-168-8", "192.168.8.1", 24},
		{"unusual-private", "10.77.42.1", 23},
	} {
		t.Run(test.name, func(t *testing.T) {
			interfaces := []interfaceInfo{
				{Name: "inside_custom", Up: true, Device: "home-device", IPv4Address: []interfaceAddress{{Address: test.address, Mask: test.mask}}},
				{Name: "internet_primary", Up: true, Device: "uplink-a", IPv4Address: []interfaceAddress{{Address: "198.51.100.44", Mask: 24}}},
			}
			routes := []routeInfo{{Dst: "default", Gateway: "198.51.100.1", Dev: "uplink-a", Table: "main"}}
			lans, wans, _ := classifyOpenWrtInterfaces(interfaces, routes, nil)
			if len(lans) != 1 || lans[0].Name != "inside_custom" || len(wans) != 1 || wans[0].Name != "internet_primary" {
				t.Fatalf("classification depends on conventional names: lans=%+v wans=%+v", lans, wans)
			}
		})
	}
}

func TestOpenWrtInterfaceClassificationSupportsMultipleLANAndWAN(t *testing.T) {
	interfaces := []interfaceInfo{
		{Name: "house", Up: true, L3Device: "house0", IPv4Address: []interfaceAddress{{Address: "10.20.30.1", Mask: 24}}},
		{Name: "lab", Up: true, L3Device: "lab0", IPv4Address: []interfaceAddress{{Address: "172.20.5.1", Mask: 24}}},
		{Name: "fiber", Up: true, L3Device: "fiber0", IPv4Address: []interfaceAddress{{Address: "198.51.100.44", Mask: 24}}},
		{Name: "cellular", Up: true, L3Device: "wwan0", IPv4Address: []interfaceAddress{{Address: "203.0.113.44", Mask: 24}}},
	}
	routes := []routeInfo{
		{Dst: "default", Gateway: "198.51.100.1", Dev: "fiber0", Table: "main"},
		{Dst: "default", Gateway: "203.0.113.1", Dev: "wwan0", Table: "main"},
	}
	lans, wans, _ := classifyOpenWrtInterfaces(interfaces, routes, nil)
	if len(lans) != 2 || len(wans) != 2 {
		t.Fatalf("multiple interfaces were lost: lans=%+v wans=%+v", lans, wans)
	}
}

func TestOpenWrtIPv6OnAnotherWANFailsClosed(t *testing.T) {
	runner := newOpenWrtFixtureRunner()
	runner.outputs[fakeCommandKey(commandInterfaceDump, "")] = []byte(`{"interface":[{"interface":"home","up":true,"device":"home0","ipv4-address":[{"address":"192.0.2.1","mask":24}]},{"interface":"uplink4","up":true,"device":"uplink0","dns-server":["203.0.113.53"]},{"interface":"uplink6","up":true,"device":"uplink6"}]}`)
	runner.outputs[fakeCommandKey(commandLinkList, "")] = []byte(`[{"ifname":"home0","operstate":"UP"},{"ifname":"uplink0","operstate":"UP"},{"ifname":"uplink6","operstate":"UP"}]`)
	for _, name := range []string{"home0", "uplink0", "uplink6"} {
		runner.outputs[fakeCommandKey(commandDeviceStatus, name)] = []byte(`{"up":true,"carrier":true}`)
	}
	runner.outputs[fakeCommandKey(commandRoutes6, "")] = []byte(`[{"dst":"default","gateway":"2001:db8::1","dev":"uplink6","table":"main"}]`)
	provider := NewOpenWrtProvider(WithOpenWrtRunner(runner), WithOpenWrtCacheTTL(time.Hour))
	diagnostics := provider.NetworkDiagnostics(nil)
	if diagnostics.Status != "UNVERIFIED" || diagnostics.Reason != "ipv6_wan_interface_mismatch" {
		t.Fatalf("split IPv4/IPv6 WAN was not rejected by the single-WAN artifact contract: %+v", diagnostics)
	}
}
