package platform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"router-policy/internal/config"
)

const maxProviderOutputBytes = 2 << 20

const networkDiagnosticsTTL = 2 * time.Minute

type OpenWrtCommand string

const (
	commandSystemBoard      OpenWrtCommand = "system-board"
	commandSystemInfo       OpenWrtCommand = "system-info"
	commandInterfaceStatus  OpenWrtCommand = "interface-status"
	commandLinkList         OpenWrtCommand = "link-list"
	commandDeviceStatus     OpenWrtCommand = "device-status"
	commandRoutes4          OpenWrtCommand = "routes-v4"
	commandRoutes6          OpenWrtCommand = "routes-v6"
	commandRules4           OpenWrtCommand = "rules-v4"
	commandRules6           OpenWrtCommand = "rules-v6"
	commandWirelessStatus   OpenWrtCommand = "wireless-status"
	commandNeighbors        OpenWrtCommand = "neighbors"
	commandDHCPLeases       OpenWrtCommand = "dhcp-leases"
	commandODHCPDHosts      OpenWrtCommand = "odhcpd-hosts"
	commandFlowSoftware     OpenWrtCommand = "flow-software"
	commandFlowHardware     OpenWrtCommand = "flow-hardware"
	commandProcess          OpenWrtCommand = "process"
	commandComponentPresent OpenWrtCommand = "component-present"
	commandThermal          OpenWrtCommand = "thermal"
	commandProcModules      OpenWrtCommand = "proc-modules"
	commandFirewallCheck    OpenWrtCommand = "firewall-check"
	commandNFTTables        OpenWrtCommand = "nft-tables"
)

var interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,32}$`)

type OpenWrtRunner interface {
	Run(context.Context, OpenWrtCommand, string) ([]byte, error)
}

type ExecOpenWrtRunner struct{}

func (ExecOpenWrtRunner) Run(ctx context.Context, command OpenWrtCommand, parameter string) ([]byte, error) {
	path, args, err := fixedOpenWrtCommand(command, parameter)
	if err != nil {
		return nil, err
	}
	if command == commandComponentPresent {
		return componentPresent(parameter)
	}

	cmd := exec.CommandContext(ctx, path, args...)
	var output cappedBuffer
	output.max = maxProviderOutputBytes
	cmd.Stdout = &output
	cmd.Stderr = &output
	err = cmd.Run()
	if output.exceeded {
		return nil, fmt.Errorf("command output exceeded limit")
	}
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(output.Bytes()), nil
}

type cappedBuffer struct {
	bytes.Buffer
	max      int
	exceeded bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	remaining := b.max - b.Len()
	if remaining <= 0 {
		b.exceeded = true
		return original, nil
	}
	if len(p) > remaining {
		b.exceeded = true
		p = p[:remaining]
	}
	_, _ = b.Buffer.Write(p)
	return original, nil
}

func fixedOpenWrtCommand(command OpenWrtCommand, parameter string) (string, []string, error) {
	switch command {
	case commandSystemBoard:
		return "/bin/ubus", []string{"call", "system", "board"}, nil
	case commandSystemInfo:
		return "/bin/ubus", []string{"call", "system", "info"}, nil
	case commandInterfaceStatus:
		if parameter != "lan" && parameter != "wan" && parameter != "wan6" {
			return "", nil, fmt.Errorf("interface status parameter is not allowed")
		}
		return "/bin/ubus", []string{"call", "network.interface." + parameter, "status"}, nil
	case commandLinkList:
		return "/sbin/ip", []string{"-s", "-j", "-details", "link", "show"}, nil
	case commandDeviceStatus:
		if !interfaceNamePattern.MatchString(parameter) {
			return "", nil, fmt.Errorf("device name is not allowed")
		}
		message, _ := json.Marshal(map[string]string{"name": parameter})
		return "/bin/ubus", []string{"call", "network.device", "status", string(message)}, nil
	case commandRoutes4:
		return "/sbin/ip", []string{"-j", "route", "show", "table", "all"}, nil
	case commandRoutes6:
		return "/sbin/ip", []string{"-j", "-6", "route", "show", "table", "all"}, nil
	case commandRules4:
		return "/sbin/ip", []string{"-j", "rule", "show"}, nil
	case commandRules6:
		return "/sbin/ip", []string{"-j", "-6", "rule", "show"}, nil
	case commandWirelessStatus:
		return "/bin/ubus", []string{"call", "network.wireless", "status"}, nil
	case commandNeighbors:
		return "/sbin/ip", []string{"-j", "neigh", "show"}, nil
	case commandDHCPLeases:
		return "/bin/cat", []string{"/tmp/dhcp.leases"}, nil
	case commandODHCPDHosts:
		return "/bin/cat", []string{"/tmp/hosts/odhcpd"}, nil
	case commandFlowSoftware:
		return "/sbin/uci", []string{"-q", "get", "firewall.@defaults[0].flow_offloading"}, nil
	case commandFlowHardware:
		return "/sbin/uci", []string{"-q", "get", "firewall.@defaults[0].flow_offloading_hw"}, nil
	case commandProcess:
		processes := map[string]string{
			"dnsmasq": "dnsmasq", "uhttpd": "uhttpd", "xray": "xray",
			"zapret": "nfqws", "router-policy": "router-policy",
		}
		name, ok := processes[parameter]
		if !ok {
			return "", nil, fmt.Errorf("process is not allowed")
		}
		return "/bin/pidof", []string{name}, nil
	case commandComponentPresent:
		if _, ok := componentPaths()[parameter]; !ok {
			return "", nil, fmt.Errorf("component is not allowed")
		}
		return "internal-stat", nil, nil
	case commandThermal:
		return "/bin/cat", []string{"/sys/class/thermal/thermal_zone0/temp"}, nil
	case commandProcModules:
		return "/bin/cat", []string{"/proc/modules"}, nil
	case commandFirewallCheck:
		return "/sbin/fw4", []string{"check"}, nil
	case commandNFTTables:
		return "/usr/sbin/nft", []string{"list", "tables"}, nil
	default:
		return "", nil, fmt.Errorf("read command is not allowed")
	}
}

func componentPaths() map[string][]string {
	return map[string][]string{
		"dnsmasq":       {"/usr/sbin/dnsmasq"},
		"uhttpd":        {"/usr/sbin/uhttpd"},
		"xray":          {"/usr/bin/xray"},
		"zapret":        {"/usr/bin/nfqws", "/opt/zapret/nfqws", "/etc/init.d/zapret"},
		"router-policy": {"/usr/bin/router-policy"},
	}
}

func componentPresent(name string) ([]byte, error) {
	paths, ok := componentPaths()[name]
	if !ok {
		return nil, fmt.Errorf("component is not allowed")
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			return []byte("present"), nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return nil, os.ErrNotExist
}

type OpenWrtProviderOption func(*openWrtRuntime)

func WithOpenWrtRunner(runner OpenWrtRunner) OpenWrtProviderOption {
	return func(runtime *openWrtRuntime) { runtime.runner = runner }
}

func WithOpenWrtCacheTTL(ttl time.Duration) OpenWrtProviderOption {
	return func(runtime *openWrtRuntime) { runtime.cacheTTL = ttl }
}

func NewOpenWrtProvider(options ...OpenWrtProviderOption) OpenWrtProvider {
	runtime := defaultOpenWrtRuntime()
	for _, option := range options {
		option(runtime)
	}
	if runtime.runner == nil {
		runtime.runner = ExecOpenWrtRunner{}
	}
	return OpenWrtProvider{runtime: runtime}
}

type OpenWrtProvider struct {
	runtime *openWrtRuntime
}

type openWrtRuntime struct {
	mu       sync.Mutex
	runner   OpenWrtRunner
	now      func() time.Time
	timeout  time.Duration
	cacheTTL time.Duration
	cached   *openWrtSnapshot
}

func defaultOpenWrtRuntime() *openWrtRuntime {
	return &openWrtRuntime{
		runner:   ExecOpenWrtRunner{},
		now:      func() time.Time { return time.Now().UTC() },
		timeout:  3 * time.Second,
		cacheTTL: 3 * time.Second,
	}
}

func (p OpenWrtProvider) Name() string     { return "openwrt-provider" }
func (p OpenWrtProvider) Simulation() bool { return false }

func (p OpenWrtProvider) NetworkDiagnostics(_ *config.Config) NetworkDiagnostics {
	snapshot := p.snapshot()
	report := NetworkDiagnostics{
		Status:               "UNVERIFIED",
		Source:               p.Name() + "/network-v1",
		Simulation:           false,
		FlowOffloadingStatus: "UNVERIFIED",
		CollectedAt:          snapshot.CollectedAt,
		ExpiresAt:            snapshot.CollectedAt.Add(networkDiagnosticsTTL),
	}
	fail := func(reason string) NetworkDiagnostics {
		report.Reason = reason
		return report
	}
	if snapshot.Status != "OK" {
		return fail("provider_snapshot_" + strings.ToLower(snapshot.Status))
	}
	for _, required := range []string{"lan_status", "wan_status", "links", "routes_v4", "routes_v6", "flow_software", "flow_hardware"} {
		if _, failed := snapshot.Errors[required]; failed {
			return fail(required + "_unverified")
		}
	}

	report.LANInterfaces = uniqueInterfaces(snapshot.LAN.L3Device, snapshot.LAN.Device)
	if !snapshot.LAN.Up || len(report.LANInterfaces) == 0 || !linkPresent(snapshot.Links, report.LANInterfaces[0]) {
		return fail("lan_interface_unverified")
	}
	report.WANInterface = firstInterface(snapshot.WAN.L3Device, snapshot.WAN.Device)
	if !snapshot.WAN.Up || report.WANInterface == "" || !linkPresent(snapshot.Links, report.WANInterface) {
		return fail("wan_interface_unverified")
	}

	gateway4, device4, ok := mainDefaultGateway(snapshot.Routes4, 4)
	if !ok || device4 != report.WANInterface {
		return fail("ipv4_gateway_unverified")
	}
	report.IPv4Gateway = gateway4

	software, softwareOK := binaryFlag(snapshot.FlowSW)
	hardware, hardwareOK := binaryFlag(snapshot.FlowHW)
	if !softwareOK || !hardwareOK {
		return fail("flow_offloading_unverified")
	}
	report.FlowOffloadingStatus = "VERIFIED"
	report.SoftwareFlowOffload = software
	report.HardwareFlowOffload = hardware

	resolverSet := map[string]struct{}{}
	for _, resolver := range append(append([]string(nil), snapshot.WAN.DNSServer...), snapshot.WAN6.DNSServer...) {
		if ip := net.ParseIP(strings.TrimSpace(resolver)); ip != nil {
			resolverSet[ip.String()] = struct{}{}
		}
	}
	for resolver := range resolverSet {
		report.DNSResolvers = append(report.DNSResolvers, resolver)
	}
	sort.Strings(report.DNSResolvers)
	if len(report.DNSResolvers) == 0 {
		return fail("dns_resolver_unverified")
	}

	if gateway6, device6, available := mainDefaultGateway(snapshot.Routes6, 6); available {
		wan6Interface := firstInterface(snapshot.WAN6.L3Device, snapshot.WAN6.Device, report.WANInterface)
		if device6 != wan6Interface || device6 != report.WANInterface {
			return fail("ipv6_wan_interface_mismatch")
		}
		report.IPv6Available = true
		report.IPv6Gateway = gateway6
	}
	if snapshot.TPROXY && snapshot.NFTSocket && snapshot.FirewallOK {
		report.TransparentProxyMode = "tproxy"
	}
	report.Status = "VERIFIED"
	report.Reason = ""
	return report
}

type boardInfo struct {
	Kernel     string `json:"kernel"`
	Hostname   string `json:"hostname"`
	System     string `json:"system"`
	Model      string `json:"model"`
	BoardName  string `json:"board_name"`
	RootFSType string `json:"rootfs_type"`
	Release    struct {
		Distribution string `json:"distribution"`
		Version      string `json:"version"`
		Revision     string `json:"revision"`
		Target       string `json:"target"`
		Description  string `json:"description"`
	} `json:"release"`
}

type systemInfo struct {
	Uptime int64   `json:"uptime"`
	Load   []int64 `json:"load"`
	Memory struct {
		Total     uint64 `json:"total"`
		Free      uint64 `json:"free"`
		Available uint64 `json:"available"`
		Cached    uint64 `json:"cached"`
		Buffered  uint64 `json:"buffered"`
	} `json:"memory"`
	Root struct {
		Total uint64 `json:"total"`
		Free  uint64 `json:"free"`
		Used  uint64 `json:"used"`
	} `json:"root"`
	Tmp struct {
		Total uint64 `json:"total"`
		Free  uint64 `json:"free"`
		Used  uint64 `json:"used"`
	} `json:"tmp"`
}

type interfaceAddress struct {
	Address string `json:"address"`
	Mask    int    `json:"mask"`
}

type interfaceInfo struct {
	Up          bool               `json:"up"`
	Pending     bool               `json:"pending"`
	Available   bool               `json:"available"`
	Uptime      int64              `json:"uptime"`
	L3Device    string             `json:"l3_device"`
	Proto       string             `json:"proto"`
	Device      string             `json:"device"`
	IPv4Address []interfaceAddress `json:"ipv4-address"`
	IPv6Address []interfaceAddress `json:"ipv6-address"`
	DNSServer   []string           `json:"dns-server"`
}

type linkInfo struct {
	IfName    string   `json:"ifname"`
	OperState string   `json:"operstate"`
	Address   string   `json:"address"`
	Master    string   `json:"master"`
	Flags     []string `json:"flags"`
	Stats64   struct {
		RX struct {
			Bytes   uint64 `json:"bytes"`
			Packets uint64 `json:"packets"`
		} `json:"rx"`
		TX struct {
			Bytes   uint64 `json:"bytes"`
			Packets uint64 `json:"packets"`
		} `json:"tx"`
	} `json:"stats64"`
}

type deviceInfo struct {
	Up         bool   `json:"up"`
	Carrier    bool   `json:"carrier"`
	Speed      int64  `json:"speed"`
	Duplex     string `json:"duplex"`
	Statistics struct {
		RXBytes uint64 `json:"rx_bytes"`
		TXBytes uint64 `json:"tx_bytes"`
	} `json:"statistics"`
}

type routeInfo struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
	Table   any    `json:"table"`
}

type ruleInfo struct {
	Priority int    `json:"priority"`
	Table    string `json:"table"`
	FwMark   string `json:"fwmark"`
}

type neighborInfo struct {
	Dst    string        `json:"dst"`
	Dev    string        `json:"dev"`
	LLAddr string        `json:"lladdr"`
	State  neighborState `json:"state"`
}

type neighborState string

func (s *neighborState) UnmarshalJSON(raw []byte) error {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if !validNeighborState(single) {
			return fmt.Errorf("invalid neighbor state")
		}
		*s = neighborState(single)
		return nil
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil || len(values) == 0 || len(values) > 8 {
		return fmt.Errorf("invalid neighbor state")
	}
	for _, value := range values {
		if !validNeighborState(value) {
			return fmt.Errorf("invalid neighbor state")
		}
	}
	*s = neighborState(strings.Join(values, ","))
	return nil
}

func validNeighborState(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for _, char := range value {
		if (char < 'A' || char > 'Z') && char != '_' {
			return false
		}
	}
	return true
}

func neighborIsConnected(state neighborState) bool {
	if state == "" {
		return false
	}
	for _, value := range strings.Split(string(state), ",") {
		if value == "FAILED" || value == "INCOMPLETE" {
			return false
		}
	}
	return true
}

type wirelessRadio struct {
	Up         bool `json:"up"`
	Interfaces []struct {
		Section string `json:"section"`
		IfName  string `json:"ifname"`
		Config  struct {
			Mode       string `json:"mode"`
			SSID       string `json:"ssid"`
			Network    any    `json:"network"`
			Encryption string `json:"encryption"`
			Disabled   bool   `json:"disabled"`
			Isolate    bool   `json:"isolate"`
		} `json:"config"`
	} `json:"interfaces"`
}

type componentState struct {
	Status    string `json:"status"`
	Installed bool   `json:"installed"`
	Running   bool   `json:"running"`
	Reason    string `json:"reason,omitempty"`
}

type openWrtSnapshot struct {
	CollectedAt time.Time
	Board       boardInfo
	System      systemInfo
	LAN         interfaceInfo
	WAN         interfaceInfo
	WAN6        interfaceInfo
	Links       []linkInfo
	Devices     map[string]deviceInfo
	Routes4     []routeInfo
	Routes6     []routeInfo
	Rules4      []ruleInfo
	Rules6      []ruleInfo
	Neighbors   []neighborInfo
	Wireless    map[string]wirelessRadio
	DHCPLeases  []dhcpLease
	ODHCPHosts  []odhcpHost
	Components  map[string]componentState
	Errors      map[string]string
	Status      string
	Reason      string
	FlowSW      string
	FlowHW      string
	Temperature *float64
	TPROXY      bool
	NFTSocket   bool
	FirewallOK  bool
	NFTTables   int
}

func (p OpenWrtProvider) runtimeOrDefault() *openWrtRuntime {
	if p.runtime != nil {
		return p.runtime
	}
	return defaultOpenWrtRuntime()
}

func (p OpenWrtProvider) snapshot() *openWrtSnapshot {
	runtime := p.runtimeOrDefault()
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	now := runtime.now()
	if runtime.cached != nil && runtime.cacheTTL > 0 && now.Sub(runtime.cached.CollectedAt) < runtime.cacheTTL {
		return runtime.cached
	}
	runtime.cached = collectOpenWrtSnapshot(runtime, now)
	return runtime.cached
}

func collectOpenWrtSnapshot(runtime *openWrtRuntime, now time.Time) *openWrtSnapshot {
	snapshot := &openWrtSnapshot{
		CollectedAt: now,
		Devices:     map[string]deviceInfo{},
		Wireless:    map[string]wirelessRadio{},
		Components:  map[string]componentState{},
		Errors:      map[string]string{},
	}

	run := func(name string, command OpenWrtCommand, parameter string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), runtime.timeout)
		defer cancel()
		output, err := runtime.runner.Run(ctx, command, parameter)
		if err != nil {
			snapshot.Errors[name] = safeProviderError(err)
		}
		return output, err
	}
	decode := func(name string, command OpenWrtCommand, parameter string, target any) {
		output, err := run(name, command, parameter)
		if err != nil {
			return
		}
		if len(output) == 0 || len(output) > maxProviderOutputBytes || json.Unmarshal(output, target) != nil {
			snapshot.Errors[name] = "malformed_output"
		}
	}

	decode("system_board", commandSystemBoard, "", &snapshot.Board)
	decode("system_info", commandSystemInfo, "", &snapshot.System)
	decode("lan_status", commandInterfaceStatus, "lan", &snapshot.LAN)
	decode("wan_status", commandInterfaceStatus, "wan", &snapshot.WAN)
	decode("wan6_status", commandInterfaceStatus, "wan6", &snapshot.WAN6)
	decode("links", commandLinkList, "", &snapshot.Links)
	decode("routes_v4", commandRoutes4, "", &snapshot.Routes4)
	decode("routes_v6", commandRoutes6, "", &snapshot.Routes6)
	decode("rules_v4", commandRules4, "", &snapshot.Rules4)
	decode("rules_v6", commandRules6, "", &snapshot.Rules6)
	decode("neighbors", commandNeighbors, "", &snapshot.Neighbors)
	decode("wireless", commandWirelessStatus, "", &snapshot.Wireless)

	if len(snapshot.Links) > 256 {
		snapshot.Links = nil
		snapshot.Errors["links"] = "too_many_records"
	}
	if len(snapshot.Routes4) > 4096 || len(snapshot.Routes6) > 4096 || len(snapshot.Neighbors) > 4096 {
		snapshot.Routes4 = nil
		snapshot.Routes6 = nil
		snapshot.Neighbors = nil
		snapshot.Errors["network_records"] = "too_many_records"
	}

	deviceNames := make([]string, 0, len(snapshot.Links))
	for _, link := range snapshot.Links {
		if interfaceNamePattern.MatchString(link.IfName) {
			deviceNames = append(deviceNames, link.IfName)
		}
	}
	sort.Strings(deviceNames)
	if len(deviceNames) > 32 {
		deviceNames = deviceNames[:32]
	}
	for _, name := range deviceNames {
		var detail deviceInfo
		decode("device_"+name, commandDeviceStatus, name, &detail)
		if _, failed := snapshot.Errors["device_"+name]; !failed {
			snapshot.Devices[name] = detail
		}
	}

	if output, err := run("dhcp_leases", commandDHCPLeases, ""); err == nil {
		leases, parseErr := parseDHCPLeases(output)
		if parseErr != nil {
			snapshot.Errors["dhcp_leases"] = "malformed_output"
		} else {
			snapshot.DHCPLeases = leases
		}
	}
	if output, err := run("odhcpd_hosts", commandODHCPDHosts, ""); err == nil {
		hosts, parseErr := parseODHCPHosts(output)
		if parseErr != nil {
			snapshot.Errors["odhcpd_hosts"] = "malformed_output"
		} else {
			snapshot.ODHCPHosts = hosts
		}
	}

	for _, component := range []string{"dnsmasq", "uhttpd", "xray", "zapret", "router-policy"} {
		_, presentErr := runComponent(runtime, commandComponentPresent, component)
		_, runningErr := runComponent(runtime, commandProcess, component)
		state := componentState{Installed: presentErr == nil, Running: runningErr == nil}
		switch {
		case !state.Installed:
			state.Status = "NOT_CONFIGURED"
			state.Reason = "executable_not_found"
		case state.Running:
			state.Status = "RUNNING"
		default:
			state.Status = "STOPPED"
			state.Reason = "process_not_running"
		}
		snapshot.Components[component] = state
	}

	if output, err := run("flow_software", commandFlowSoftware, ""); err == nil {
		snapshot.FlowSW = strings.TrimSpace(string(output))
	}
	if output, err := run("flow_hardware", commandFlowHardware, ""); err == nil {
		snapshot.FlowHW = strings.TrimSpace(string(output))
	}
	if output, err := run("thermal", commandThermal, ""); err == nil {
		if milli, parseErr := strconv.ParseFloat(strings.TrimSpace(string(output)), 64); parseErr == nil && milli >= -100000 && milli <= 250000 {
			value := milli / 1000
			snapshot.Temperature = &value
		} else {
			snapshot.Errors["thermal"] = "malformed_output"
		}
	}
	if output, err := run("kernel_modules", commandProcModules, ""); err == nil {
		modules := string(output)
		snapshot.TPROXY = strings.Contains(modules, "nft_tproxy ") || strings.Contains(modules, "xt_TPROXY ")
		snapshot.NFTSocket = strings.Contains(modules, "nft_socket ")
	}
	if _, err := run("firewall_check", commandFirewallCheck, ""); err == nil {
		snapshot.FirewallOK = true
	}
	if output, err := run("nft_tables", commandNFTTables, ""); err == nil {
		for _, line := range strings.Split(string(output), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "table ") {
				snapshot.NFTTables++
			}
		}
	}

	critical := []string{"system_board", "system_info", "lan_status", "wan_status", "links", "routes_v4"}
	for _, name := range critical {
		if reason, failed := snapshot.Errors[name]; failed {
			snapshot.Status = "UNVERIFIED"
			snapshot.Reason = name + ":" + reason
			if name == "system_board" || name == "system_info" {
				snapshot.Status = "ERROR"
			}
			return snapshot
		}
	}
	snapshot.Status = "OK"
	return snapshot
}

func runComponent(runtime *openWrtRuntime, command OpenWrtCommand, component string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), runtime.timeout)
	defer cancel()
	return runtime.runner.Run(ctx, command, component)
}

func safeProviderError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	if errors.Is(err, os.ErrNotExist) {
		return "not_found"
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return fmt.Sprintf("exit_%d", exitErr.ExitCode())
	}
	return "unavailable"
}

func (p OpenWrtProvider) Overview(cfg *config.Config) map[string]any {
	snapshot := p.snapshot()
	internet := "OFFLINE"
	if _, failed := snapshot.Errors["wan_status"]; failed {
		internet = "UNVERIFIED"
	} else if snapshot.WAN.Up && hasDefaultRoute(snapshot.Routes4) {
		internet = "ROUTE_AVAILABLE"
	}
	dns := "UNVERIFIED"
	if state := snapshot.Components["dnsmasq"]; state.Running {
		if len(snapshot.WAN.DNSServer) > 0 {
			dns = "AVAILABLE"
		} else {
			dns = "NO_UPSTREAM"
		}
	}
	ipv6 := "NOT_CONFIGURED"
	if len(snapshot.WAN.IPv6Address) > 0 || hasDefaultRoute(snapshot.Routes6) {
		ipv6 = "CONFIGURED"
	}

	return map[string]any{
		"internet":             internet,
		"external_ipv4_hash":   firstAddressHash(snapshot.WAN.IPv4Address),
		"ipv6":                 ipv6,
		"wan_speed_mbps":       linkSpeed(snapshot, snapshot.WAN.Device),
		"dns":                  dns,
		"zapret":               snapshot.Components["zapret"],
		"xray":                 snapshot.Components["xray"],
		"vless_configured":     countRoutes(cfg, "vless"),
		"smart_dns_configured": countRoutes(cfg, "smart_dns"),
		"telegram_configured":  countRoutes(cfg, "tg_ws_proxy"),
		"cpu_load_1m":          loadOne(snapshot.System.Load),
		"memory_used_percent":  memoryUsedPercent(snapshot.System),
		"temperature_c":        snapshot.Temperature,
		"uptime_seconds":       snapshot.System.Uptime,
		"data_plane":           "UNVERIFIED",
		"source":               p.Name(),
		"status":               snapshot.Status,
		"reason":               nilIfEmpty(snapshot.Reason),
		"simulation":           false,
		"freshness":            "live",
		"collected_at":         snapshot.CollectedAt,
		"last_confirmed":       nil,
	}
}

func (p OpenWrtProvider) System(cfg *config.Config) map[string]any {
	snapshot := p.snapshot()
	target := "unknown"
	if cfg != nil {
		target = cfg.Platform.Target
	}
	return map[string]any{
		"version":             "dev",
		"platform":            target,
		"model":               snapshot.Board.Model,
		"board_name":          snapshot.Board.BoardName,
		"kernel":              snapshot.Board.Kernel,
		"firmware":            snapshot.Board.Release.Description,
		"firmware_version":    snapshot.Board.Release.Version,
		"target":              snapshot.Board.Release.Target,
		"rootfs_type":         snapshot.Board.RootFSType,
		"uptime_seconds":      snapshot.System.Uptime,
		"cpu_load_1m":         loadOne(snapshot.System.Load),
		"memory_total_bytes":  snapshot.System.Memory.Total,
		"memory_free_bytes":   snapshot.System.Memory.Available,
		"memory_used_percent": memoryUsedPercent(snapshot.System),
		"temperature_c":       snapshot.Temperature,
		"root_total_bytes":    snapshot.System.Root.Total,
		"root_free_bytes":     snapshot.System.Root.Free,
		"tmp_total_bytes":     snapshot.System.Tmp.Total,
		"tmp_free_bytes":      snapshot.System.Tmp.Free,
		"components":          snapshot.Components,
		"source":              p.Name(),
		"status":              snapshot.Status,
		"reason":              nilIfEmpty(snapshot.Reason),
		"simulation":          false,
		"freshness":           "live",
		"collected_at":        snapshot.CollectedAt,
	}
}

func (p OpenWrtProvider) Diagnostics(*config.Config) map[string]any {
	snapshot := p.snapshot()
	checks := make([]map[string]any, 0, len(snapshot.Errors)+6)
	for _, name := range []string{"system_board", "system_info", "lan_status", "wan_status", "links", "routes_v4", "routes_v6", "rules_v4", "rules_v6", "wireless", "neighbors", "dhcp_leases", "firewall_check", "nft_tables"} {
		status := "PASS"
		reason := ""
		if value, failed := snapshot.Errors[name]; failed {
			status = "UNVERIFIED"
			reason = value
		}
		checks = append(checks, map[string]any{"name": name, "status": status, "reason": nilIfEmpty(reason)})
	}
	missing := make([]string, 0, len(snapshot.Errors))
	for name := range snapshot.Errors {
		missing = append(missing, name)
	}
	sort.Strings(missing)
	return map[string]any{
		"platform": "openwrt",
		"checks":   checks,
		"missing":  missing,
		"capabilities": map[string]any{
			"tproxy":              snapshot.TPROXY,
			"nft_socket":          snapshot.NFTSocket,
			"firewall_check":      snapshot.FirewallOK,
			"nft_table_count":     snapshot.NFTTables,
			"ipv4_route_count":    len(snapshot.Routes4),
			"ipv6_route_count":    len(snapshot.Routes6),
			"ipv4_rule_count":     len(snapshot.Rules4),
			"ipv6_rule_count":     len(snapshot.Rules6),
			"flow_offloading":     triState(snapshot.FlowSW),
			"flow_offloading_hw":  triState(snapshot.FlowHW),
			"management_lan_up":   snapshot.LAN.Up,
			"wan_route_available": snapshot.WAN.Up && hasDefaultRoute(snapshot.Routes4),
			"data_plane_verified": false,
			"management_verified": false,
		},
		"components":   snapshot.Components,
		"source":       p.Name(),
		"status":       snapshot.Status,
		"reason":       nilIfEmpty(snapshot.Reason),
		"simulation":   false,
		"freshness":    "live",
		"collected_at": snapshot.CollectedAt,
	}
}

func (p OpenWrtProvider) Devices(*config.Config) []map[string]any {
	return buildDeviceItems(p.snapshot(), p.Name())
}

func (p OpenWrtProvider) Policies(cfg *config.Config) []map[string]any {
	if cfg == nil {
		return []map[string]any{}
	}
	names := make([]string, 0, len(cfg.Services))
	for name := range cfg.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]map[string]any, 0, len(names))
	for _, name := range names {
		service := cfg.Services[name]
		result = append(result, map[string]any{
			"id":                    "service:" + name,
			"name":                  name,
			"category":              service.Category,
			"allowed_paths":         service.AllowedPaths,
			"forbidden_paths":       service.ForbiddenPaths,
			"require_non_ru_egress": service.RequireNonRUEgress,
			"domains":               len(service.Domains),
			"source":                "active-config",
			"status":                "CONFIGURED",
			"simulation":            false,
		})
	}
	return result
}

func (p OpenWrtProvider) Topology(*config.Config) map[string]any {
	snapshot := p.snapshot()
	nodes := []map[string]any{
		{"id": "internet", "label": "Internet", "type": "internet", "status": internetStatus(snapshot)},
		{"id": "router", "label": nonEmpty(snapshot.Board.Model, "OpenWrt router"), "type": "router", "status": snapshot.Status},
	}
	edges := []map[string]any{{"from": "internet", "to": "router", "status": internetStatus(snapshot)}}
	linkIDs := map[string]string{}
	for _, link := range snapshot.Links {
		if !topologyInterface(link.IfName, snapshot.WAN.Device) {
			continue
		}
		id := "interface-" + stableID(link.IfName)
		linkIDs[link.IfName] = id
		detail := snapshot.Devices[link.IfName]
		nodes = append(nodes, map[string]any{
			"id": id, "label": link.IfName, "type": interfaceKind(link.IfName, snapshot.WAN.Device),
			"status": strings.ToUpper(nonEmpty(link.OperState, "UNKNOWN")), "carrier": detail.Carrier,
			"speed_mbps": detail.Speed, "rx_bytes": maxUint64(link.Stats64.RX.Bytes, detail.Statistics.RXBytes),
			"tx_bytes": maxUint64(link.Stats64.TX.Bytes, detail.Statistics.TXBytes),
		})
		if link.IfName != snapshot.WAN.Device {
			edges = append(edges, map[string]any{"from": "router", "to": id, "status": strings.ToUpper(nonEmpty(link.OperState, "UNKNOWN"))})
		}
	}
	for _, device := range buildDeviceItems(snapshot, p.Name()) {
		id, _ := device["id"].(string)
		nodes = append(nodes, map[string]any{
			"id": id, "label": device["name"], "type": "device", "status": device["status"],
			"ip": device["ip"], "kind": device["kind"], "policy": device["policy"],
		})
		parent := "router"
		if interfaceName, ok := device["interface"].(string); ok && linkIDs[interfaceName] != "" {
			parent = linkIDs[interfaceName]
		}
		edges = append(edges, map[string]any{"from": parent, "to": id, "status": device["status"]})
	}
	return map[string]any{
		"nodes": nodes, "edges": edges, "source": p.Name(), "status": snapshot.Status,
		"reason": nilIfEmpty(snapshot.Reason), "simulation": false, "freshness": "live", "collected_at": snapshot.CollectedAt,
	}
}

type dhcpLease struct {
	ExpiresAt time.Time
	MAC       string
	IP        string
	Hostname  string
}

type odhcpHost struct {
	IP       string
	Hostname string
}

func parseDHCPLeases(output []byte) ([]dhcpLease, error) {
	if len(output) > 1<<20 {
		return nil, fmt.Errorf("lease file too large")
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 1 && strings.TrimSpace(lines[0]) == "" {
		return []dhcpLease{}, nil
	}
	if len(lines) > 4096 {
		return nil, fmt.Errorf("too many leases")
	}
	leases := make([]dhcpLease, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return nil, fmt.Errorf("malformed lease")
		}
		expires, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil || net.ParseIP(fields[2]) == nil {
			return nil, fmt.Errorf("malformed lease")
		}
		if _, err := net.ParseMAC(fields[1]); err != nil {
			return nil, fmt.Errorf("malformed lease")
		}
		hostname := sanitizeLabel(fields[3])
		if hostname == "*" {
			hostname = ""
		}
		leases = append(leases, dhcpLease{ExpiresAt: time.Unix(expires, 0).UTC(), MAC: strings.ToLower(fields[1]), IP: fields[2], Hostname: hostname})
	}
	return leases, nil
}

func parseODHCPHosts(output []byte) ([]odhcpHost, error) {
	if len(output) > 1<<20 {
		return nil, fmt.Errorf("odhcpd hosts file too large")
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 1 && strings.TrimSpace(lines[0]) == "" {
		return []odhcpHost{}, nil
	}
	if len(lines) > 4096 {
		return nil, fmt.Errorf("too many odhcpd hosts")
	}
	hosts := make([]odhcpHost, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if net.ParseIP(fields[0]) == nil {
			continue
		}
		hosts = append(hosts, odhcpHost{IP: fields[0], Hostname: sanitizeLabel(fields[1])})
	}
	return hosts, nil
}

func buildDeviceItems(snapshot *openWrtSnapshot, source string) []map[string]any {
	neighborsByIP := make(map[string]neighborInfo, len(snapshot.Neighbors))
	for _, neighbor := range snapshot.Neighbors {
		neighborsByIP[neighbor.Dst] = neighbor
	}
	items := make([]map[string]any, 0, len(snapshot.DHCPLeases)+len(snapshot.ODHCPHosts))
	seen := map[string]bool{}
	for _, lease := range snapshot.DHCPLeases {
		neighbor := neighborsByIP[lease.IP]
		name := nonEmpty(lease.Hostname, "Unknown device")
		connected := neighborIsConnected(neighbor.State)
		id := "device-" + stableID(lease.MAC)
		seen[lease.IP] = true
		items = append(items, map[string]any{
			"id": id, "name": name, "kind": deviceKind(neighbor.Dev), "ip": lease.IP,
			"mac": maskMAC(lease.MAC), "mac_hash": hashText(lease.MAC), "interface": neighbor.Dev,
			"connected": connected, "neighbor_state": neighbor.State, "lease_expires_at": lease.ExpiresAt,
			"policy": "UNVERIFIED", "active_route": "UNVERIFIED", "source": source + ":dhcp+neighbor",
			"status": "OK", "simulation": false, "freshness": "live", "collected_at": snapshot.CollectedAt,
		})
	}
	for _, host := range snapshot.ODHCPHosts {
		if seen[host.IP] {
			continue
		}
		neighbor := neighborsByIP[host.IP]
		items = append(items, map[string]any{
			"id": "device-" + stableID(host.IP), "name": nonEmpty(host.Hostname, "IPv6 device"),
			"kind": deviceKind(neighbor.Dev), "ip": host.IP, "mac": maskMAC(neighbor.LLAddr),
			"mac_hash": hashText(neighbor.LLAddr), "interface": neighbor.Dev,
			"connected":      neighborIsConnected(neighbor.State),
			"neighbor_state": neighbor.State, "policy": "UNVERIFIED", "active_route": "UNVERIFIED",
			"source": source + ":odhcpd+neighbor", "status": "OK", "simulation": false,
			"freshness": "live", "collected_at": snapshot.CollectedAt,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		return fmt.Sprint(items[i]["name"], items[i]["ip"]) < fmt.Sprint(items[j]["name"], items[j]["ip"])
	})
	return items
}

func sanitizeLabel(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 128 {
		value = value[:128]
	}
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, value)
}

func hasDefaultRoute(routes []routeInfo) bool {
	for _, route := range routes {
		if route.Dst == "default" || route.Dst == "0.0.0.0/0" || route.Dst == "::/0" {
			return true
		}
	}
	return false
}

func mainDefaultGateway(routes []routeInfo, family int) (string, string, bool) {
	for _, route := range routes {
		if !mainRouteTable(route.Table) || !interfaceNamePattern.MatchString(route.Dev) {
			continue
		}
		switch family {
		case 4:
			if route.Dst != "default" && route.Dst != "0.0.0.0/0" {
				continue
			}
			ip := net.ParseIP(route.Gateway)
			if ip != nil && ip.To4() != nil {
				return ip.String(), route.Dev, true
			}
		case 6:
			if route.Dst != "default" && route.Dst != "::/0" {
				continue
			}
			ip := net.ParseIP(route.Gateway)
			if ip != nil && ip.To4() == nil {
				return ip.String(), route.Dev, true
			}
		}
	}
	return "", "", false
}

func mainRouteTable(table any) bool {
	switch value := table.(type) {
	case nil:
		return true
	case string:
		return value == "" || value == "main" || value == "254"
	case float64:
		return value == 254
	case json.Number:
		return value.String() == "254"
	case int:
		return value == 254
	default:
		return false
	}
}

func firstInterface(names ...string) string {
	for _, name := range names {
		name = strings.TrimSpace(name)
		if interfaceNamePattern.MatchString(name) {
			return name
		}
	}
	return ""
}

func uniqueInterfaces(names ...string) []string {
	seen := map[string]struct{}{}
	interfaces := make([]string, 0, len(names))
	for _, name := range names {
		name = firstInterface(name)
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		interfaces = append(interfaces, name)
	}
	sort.Strings(interfaces)
	return interfaces
}

func linkPresent(links []linkInfo, name string) bool {
	for _, link := range links {
		if link.IfName == name {
			return true
		}
	}
	return false
}

func binaryFlag(value string) (bool, bool) {
	switch strings.TrimSpace(value) {
	case "0":
		return false, true
	case "1":
		return true, true
	default:
		return false, false
	}
}

func firstAddressHash(addresses []interfaceAddress) any {
	for _, address := range addresses {
		ip := net.ParseIP(address.Address)
		if ip != nil && !ip.IsUnspecified() {
			return hashText(ip.String())
		}
	}
	return nil
}

func hashText(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func stableID(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func maskMAC(value string) string {
	parts := strings.Split(strings.ToLower(value), ":")
	if len(parts) != 6 {
		return "unavailable"
	}
	return "**:**:**:**:" + parts[4] + ":" + parts[5]
}

func loadOne(load []int64) any {
	if len(load) == 0 {
		return nil
	}
	return float64(load[0]) / 65536
}

func memoryUsedPercent(system systemInfo) any {
	if system.Memory.Total == 0 || system.Memory.Available > system.Memory.Total {
		return nil
	}
	return float64(system.Memory.Total-system.Memory.Available) * 100 / float64(system.Memory.Total)
}

func linkSpeed(snapshot *openWrtSnapshot, device string) any {
	if detail, ok := snapshot.Devices[device]; ok && detail.Speed > 0 {
		return detail.Speed
	}
	return nil
}

func internetStatus(snapshot *openWrtSnapshot) string {
	if _, failed := snapshot.Errors["wan_status"]; failed {
		return "UNVERIFIED"
	}
	if snapshot.WAN.Up && hasDefaultRoute(snapshot.Routes4) {
		return "ROUTE_AVAILABLE"
	}
	return "OFFLINE"
}

func triState(value string) string {
	switch strings.TrimSpace(value) {
	case "1":
		return "ENABLED"
	case "0":
		return "DISABLED"
	default:
		return "UNVERIFIED"
	}
}

func nilIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func topologyInterface(name, wanDevice string) bool {
	if name == wanDevice || name == "br-lan" || strings.HasPrefix(name, "lan") || strings.HasPrefix(name, "wlan") || strings.HasPrefix(name, "br-guest") || strings.HasPrefix(name, "br-iot") {
		return true
	}
	return false
}

func interfaceKind(name, wanDevice string) string {
	if name == wanDevice {
		return "wan"
	}
	if strings.HasPrefix(name, "wlan") {
		return "wifi"
	}
	if strings.HasPrefix(name, "br-") {
		return "bridge"
	}
	return "ethernet"
}

func deviceKind(name string) string {
	if strings.HasPrefix(name, "wlan") {
		return "wifi"
	}
	if name == "" {
		return "unknown"
	}
	return "ethernet"
}

func maxUint64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
