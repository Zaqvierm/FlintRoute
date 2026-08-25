// Package manualimport turns an administrator-owned, manually maintained
// Xray/Zapret dataplane into a redacted migration report and an immutable Xray
// candidate. It deliberately has no adapter, procd, nft or network mutation
// path. Adoption is a separate, transactional operation after ownership has
// been proven.
package manualimport

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"

	"router-policy/internal/xraybundle"
)

const (
	maxXrayBytes   = 4 << 20
	maxEvidence    = 1 << 20
	maxZapretLines = 4096
)

var (
	tagPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	queueValue     = regexp.MustCompile(`^--qnum(?:=|\s+)([0-9]+)$`)
	optionValue    = regexp.MustCompile(`^--(filter-(?:tcp|udp)|dpi-desync)(?:=|\s+)(.+)$`)
	uuidPattern    = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[1-5][a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$`)
	nftSourceValue = regexp.MustCompile(`(?i)\b(?:ip|ip6)\s+saddr\s+([0-9a-f:.\/]+)`)
	nftQueueValue  = regexp.MustCompile(`(?i)\bqueue(?:\s+flags\s+[^\s]+)*\s+to\s+([0-9]+)\b`)
	nftPortValue   = regexp.MustCompile(`(?i)\b(tcp|udp)\s+dport\s+(\{[^}]+\}|[0-9]+(?:-[0-9]+)?)`)
)

// Options identifies manually maintained files. All paths are read-only
// inputs except OutputBundle, which is an explicitly requested local
// candidate artifact.
type Options struct {
	XrayPath     string
	ZapretArgs   []string
	DNSMasqPath  string
	NFTPaths     []string
	OutputBundle string
	GeneratedAt  time.Time
}

// Report is intentionally safe to print. It contains counts, hashes and
// endpoint metadata, never UUIDs, credentials, subscription URLs or raw JSON.
type Report struct {
	SchemaVersion  int            `json:"schema_version"`
	GeneratedAt    string         `json:"generated_at"`
	SecretsPrinted bool           `json:"secrets_printed"`
	MigrationState string         `json:"migration_state"`
	Files          []FileEvidence `json:"files"`
	Xray           XrayReport     `json:"xray"`
	Zapret         []ZapretReport `json:"zapret,omitempty"`
	Conflicts      []Conflict     `json:"conflicts"`
	NextSteps      []string       `json:"next_steps"`
}

type FileEvidence struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Role   string `json:"role"`
}

type XrayReport struct {
	SourceSHA256  string          `json:"source_sha256"`
	InboundCount  int             `json:"inbound_count"`
	SOCKSCount    int             `json:"socks_count"`
	VLESSCount    int             `json:"vless_count"`
	Transparent   int             `json:"transparent_inbounds"`
	DNSInbounds   int             `json:"dns_inbounds"`
	ListenerPorts []int           `json:"listener_ports"`
	Servers       []ServerSummary `json:"servers"`
	BundleSHA256  string          `json:"bundle_sha256,omitempty"`
	BundlePath    string          `json:"bundle_path,omitempty"`
	BundleReady   bool            `json:"bundle_ready"`
}

type ServerSummary struct {
	Tag        string `json:"tag"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	Transport  string `json:"transport"`
	Security   string `json:"security"`
	Flow       string `json:"flow,omitempty"`
	InboundTag string `json:"inbound_tag"`
	SOCKS5     string `json:"socks5"`
	Credential bool   `json:"credential_present"`
}

type ZapretReport struct {
	Path            string             `json:"path"`
	SHA256          string             `json:"sha256"`
	Queue           int                `json:"queue"`
	Filters         []string           `json:"filters,omitempty"`
	Desync          []string           `json:"desync,omitempty"`
	Ownership       string             `json:"ownership"`
	QueueSafe       bool               `json:"queue_safe"`
	TypedStrategy   string             `json:"typed_strategy,omitempty"`
	TypedModelReady bool               `json:"typed_model_ready"`
	ModelBlockers   []string           `json:"model_blockers,omitempty"`
	DeviceScoped    bool               `json:"device_scoped,omitempty"`
	DeviceScope     *ZapretDeviceScope `json:"device_scope,omitempty"`
}

// ZapretDeviceScope is a redacted, typed description of a host-scoped nft
// profile. ScopeFingerprint is an opaque per-report identifier used to join
// rules without exposing or hashing a low-entropy LAN IP/MAC in the report. It
// is evidence for a future profile handoff, not an apply instruction.
type ZapretDeviceScope struct {
	ScopeFingerprint string   `json:"scope_fingerprint"`
	Queue            int      `json:"queue"`
	TCPPorts         []string `json:"tcp_ports,omitempty"`
	UDPDropPorts     []string `json:"udp_drop_ports,omitempty"`
	SourceRuleCount  int      `json:"source_rule_count"`
	ScopeConflict    bool     `json:"scope_conflict,omitempty"`
}

type Conflict struct {
	Resource string `json:"resource"`
	Severity string `json:"severity"`
	Reason   string `json:"reason"`
	Action   string `json:"action"`
}

type rawConfig struct {
	Inbounds  []json.RawMessage `json:"inbounds"`
	Outbounds []json.RawMessage `json:"outbounds"`
	Routing   struct {
		Rules []json.RawMessage `json:"rules"`
	} `json:"routing"`
}

type inboundMeta struct {
	Tag      string `json:"tag"`
	Listen   string `json:"listen"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type userMeta struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
	Flow       string `json:"flow"`
}

type outboundMeta struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
	Settings struct {
		VNext []struct {
			Address string     `json:"address"`
			Port    int        `json:"port"`
			Users   []userMeta `json:"users"`
		} `json:"vnext"`
	} `json:"settings"`
	StreamSettings struct {
		Network  string `json:"network"`
		Security string `json:"security"`
	} `json:"streamSettings"`
}

type ruleMeta struct {
	Type        string   `json:"type"`
	InboundTags []string `json:"inboundTag"`
	OutboundTag string   `json:"outboundTag"`
}

// Inspect reads and validates the manual Xray config, plus optional evidence
// files, and returns a report. It never starts a process or invokes a shell.
func Inspect(opts Options) (Report, error) {
	generated := opts.GeneratedAt
	if generated.IsZero() {
		generated = time.Now().UTC()
	}
	report := Report{
		SchemaVersion:  1,
		GeneratedAt:    generated.UTC().Format(time.RFC3339Nano),
		SecretsPrinted: false,
		MigrationState: "blocked_on_ownership_handoff",
		Files:          []FileEvidence{},
		Conflicts:      []Conflict{},
		NextSteps: []string{
			"stop the manual owner only during a reviewed maintenance window",
			"prove listener, process, nft-table and NFQUEUE ownership",
			"stage and validate a ChangeSet before any dataplane switch",
			"keep a tested rollback to the manual dataplane until post-apply probes pass",
		},
	}

	raw, evidence, err := readBounded(opts.XrayPath, maxXrayBytes, "manual-xray")
	if err != nil {
		return Report{}, fmt.Errorf("read manual Xray config: %w", err)
	}
	report.Files = append(report.Files, evidence)
	xrayReport, bundle, err := inspectXray(raw)
	if err != nil {
		return Report{}, err
	}
	xrayReport.SourceSHA256 = evidence.SHA256
	report.Xray = xrayReport

	for _, path := range opts.ZapretArgs {
		if strings.TrimSpace(path) == "" {
			continue
		}
		zapret, evidence, err := inspectZapret(path)
		if err != nil {
			return Report{}, err
		}
		report.Zapret = append(report.Zapret, zapret)
		report.Files = append(report.Files, evidence)
	}
	if opts.DNSMasqPath != "" {
		evidence, err := evidenceOnly(opts.DNSMasqPath, "manual-dnsmasq")
		if err != nil {
			return Report{}, err
		}
		report.Files = append(report.Files, evidence)
	}
	deviceScopedQueues := map[int]ZapretDeviceScope{}
	for _, path := range opts.NFTPaths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		rawNFT, evidence, err := readBounded(path, maxEvidence, "manual-nft")
		if err != nil {
			return Report{}, err
		}
		report.Files = append(report.Files, evidence)
		queues, err := inspectNFTDeviceScopedQueues(rawNFT)
		if err != nil {
			return Report{}, fmt.Errorf("inspect manual nft evidence: %w", err)
		}
		for queue, scope := range queues {
			if previous, exists := deviceScopedQueues[queue]; exists {
				if previous.ScopeFingerprint != scope.ScopeFingerprint {
					previous.ScopeConflict = true
				}
				previous.TCPPorts = mergePortSpecs(previous.TCPPorts, scope.TCPPorts)
				previous.UDPDropPorts = mergePortSpecs(previous.UDPDropPorts, scope.UDPDropPorts)
				previous.SourceRuleCount += scope.SourceRuleCount
				deviceScopedQueues[queue] = previous
				continue
			}
			deviceScopedQueues[queue] = scope
		}
	}
	for index := range report.Zapret {
		scope, ok := deviceScopedQueues[report.Zapret[index].Queue]
		report.Zapret[index].DeviceScoped = ok
		if ok {
			scopeCopy := scope
			scopeCopy.TCPPorts = append([]string(nil), scope.TCPPorts...)
			scopeCopy.UDPDropPorts = append([]string(nil), scope.UDPDropPorts...)
			report.Zapret[index].DeviceScope = &scopeCopy
		}
	}

	report.Conflicts = conflicts(report.Xray, report.Zapret)
	if opts.OutputBundle != "" {
		if err := writeCandidate(opts.OutputBundle, bundle); err != nil {
			return Report{}, fmt.Errorf("write Xray migration candidate: %w", err)
		}
		report.Xray.BundleSHA256 = xraybundle.Hash(bundle)
		report.Xray.BundlePath = opts.OutputBundle
		report.Xray.BundleReady = true
	}
	return report, nil
}

// inspectNFTDeviceScopedQueues extracts only typed, redacted ownership facts from
// nft evidence. It deliberately does not return source IP/MAC values, so a
// redacted migration report cannot leak LAN identity. A host-scoped source
// (an address or a full-length /32 or /128 prefix) on a queue verdict is a
// device-scoped rule and must not be collapsed into a generic Zapret profile.
func inspectNFTDeviceScopedQueues(raw []byte) (map[int]ZapretDeviceScope, error) {
	queues := map[int]ZapretDeviceScope{}
	scopeQueues := map[string]map[int]bool{}
	udpDrops := map[string][]string{}
	scopeIDs := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64*1024), maxEvidence)
	for scanner.Scan() {
		line := scanner.Text()
		sourceMatch := nftSourceValue.FindStringSubmatch(line)
		if len(sourceMatch) != 2 || !hostScopedAddress(sourceMatch[1]) {
			continue
		}
		scopeFingerprint := scopeID(scopeIDs, sourceMatch[1])
		portMatch := nftPortValue.FindStringSubmatch(line)
		if len(portMatch) == 3 && strings.Contains(strings.ToLower(line), " drop") {
			if strings.EqualFold(portMatch[1], "udp") {
				udpDrops[scopeFingerprint] = mergePortSpecs(udpDrops[scopeFingerprint], []string{portMatch[2]})
			}
		}
		queueMatch := nftQueueValue.FindStringSubmatch(line)
		if len(queueMatch) != 2 {
			continue
		}
		queue, err := strconv.Atoi(queueMatch[1])
		if err != nil || queue < 1 || queue > 65535 {
			continue
		}
		scope := queues[queue]
		if scope.ScopeFingerprint == "" {
			scope = ZapretDeviceScope{ScopeFingerprint: scopeFingerprint, Queue: queue}
		} else if scope.ScopeFingerprint != scopeFingerprint {
			scope.ScopeConflict = true
		}
		if len(portMatch) == 3 && strings.EqualFold(portMatch[1], "tcp") {
			scope.TCPPorts = mergePortSpecs(scope.TCPPorts, []string{portMatch[2]})
		}
		scope.SourceRuleCount++
		queues[queue] = scope
		if scopeQueues[scopeFingerprint] == nil {
			scopeQueues[scopeFingerprint] = map[int]bool{}
		}
		scopeQueues[scopeFingerprint][queue] = true
	}
	for fingerprint, queueSet := range scopeQueues {
		for queue := range queueSet {
			scope := queues[queue]
			scope.UDPDropPorts = mergePortSpecs(scope.UDPDropPorts, udpDrops[fingerprint])
			queues[queue] = scope
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return queues, nil
}

func scopeID(ids map[string]string, rawSource string) string {
	if id := ids[rawSource]; id != "" {
		return id
	}
	id := fmt.Sprintf("scope-%03d", len(ids)+1)
	ids[rawSource] = id
	return id
}

func mergePortSpecs(existing, additions []string) []string {
	seen := make(map[string]bool, len(existing)+len(additions))
	for _, value := range append(append([]string(nil), existing...), additions...) {
		for _, part := range strings.Split(strings.Trim(value, "{} "), ",") {
			part = strings.TrimSpace(part)
			if part == "" || !validNFTPortSpec(part) {
				continue
			}
			seen[part] = true
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func validNFTPortSpec(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) > 2 {
		return false
	}
	start, err := strconv.Atoi(parts[0])
	if err != nil || start < 1 || start > 65535 {
		return false
	}
	if len(parts) == 2 {
		end, err := strconv.Atoi(parts[1])
		if err != nil || end < start || end > 65535 {
			return false
		}
	}
	return true
}

func hostScopedAddress(value string) bool {
	if addr, err := netip.ParseAddr(value); err == nil {
		return !addr.IsUnspecified()
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return false
	}
	return prefix.Bits() == prefix.Addr().BitLen() && !prefix.Addr().IsUnspecified()
}

func inspectXray(raw []byte) (XrayReport, []byte, error) {
	var cfg rawConfig
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&cfg); err != nil {
		return XrayReport{}, nil, errors.New("manual Xray config is invalid JSON")
	}
	if err := ensureEOF(decoder); err != nil {
		return XrayReport{}, nil, errors.New("manual Xray config has trailing data")
	}

	inbounds := make(map[string]inboundMeta)
	listenersSeen := make(map[string]bool)
	var report XrayReport
	ports := make([]int, 0, len(cfg.Inbounds))
	for _, rawInbound := range cfg.Inbounds {
		var value inboundMeta
		if err := json.Unmarshal(rawInbound, &value); err != nil {
			return XrayReport{}, nil, errors.New("manual Xray inbound is invalid")
		}
		if !tagPattern.MatchString(value.Tag) || value.Port < 1 || value.Port > 65535 {
			return XrayReport{}, nil, errors.New("manual Xray inbound has unsafe tag or port")
		}
		if _, exists := inbounds[value.Tag]; exists {
			return XrayReport{}, nil, fmt.Errorf("duplicate manual Xray inbound %s", value.Tag)
		}
		listenerKey := fmt.Sprintf("%s:%d", value.Listen, value.Port)
		if listenersSeen[listenerKey] {
			return XrayReport{}, nil, fmt.Errorf("duplicate manual Xray listener %s", listenerKey)
		}
		listenersSeen[listenerKey] = true
		inbounds[value.Tag] = value
		ports = append(ports, value.Port)
		report.InboundCount++
		switch {
		case value.Protocol == "socks" && value.Listen == "127.0.0.1":
			if value.Port < 1024 {
				return XrayReport{}, nil, fmt.Errorf("manual SOCKS inbound %s uses a privileged port", value.Tag)
			}
		case value.Protocol == "dokodemo-door" && strings.Contains(strings.ToLower(value.Tag), "tproxy"):
			report.Transparent++
		case value.Protocol == "dokodemo-door" && strings.Contains(strings.ToLower(value.Tag), "dns"):
			report.DNSInbounds++
		}
	}

	selectedInbounds := make(map[string]json.RawMessage)
	for _, rawInbound := range cfg.Inbounds {
		var value inboundMeta
		if err := json.Unmarshal(rawInbound, &value); err != nil {
			return XrayReport{}, nil, errors.New("manual Xray inbound is invalid")
		}
		if value.Protocol != "socks" || value.Listen != "127.0.0.1" {
			continue
		}
		if !strings.HasPrefix(value.Tag, "socks-") || len(value.Tag) <= len("socks-") {
			return XrayReport{}, nil, fmt.Errorf("manual SOCKS inbound %s does not have a route tag", value.Tag)
		}
		selectedInbounds[value.Tag] = append(json.RawMessage(nil), rawInbound...)
	}
	if len(selectedInbounds) == 0 {
		return XrayReport{}, nil, errors.New("manual Xray config has no loopback SOCKS inbounds to migrate")
	}

	selectedOutbounds := make(map[string]json.RawMessage)
	metas := make(map[string]outboundMeta)
	for _, rawOutbound := range cfg.Outbounds {
		var value outboundMeta
		if err := json.Unmarshal(rawOutbound, &value); err != nil {
			return XrayReport{}, nil, errors.New("manual Xray outbound is invalid")
		}
		if value.Protocol != "vless" {
			continue
		}
		if err := validateVLESS(value); err != nil {
			return XrayReport{}, nil, fmt.Errorf("manual Xray outbound %s: %w", value.Tag, err)
		}
		if _, exists := selectedOutbounds[value.Tag]; exists {
			return XrayReport{}, nil, fmt.Errorf("duplicate manual Xray outbound %s", value.Tag)
		}
		selectedOutbounds[value.Tag] = append(json.RawMessage(nil), rawOutbound...)
		metas[value.Tag] = value
	}
	if len(selectedOutbounds) != len(selectedInbounds) {
		return XrayReport{}, nil, fmt.Errorf("manual Xray SOCKS/VLESS topology mismatch: %d SOCKS, %d VLESS", len(selectedInbounds), len(selectedOutbounds))
	}

	selectedRules := make(map[string]json.RawMessage)
	for _, rawRule := range cfg.Routing.Rules {
		var value ruleMeta
		if err := json.Unmarshal(rawRule, &value); err != nil {
			return XrayReport{}, nil, errors.New("manual Xray routing rule is invalid")
		}
		if value.Type != "field" || len(value.InboundTags) != 1 || !strings.HasPrefix(value.InboundTags[0], "socks-") {
			continue
		}
		inboundTag := value.InboundTags[0]
		routeTag := strings.TrimPrefix(inboundTag, "socks-")
		if _, ok := selectedInbounds[inboundTag]; !ok {
			continue
		}
		if value.OutboundTag != routeTag {
			return XrayReport{}, nil, fmt.Errorf("manual Xray rule %s points to %s, expected %s", inboundTag, value.OutboundTag, routeTag)
		}
		if _, ok := selectedOutbounds[routeTag]; !ok {
			return XrayReport{}, nil, fmt.Errorf("manual Xray rule %s references missing VLESS outbound %s", inboundTag, routeTag)
		}
		if _, exists := selectedRules[inboundTag]; exists {
			return XrayReport{}, nil, fmt.Errorf("duplicate manual Xray SOCKS rule %s", inboundTag)
		}
		selectedRules[inboundTag] = append(json.RawMessage(nil), rawRule...)
	}
	if len(selectedRules) != len(selectedInbounds) {
		return XrayReport{}, nil, fmt.Errorf("manual Xray SOCKS routing rules mismatch: %d rules, %d inbounds", len(selectedRules), len(selectedInbounds))
	}

	tags := make([]string, 0, len(selectedOutbounds))
	for tag := range selectedOutbounds {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		meta := metas[tag]
		inboundTag := "socks-" + tag
		inbound := inbounds[inboundTag]
		report.Servers = append(report.Servers, ServerSummary{
			Tag: tag, Address: meta.Settings.VNext[0].Address, Port: meta.Settings.VNext[0].Port,
			Transport: meta.StreamSettings.Network, Security: meta.StreamSettings.Security,
			Flow: meta.Settings.VNext[0].Users[0].Flow, InboundTag: inboundTag,
			SOCKS5: fmt.Sprintf("127.0.0.1:%d", inbound.Port), Credential: true,
		})
	}
	report.SOCKSCount = len(selectedInbounds)
	report.VLESSCount = len(selectedOutbounds)
	report.ListenerPorts = append([]int(nil), ports...)
	sort.Ints(report.ListenerPorts)

	bundleRoot := struct {
		Log       map[string]string `json:"log"`
		Inbounds  []json.RawMessage `json:"inbounds"`
		Outbounds []json.RawMessage `json:"outbounds"`
		Routing   struct {
			DomainStrategy string            `json:"domainStrategy"`
			Rules          []json.RawMessage `json:"rules"`
		} `json:"routing"`
	}{Log: map[string]string{"loglevel": "warning"}}
	for _, tag := range tags {
		bundleRoot.Inbounds = append(bundleRoot.Inbounds, selectedInbounds["socks-"+tag])
		bundleRoot.Outbounds = append(bundleRoot.Outbounds, selectedOutbounds[tag])
		bundleRoot.Routing.Rules = append(bundleRoot.Routing.Rules, selectedRules["socks-"+tag])
	}
	bundleRoot.Routing.DomainStrategy = "AsIs"
	bundle, err := json.MarshalIndent(bundleRoot, "", "  ")
	if err != nil {
		return XrayReport{}, nil, fmt.Errorf("marshal Xray migration bundle: %w", err)
	}
	bundle = append(bundle, '\n')
	return report, bundle, nil
}

func validateVLESS(value outboundMeta) error {
	if !tagPattern.MatchString(value.Tag) || len(value.Settings.VNext) != 1 {
		return errors.New("VLESS outbound has invalid tag or vnext count")
	}
	server := value.Settings.VNext[0]
	if err := validateServerAddress(server.Address); err != nil {
		return err
	}
	if server.Port < 1 || server.Port > 65535 || len(server.Users) != 1 {
		return errors.New("VLESS outbound has invalid port or user count")
	}
	user := server.Users[0]
	if !uuidPattern.MatchString(user.ID) || user.Encryption != "none" {
		return errors.New("VLESS outbound has invalid credential encoding")
	}
	if value.StreamSettings.Network == "" || value.StreamSettings.Security == "" {
		return errors.New("VLESS outbound is missing transport security")
	}
	return nil
}

func validateServerAddress(address string) error {
	address = strings.TrimSpace(address)
	if address == "" || strings.ContainsAny(address, "\r\n/ \\@") {
		return errors.New("VLESS server address is invalid")
	}
	if ip, err := netip.ParseAddr(address); err == nil {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
			return errors.New("VLESS server address is not a public endpoint")
		}
		return nil
	}
	if net.ParseIP(address) != nil {
		return errors.New("VLESS server address is invalid")
	}
	canonical, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.ToLower(address), "."))
	if err != nil || canonical == "" || len(canonical) > 253 || strings.Contains(canonical, "..") {
		return errors.New("VLESS server hostname is invalid")
	}
	if canonical == "localhost" || strings.HasSuffix(canonical, ".local") || strings.HasSuffix(canonical, ".internal") {
		return errors.New("VLESS server hostname is not a public endpoint")
	}
	return nil
}

func inspectZapret(path string) (ZapretReport, FileEvidence, error) {
	raw, evidence, err := readBounded(path, maxEvidence, "manual-zapret")
	if err != nil {
		return ZapretReport{}, FileEvidence{}, err
	}
	report := ZapretReport{Path: path, SHA256: evidence.SHA256, Ownership: "foreign/manual", QueueSafe: true}
	lines := 0
	tokens := zapretTokens(raw)
	for _, token := range tokens {
		lines++
		if lines > maxZapretLines {
			return ZapretReport{}, FileEvidence{}, errors.New("Zapret argument file has too many lines")
		}
		line := strings.TrimSpace(token)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if match := queueValue.FindStringSubmatch(line); len(match) == 2 {
			queue, convErr := strconv.Atoi(match[1])
			if convErr != nil || queue < 1 || queue > 65535 {
				return ZapretReport{}, FileEvidence{}, errors.New("Zapret queue is invalid")
			}
			report.Queue = queue
			if queue == 0 || queue == 1 {
				report.QueueSafe = false
			}
			continue
		}
		if match := optionValue.FindStringSubmatch(line); len(match) == 3 {
			value := strings.TrimSpace(match[2])
			if match[1] == "dpi-desync" {
				report.Desync = append(report.Desync, value)
			} else {
				report.Filters = append(report.Filters, match[1]+"="+value)
			}
		}
	}
	if report.Queue == 0 {
		return ZapretReport{}, FileEvidence{}, errors.New("Zapret argument file has no queue number")
	}
	report.TypedStrategy, report.TypedModelReady, report.ModelBlockers = classifyTypedStrategy(tokens)
	return report, evidence, nil
}

// classifyTypedStrategy deliberately recognizes only the small, audited
// device-profile vocabulary. A readable nfqws argument file is not a typed
// managed profile: multi-stage hostlist/ipset strategies and payload assets
// remain blocked until they have their own structured model and ownership
// manifest.
func classifyTypedStrategy(tokens []string) (string, bool, []string) {
	normalized := normalizeStrategyTokens(tokens)
	const tvStrategy = "tv-fake-multidisorder-v1"
	expected := []string{
		"--filter-tcp=443",
		"--dpi-desync=fake,multidisorder",
		"--dpi-desync-split-pos=1,midsld",
		"--dpi-desync-fooling=badseq,md5sig",
	}
	if len(normalized) == len(expected) {
		match := true
		for index := range expected {
			if normalized[index] != expected[index] {
				match = false
				break
			}
		}
		if match {
			return tvStrategy, true, nil
		}
	}
	blockers := []string{"nfqws strategy is not in the audited typed profile vocabulary"}
	for _, token := range normalized {
		if strings.HasPrefix(token, "--hostlist") || strings.HasPrefix(token, "--ipset") || strings.HasPrefix(token, "--dpi-desync-fake-") || token == "--new" {
			blockers = append(blockers, "strategy uses multi-stage or external hostlist/ipset/payload assets")
			break
		}
	}
	return "", false, uniqueStrings(blockers)
}

func normalizeStrategyTokens(tokens []string) []string {
	result := make([]string, 0, len(tokens))
	for index := 0; index < len(tokens); index++ {
		token := strings.TrimSpace(tokens[index])
		if token == "" || token == "/usr/bin/nfqws" || strings.HasPrefix(token, "--qnum=") || token == "--qnum" {
			continue
		}
		if token == "multidisorder" && len(result) > 0 && result[len(result)-1] == "--dpi-desync=fake" {
			result[len(result)-1] = "--dpi-desync=fake,multidisorder"
			continue
		}
		if token == "md5sig" && len(result) > 0 && result[len(result)-1] == "--dpi-desync-fooling=badseq" {
			result[len(result)-1] = "--dpi-desync-fooling=badseq,md5sig"
			continue
		}
		result = append(result, token)
	}
	return result
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func zapretTokens(raw []byte) []string {
	if bytes.IndexByte(raw, 0) >= 0 {
		parts := bytes.Split(raw, []byte{0})
		tokens := make([]string, 0, len(parts))
		for _, part := range parts {
			value := strings.TrimSpace(string(part))
			if value != "" && !strings.HasPrefix(value, "PID:") && value != "/usr/bin/nfqws" {
				tokens = append(tokens, value)
			}
		}
		return tokens
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 1024), maxEvidence)
	tokens := make([]string, 0)
	for scanner.Scan() {
		tokens = append(tokens, scanner.Text())
	}
	return tokens
}

func conflicts(xray XrayReport, zapret []ZapretReport) []Conflict {
	conflicts := []Conflict{
		{Resource: "xray listener ports", Severity: "SEV-1", Reason: "manual Xray already owns the TPROXY/DNS/SOCKS listeners used by the managed service", Action: "prove a single owner and stop the manual owner only inside a reviewed ChangeSet"},
		{Resource: "manual nft tables", Severity: "SEV-1", Reason: "manual tables are not marked as FlintRoute-owned", Action: "keep them foreign; never flush or replace them during import"},
		{Resource: "manual dnsmasq include", Severity: "SEV-2", Reason: "DNS policy is outside the current install manifest", Action: "include it in a future handoff manifest before activation"},
		{Resource: "manual cron/procd lifecycle", Severity: "SEV-1", Reason: "the manual owner can recreate processes after FlintRoute stops them", Action: "inventory and disable only after a tested replacement and rollback exist"},
	}
	if xray.VLESSCount == 0 || xray.SOCKSCount != xray.VLESSCount {
		conflicts = append(conflicts, Conflict{Resource: "xray bundle", Severity: "SEV-1", Reason: "SOCKS/VLESS topology is incomplete", Action: "do not create a candidate"})
	}
	for _, item := range zapret {
		if !item.QueueSafe {
			conflicts = append(conflicts, Conflict{Resource: fmt.Sprintf("NFQUEUE %d", item.Queue), Severity: "SEV-1", Reason: "reserved system queue", Action: "refuse migration and leave the queue untouched"})
		}
		if item.DeviceScoped {
			conflicts = append(conflicts, Conflict{Resource: fmt.Sprintf("device-scoped Zapret queue %d", item.Queue), Severity: "SEV-1", Reason: "nft evidence binds this queue to a host-scoped source rule", Action: "keep it foreign until an explicit device-scoped profile, lifecycle owner and rollback are reviewed"})
		}
	}
	return conflicts
}

func evidenceOnly(path, role string) (FileEvidence, error) {
	_, evidence, err := readBounded(path, maxEvidence, role)
	return evidence, err
}

func readBounded(path string, limit int64, role string) ([]byte, FileEvidence, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || path == "" {
		return nil, FileEvidence{}, errors.New("manual migration path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, FileEvidence{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, FileEvidence{}, fmt.Errorf("manual migration input %s is not a regular file", path)
	}
	if role == "manual-xray" && runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return nil, FileEvidence{}, errors.New("manual Xray config must have mode 0600")
	}
	if info.Size() <= 0 || info.Size() > limit {
		return nil, FileEvidence{}, fmt.Errorf("manual migration input %s exceeds size limit", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, FileEvidence{}, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, FileEvidence{}, err
	}
	if int64(len(raw)) > limit {
		return nil, FileEvidence{}, fmt.Errorf("manual migration input %s exceeds size limit", path)
	}
	sum := sha256.Sum256(raw)
	return raw, FileEvidence{Path: path, Bytes: int64(len(raw)), SHA256: hex.EncodeToString(sum[:]), Role: role}, nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func writeCandidate(path string, raw []byte) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || path == "" {
		return errors.New("candidate output path is required")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("candidate output is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".manual-import-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return nil
}
