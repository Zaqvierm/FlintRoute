package vpnsub

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"router-policy/internal/secureid"
)

var secureRandomHex = secureid.Hex

const (
	maxSubscriptionFileBytes = 4 << 20
	maxVLESSServers          = 1024
)

var (
	safeTagPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	uuidPattern    = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[1-5][a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$`)
)

type Summary struct {
	TopLevelType           string         `json:"top_level_type"`
	ConfigCount            int            `json:"config_count"`
	OutboundCount          int            `json:"outbound_count"`
	VLESSCount             int            `json:"vless_count"`
	ProtocolCounts         map[string]int `json:"protocol_counts"`
	StreamSecurityCounts   map[string]int `json:"stream_security_counts"`
	StreamNetworkCounts    map[string]int `json:"stream_network_counts"`
	MissingRequiredCounts  map[string]int `json:"missing_required_counts"`
	DuplicateTags          []string       `json:"duplicate_tags,omitempty"`
	DeduplicatedVLESSCount int            `json:"deduplicated_vless_count,omitempty"`
	SupportedVLESSCount    int            `json:"supported_vless_count"`
	UnsupportedVLESSCount  int            `json:"unsupported_vless_count"`
	Servers                []ServerStatus `json:"servers,omitempty"`
	SafeSummary            bool           `json:"safe_summary"`
}

type ServerStatus struct {
	Tag       string `json:"tag,omitempty"`
	SourceTag string `json:"source_tag,omitempty"`
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
	SOCKS5    string `json:"socks5,omitempty"`
}

type GeneratedRoute struct {
	Type            string `json:"type"`
	Tag             string `json:"tag"`
	Priority        int    `json:"priority"`
	SOCKS5          string `json:"socks5"`
	DNSMode         string `json:"dns_mode"`
	ExternalIPProbe bool   `json:"external_ip_probe"`
}

type XrayGenerationSummary struct {
	Inbounds           int            `json:"inbounds"`
	Outbounds          int            `json:"outbounds"`
	RoutingRules       int            `json:"routing_rules"`
	SOCKS5             []string       `json:"socks5"`
	Output             string         `json:"output"`
	SHA256             string         `json:"sha256"`
	SecretsPrinted     bool           `json:"secrets_printed"`
	SubscriptionSHA256 string         `json:"subscription_sha256"`
	Servers            []ServerStatus `json:"servers"`
}

type outbound struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
	Settings struct {
		VNext []struct {
			Address string `json:"address"`
			Port    int    `json:"port"`
			Users   []struct {
				ID         string `json:"id"`
				Encryption string `json:"encryption"`
				Flow       string `json:"flow"`
			} `json:"users"`
		} `json:"vnext"`
	} `json:"settings"`
	StreamSettings struct {
		Network  string          `json:"network"`
		Security string          `json:"security"`
		Raw      json.RawMessage `json:"-"`
	} `json:"streamSettings"`
}

type rawOutbound struct {
	Outbound  outbound
	Raw       json.RawMessage
	SourceTag string
}

type outboundNormalization struct {
	DuplicateTags     []string
	DeduplicatedVLESS int
}

type outboundDecision struct {
	Supported bool
	Reason    string
}

func NormalizeFile(path string) (Summary, error) {
	b, err := readSubscriptionFile(path)
	if err != nil {
		return Summary{}, err
	}
	return Normalize(b)
}

func GenerateRoutesFile(path string, basePort int) ([]GeneratedRoute, error) {
	b, err := readSubscriptionFile(path)
	if err != nil {
		return nil, err
	}
	rawOuts, err := extractRawOutbounds(b)
	if err != nil {
		return nil, err
	}
	supported, _, err := classifyRawOutbounds(rawOuts)
	if err != nil {
		return nil, err
	}
	if err := validatePortRange(basePort, len(supported)); err != nil {
		return nil, err
	}
	routes := make([]GeneratedRoute, 0, len(supported))
	for idx, item := range supported {
		routes = append(routes, GeneratedRoute{
			Type:            "vless",
			Tag:             item.Outbound.Tag,
			Priority:        100 + idx,
			SOCKS5:          fmt.Sprintf("127.0.0.1:%d", basePort+idx),
			DNSMode:         "socks_remote",
			ExternalIPProbe: true,
		})
	}
	if len(routes) == 0 {
		return nil, errors.New("no vless routes generated")
	}
	return routes, nil
}

func GenerateXrayConfigFile(subscriptionPath, outputPath string, basePort int) (XrayGenerationSummary, error) {
	b, err := readSubscriptionFile(subscriptionPath)
	if err != nil {
		return XrayGenerationSummary{}, err
	}
	rawOuts, err := extractRawOutbounds(b)
	if err != nil {
		return XrayGenerationSummary{}, err
	}
	supported, statuses, err := classifyRawOutbounds(rawOuts)
	if err != nil {
		return XrayGenerationSummary{}, err
	}
	if err := validatePortRange(basePort, len(supported)); err != nil {
		return XrayGenerationSummary{}, err
	}

	type xrayConfig struct {
		Log       map[string]any    `json:"log"`
		Inbounds  []map[string]any  `json:"inbounds"`
		Outbounds []json.RawMessage `json:"outbounds"`
		Routing   map[string]any    `json:"routing"`
	}
	var cfg xrayConfig
	cfg.Log = map[string]any{"loglevel": "warning"}
	cfg.Routing = map[string]any{"domainStrategy": "AsIs"}

	var rules []map[string]any
	socksByTag := map[string]string{}
	for idx, item := range supported {
		o := item.Outbound
		tag := strings.TrimSpace(o.Tag)
		port := basePort + idx
		inboundTag := "socks-" + tag
		socksByTag[tag] = fmt.Sprintf("127.0.0.1:%d", port)
		cfg.Inbounds = append(cfg.Inbounds, map[string]any{
			"tag":      inboundTag,
			"listen":   "127.0.0.1",
			"port":     port,
			"protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": true, "ip": "127.0.0.1"},
			"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls"}},
		})
		cfg.Outbounds = append(cfg.Outbounds, item.Raw)
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{inboundTag}, "outboundTag": tag})
	}
	if len(cfg.Inbounds) == 0 {
		return XrayGenerationSummary{}, errors.New("no vless outbounds generated")
	}
	cfg.Routing["rules"] = rules

	rawConfig, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return XrayGenerationSummary{}, err
	}
	configBytes := append(append([]byte(nil), rawConfig...), '\n')
	if err := writeFileAtomic(outputPath, configBytes, 0o600); err != nil {
		return XrayGenerationSummary{}, err
	}
	socks := make([]string, 0, len(cfg.Inbounds))
	for _, inbound := range cfg.Inbounds {
		socks = append(socks, fmt.Sprintf("127.0.0.1:%d", inbound["port"]))
	}
	for i := range statuses {
		if statuses[i].Status == "SUPPORTED" {
			statuses[i].SOCKS5 = socksByTag[statuses[i].Tag]
		}
	}
	return XrayGenerationSummary{
		Inbounds:           len(cfg.Inbounds),
		Outbounds:          len(cfg.Outbounds),
		RoutingRules:       len(rules),
		SOCKS5:             socks,
		Output:             outputPath,
		SHA256:             "sha256:" + sha256Hex(configBytes),
		SecretsPrinted:     false,
		SubscriptionSHA256: "sha256:" + sha256Hex(b),
		Servers:            statuses,
	}, nil
}

func Normalize(b []byte) (Summary, error) {
	outs, topLevel, configCount, err := extractOutboundsWithShape(b)
	if err != nil {
		return Summary{}, err
	}
	summary := Summary{
		TopLevelType:          topLevel,
		ConfigCount:           configCount,
		ProtocolCounts:        map[string]int{},
		StreamSecurityCounts:  map[string]int{},
		StreamNetworkCounts:   map[string]int{},
		MissingRequiredCounts: map[string]int{},
		SafeSummary:           true,
	}
	rawOuts, err := extractRawOutbounds(b)
	if err != nil {
		return Summary{}, err
	}
	prepared, normalization, err := prepareRawOutbounds(rawOuts)
	if err != nil {
		return Summary{}, err
	}
	_, statuses, err := classifyPreparedRawOutbounds(prepared)
	if err != nil && len(statuses) == 0 {
		return Summary{}, err
	}
	for _, o := range outs {
		summary.OutboundCount++
		summary.ProtocolCounts[emptyToNull(o.Protocol)]++
		summary.StreamSecurityCounts[emptyToNull(o.StreamSettings.Security)]++
		summary.StreamNetworkCounts[emptyToNull(o.StreamSettings.Network)]++
		if o.Protocol == "vless" {
			summary.VLESSCount++
		}
	}
	if summary.VLESSCount == 0 {
		return summary, errors.New("no vless outbounds")
	}
	summary.DuplicateTags = normalization.DuplicateTags
	summary.DeduplicatedVLESSCount = normalization.DeduplicatedVLESS
	summary.Servers = statuses
	for _, status := range statuses {
		if status.Status == "SUPPORTED" {
			summary.SupportedVLESSCount++
			continue
		}
		summary.UnsupportedVLESSCount++
		summary.MissingRequiredCounts[status.Reason]++
	}
	return summary, nil
}

func extractOutbounds(b []byte) ([]outbound, error) {
	outs, _, _, err := extractOutboundsWithShape(b)
	return outs, err
}

func extractRawOutbounds(b []byte) ([]rawOutbound, error) {
	var anyValue any
	if err := json.Unmarshal(b, &anyValue); err != nil {
		return nil, err
	}
	var out []rawOutbound
	switch top := anyValue.(type) {
	case map[string]any:
		if _, ok := top["outbounds"].([]any); !ok {
			return nil, errors.New("object has no outbounds array")
		}
		var cfg struct {
			Outbounds []json.RawMessage `json:"outbounds"`
		}
		if err := json.Unmarshal(b, &cfg); err != nil {
			return nil, err
		}
		return rawMessagesToOutbounds(cfg.Outbounds)
	case []any:
		var items []json.RawMessage
		if err := json.Unmarshal(b, &items); err != nil {
			return nil, err
		}
		for _, item := range items {
			var cfg struct {
				Outbounds []json.RawMessage `json:"outbounds"`
			}
			if err := json.Unmarshal(item, &cfg); err == nil && len(cfg.Outbounds) > 0 {
				next, err := rawMessagesToOutbounds(cfg.Outbounds)
				if err != nil {
					return nil, err
				}
				out = append(out, next...)
				continue
			}
			next, err := rawMessagesToOutbounds([]json.RawMessage{item})
			if err == nil {
				out = append(out, next...)
			}
		}
		if len(out) == 0 {
			return nil, errors.New("no outbounds found")
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported top-level JSON type")
	}
}

func rawMessagesToOutbounds(items []json.RawMessage) ([]rawOutbound, error) {
	out := make([]rawOutbound, 0, len(items))
	for _, raw := range items {
		var o outbound
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, err
		}
		out = append(out, rawOutbound{Outbound: o, Raw: append(json.RawMessage(nil), raw...)})
	}
	return out, nil
}

func prepareRawOutbounds(items []rawOutbound) ([]rawOutbound, outboundNormalization, error) {
	var meta outboundNormalization
	rawTagCounts := map[string]int{}
	vlessCount := 0
	for _, item := range items {
		if item.Outbound.Protocol != "vless" {
			continue
		}
		vlessCount++
		if item.Outbound.Tag != "" {
			rawTagCounts[item.Outbound.Tag]++
		}
	}
	if vlessCount > maxVLESSServers {
		return nil, meta, errors.New("vless server limit exceeded")
	}
	for tag, count := range rawTagCounts {
		if count > 1 {
			meta.DuplicateTags = append(meta.DuplicateTags, tag)
		}
	}
	sort.Strings(meta.DuplicateTags)

	identitySeen := map[string]struct{}{}
	identities := make([]string, 0, len(items))
	prepared := make([]rawOutbound, 0, len(items))
	for _, item := range items {
		item.SourceTag = item.Outbound.Tag
		if item.Outbound.Protocol != "vless" {
			prepared = append(prepared, item)
			identities = append(identities, "")
			continue
		}
		identity, err := outboundIdentity(item.Raw)
		if err != nil {
			return nil, meta, errors.New("invalid outbound JSON")
		}
		if _, exists := identitySeen[identity]; exists {
			meta.DeduplicatedVLESS++
			continue
		}
		identitySeen[identity] = struct{}{}
		prepared = append(prepared, item)
		identities = append(identities, identity)
	}

	uniqueTagCounts := map[string]int{}
	usedTags := map[string]struct{}{}
	for _, item := range prepared {
		if item.Outbound.Protocol != "vless" {
			continue
		}
		uniqueTagCounts[item.Outbound.Tag]++
		usedTags[item.Outbound.Tag] = struct{}{}
	}
	for i := range prepared {
		item := &prepared[i]
		if item.Outbound.Protocol != "vless" || uniqueTagCounts[item.Outbound.Tag] < 2 || !safeTagPattern.MatchString(item.Outbound.Tag) {
			continue
		}
		newTag, err := collisionSafeTag(item.Outbound.Tag, identities[i], usedTags)
		if err != nil {
			return nil, meta, err
		}
		retagged, err := retagOutbound(item.Raw, newTag)
		if err != nil {
			return nil, meta, errors.New("could not retag duplicate outbound")
		}
		item.Outbound.Tag = newTag
		item.Raw = retagged
		usedTags[newTag] = struct{}{}
	}
	return prepared, meta, nil
}

func outboundIdentity(raw json.RawMessage) (string, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return "", err
	}
	delete(object, "tag")
	canonical, err := json.Marshal(object)
	if err != nil {
		return "", err
	}
	return sha256Hex(canonical), nil
}

func collisionSafeTag(base, identity string, used map[string]struct{}) (string, error) {
	for suffixLength := 8; suffixLength <= 32; suffixLength += 4 {
		prefixLength := 64 - suffixLength - 1
		prefix := base
		if len(prefix) > prefixLength {
			prefix = prefix[:prefixLength]
		}
		candidate := prefix + "-" + identity[:suffixLength]
		if _, exists := used[candidate]; !exists {
			return candidate, nil
		}
	}
	return "", errors.New("could not derive unique outbound tag")
}

func retagOutbound(raw json.RawMessage, tag string) (json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	rawTag, err := json.Marshal(tag)
	if err != nil {
		return nil, err
	}
	object["tag"] = rawTag
	return json.Marshal(object)
}

func extractOutboundsWithShape(b []byte) ([]outbound, string, int, error) {
	var anyValue any
	if err := json.Unmarshal(b, &anyValue); err != nil {
		return nil, "", 0, err
	}
	var outs []outbound
	topLevel := ""
	configCount := 0

	switch top := anyValue.(type) {
	case map[string]any:
		topLevel = "object"
		configCount = 1
		if _, ok := top["outbounds"].([]any); !ok {
			return nil, "", 0, errors.New("object has no outbounds array")
		}
		var cfg struct {
			Outbounds []outbound `json:"outbounds"`
		}
		if err := json.Unmarshal(b, &cfg); err != nil {
			return nil, "", 0, err
		}
		outs = append(outs, cfg.Outbounds...)
	case []any:
		topLevel = "array"
		configCount = len(top)
		var raw []json.RawMessage
		if err := json.Unmarshal(b, &raw); err != nil {
			return nil, "", 0, err
		}
		for _, item := range raw {
			var cfg struct {
				Outbounds []outbound `json:"outbounds"`
			}
			if err := json.Unmarshal(item, &cfg); err == nil && len(cfg.Outbounds) > 0 {
				outs = append(outs, cfg.Outbounds...)
				continue
			}
			var o outbound
			if err := json.Unmarshal(item, &o); err == nil && o.Protocol != "" {
				outs = append(outs, o)
			}
		}
	default:
		return nil, "", 0, fmt.Errorf("unsupported top-level JSON type")
	}
	return outs, topLevel, configCount, nil
}

func summarizeOutbounds(outs []outbound, summary Summary) (Summary, error) {
	tagSeen := map[string]int{}
	decisions := classifyOutbounds(outs)
	for _, o := range outs {
		summary.OutboundCount++
		summary.ProtocolCounts[emptyToNull(o.Protocol)]++
		summary.StreamSecurityCounts[emptyToNull(o.StreamSettings.Security)]++
		summary.StreamNetworkCounts[emptyToNull(o.StreamSettings.Network)]++
		if o.Tag != "" {
			tagSeen[o.Tag]++
		}
		if o.Protocol != "vless" {
			continue
		}
		summary.VLESSCount++
	}
	for tag, count := range tagSeen {
		if count > 1 {
			summary.DuplicateTags = append(summary.DuplicateTags, tag)
		}
	}
	if summary.VLESSCount == 0 {
		return summary, errors.New("no vless outbounds")
	}
	for i, o := range outs {
		if o.Protocol != "vless" {
			continue
		}
		decision := decisions[i]
		server := ServerStatus{Tag: o.Tag, Status: "SUPPORTED"}
		if decision.Supported {
			summary.SupportedVLESSCount++
		} else {
			server.Status = "UNSUPPORTED"
			server.Reason = decision.Reason
			summary.UnsupportedVLESSCount++
			summary.MissingRequiredCounts[decision.Reason]++
		}
		summary.Servers = append(summary.Servers, server)
	}
	return summary, nil
}

func classifyRawOutbounds(items []rawOutbound) ([]rawOutbound, []ServerStatus, error) {
	prepared, _, err := prepareRawOutbounds(items)
	if err != nil {
		return nil, nil, err
	}
	return classifyPreparedRawOutbounds(prepared)
}

func classifyPreparedRawOutbounds(items []rawOutbound) ([]rawOutbound, []ServerStatus, error) {
	typed := make([]outbound, len(items))
	for i := range items {
		typed[i] = items[i].Outbound
	}
	decisions := classifyOutbounds(typed)
	supported := make([]rawOutbound, 0, len(items))
	statuses := make([]ServerStatus, 0, len(items))
	for i, item := range items {
		if item.Outbound.Protocol != "vless" {
			continue
		}
		status := ServerStatus{Tag: item.Outbound.Tag, Status: "SUPPORTED"}
		if item.SourceTag != "" && item.SourceTag != item.Outbound.Tag {
			status.SourceTag = item.SourceTag
		}
		if decisions[i].Supported {
			supported = append(supported, item)
		} else {
			status.Status = "UNSUPPORTED"
			status.Reason = decisions[i].Reason
		}
		statuses = append(statuses, status)
	}
	if len(statuses) == 0 {
		return nil, nil, errors.New("no vless outbounds")
	}
	if len(supported) == 0 {
		return nil, statuses, errors.New("no supported vless outbounds")
	}
	return supported, statuses, nil
}

func classifyOutbounds(outs []outbound) []outboundDecision {
	decisions := make([]outboundDecision, len(outs))
	vlessCount := 0
	for i, o := range outs {
		if o.Protocol != "vless" {
			continue
		}
		vlessCount++
		reason := validateVLESSOutbound(o)
		decisions[i] = outboundDecision{Supported: reason == "", Reason: reason}
	}
	if vlessCount > maxVLESSServers {
		for i, o := range outs {
			if o.Protocol == "vless" {
				decisions[i] = outboundDecision{Reason: "server_limit_exceeded"}
			}
		}
	}
	return decisions
}

func validateVLESSOutbound(o outbound) string {
	if !safeTagPattern.MatchString(o.Tag) {
		return "invalid_tag"
	}
	if len(o.Settings.VNext) == 0 || len(o.Settings.VNext) > 8 {
		return "invalid_vnext_count"
	}
	for _, server := range o.Settings.VNext {
		if !safeServerAddress(server.Address) {
			return "invalid_address"
		}
		if server.Port < 1 || server.Port > 65535 {
			return "invalid_port"
		}
		if len(server.Users) == 0 || len(server.Users) > 16 {
			return "invalid_user_count"
		}
		for _, user := range server.Users {
			if !uuidPattern.MatchString(user.ID) {
				return "invalid_user_id"
			}
			if user.Encryption != "" && user.Encryption != "none" {
				return "unsupported_encryption"
			}
			if user.Flow != "" && user.Flow != "xtls-rprx-vision" {
				return "unsupported_flow"
			}
		}
	}
	switch strings.ToLower(o.StreamSettings.Security) {
	case "tls", "reality":
	default:
		return "unsupported_stream_security"
	}
	switch strings.ToLower(o.StreamSettings.Network) {
	case "tcp", "ws", "grpc", "httpupgrade", "xhttp":
	default:
		return "unsupported_stream_network"
	}
	return ""
}

func safeServerAddress(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "\x00\r\n\t /\\") {
		return false
	}
	return true
}

func validatePortRange(basePort, count int) error {
	if count <= 0 {
		return errors.New("no supported vless outbounds")
	}
	if basePort < 1024 || basePort > 65535 || count > 65535-basePort+1 {
		return errors.New("SOCKS port range exhausted")
	}
	return nil
}

func emptyToNull(s string) string {
	if s == "" {
		return "null"
	}
	return s
}

func readSubscriptionFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("subscription must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > maxSubscriptionFileBytes {
		return nil, errors.New("subscription size limit exceeded")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return nil, errors.New("subscription file must have mode 0600")
	}
	return os.ReadFile(path)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	suffix, err := secureRandomHex(6)
	if err != nil {
		return fmt.Errorf("generate subscription temporary name: %w", err)
	}
	tmp := path + ".tmp." + suffix
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Chmod(path, perm)
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}
