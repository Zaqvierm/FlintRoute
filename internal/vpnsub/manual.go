package vpnsub

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const maxManualVLESSServers = 20

// ManualServer is the safe, non-secret view of a manually added VLESS outbound.
type ManualServer struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Security string `json:"security"`
	Network  string `json:"network"`
}

// ManualServersPath keeps manually entered credentials outside the public config.
func ManualServersPath(stateDir string) string {
	return filepath.Join(stateDir, "xray", "manual-servers.json")
}

// AddManualServer parses a VLESS URI, stores only the generated Xray outbound,
// and returns a safe inventory that never contains the user UUID or URI.
func AddManualServer(path, rawURI string) ([]ManualServer, bool, error) {
	outbound, server, err := parseManualVLESSURI(rawURI)
	if err != nil {
		return nil, false, err
	}
	items, err := loadManualOutbounds(path, true)
	if err != nil {
		return nil, false, err
	}
	changed := true
	replaced := false
	for index := range items {
		if items[index].Outbound.Tag != server.ID {
			continue
		}
		replaced = true
		if bytes.Equal(items[index].Raw, outbound.Raw) {
			changed = false
		} else {
			items[index] = outbound
		}
		break
	}
	if !replaced {
		if len(items) >= maxManualVLESSServers {
			return nil, false, fmt.Errorf("manual VLESS server limit is %d", maxManualVLESSServers)
		}
		items = append(items, outbound)
	}
	if changed {
		if err := storeManualOutbounds(path, items); err != nil {
			return nil, false, err
		}
	}
	servers, err := safeManualServers(items)
	return servers, changed, err
}

// DeleteManualServer removes exactly one registered outbound by its safe ID.
func DeleteManualServer(path, id string) ([]ManualServer, bool, error) {
	if !safeTagPattern.MatchString(id) || !strings.HasPrefix(id, "manual-") {
		return nil, false, errors.New("invalid manual VLESS server ID")
	}
	items, err := loadManualOutbounds(path, true)
	if err != nil {
		return nil, false, err
	}
	next := make([]rawOutbound, 0, len(items))
	changed := false
	for _, item := range items {
		if item.Outbound.Tag == id {
			changed = true
			continue
		}
		next = append(next, item)
	}
	if changed {
		if len(next) == 0 {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, false, err
			}
		} else if err := storeManualOutbounds(path, next); err != nil {
			return nil, false, err
		}
	}
	servers, err := safeManualServers(next)
	return servers, changed, err
}

func ListManualServers(path string) ([]ManualServer, error) {
	items, err := loadManualOutbounds(path, true)
	if err != nil {
		return nil, err
	}
	return safeManualServers(items)
}

func parseManualVLESSURI(rawURI string) (rawOutbound, ManualServer, error) {
	value := strings.TrimSpace(rawURI)
	if value == "" || len(value) > 8192 || strings.ContainsAny(value, "\x00\r\n\t") {
		return rawOutbound{}, ManualServer{}, errors.New("VLESS URI is empty or invalid")
	}
	parsed, err := url.Parse(value)
	if err != nil || strings.ToLower(parsed.Scheme) != "vless" || parsed.User == nil || parsed.Hostname() == "" {
		return rawOutbound{}, ManualServer{}, errors.New("provide a valid vless:// URI")
	}
	if _, hasPassword := parsed.User.Password(); hasPassword {
		return rawOutbound{}, ManualServer{}, errors.New("VLESS URI userinfo must contain only the UUID")
	}
	uuid := parsed.User.Username()
	if !uuidPattern.MatchString(uuid) {
		return rawOutbound{}, ManualServer{}, errors.New("VLESS URI contains an invalid UUID")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return rawOutbound{}, ManualServer{}, errors.New("VLESS URI contains an invalid port")
	}
	address := strings.TrimSpace(parsed.Hostname())
	if !safeServerAddress(address) {
		return rawOutbound{}, ManualServer{}, errors.New("VLESS URI contains an invalid server address")
	}
	query := parsed.Query()
	security := strings.ToLower(strings.TrimSpace(query.Get("security")))
	if security != "tls" && security != "reality" {
		return rawOutbound{}, ManualServer{}, errors.New("manual VLESS requires TLS or Reality security")
	}
	network := strings.ToLower(strings.TrimSpace(query.Get("type")))
	if network == "" {
		network = "tcp"
	}
	switch network {
	case "tcp", "ws", "grpc", "httpupgrade", "xhttp":
	default:
		return rawOutbound{}, ManualServer{}, errors.New("unsupported VLESS transport type")
	}
	flow := strings.TrimSpace(query.Get("flow"))
	if flow != "" && flow != "xtls-rprx-vision" {
		return rawOutbound{}, ManualServer{}, errors.New("unsupported VLESS flow")
	}
	name, _ := url.PathUnescape(parsed.Fragment)
	name = strings.TrimSpace(name)
	if name == "" {
		name = address
	}
	if len(name) > 96 {
		name = name[:96]
	}
	identity := sha256Hex([]byte(value))
	tag := manualServerTag(name, identity)
	user := map[string]any{"id": uuid, "encryption": "none"}
	if flow != "" {
		user["flow"] = flow
	}
	stream := map[string]any{"network": network, "security": security}
	serverName := strings.TrimSpace(query.Get("sni"))
	fingerprint := strings.TrimSpace(query.Get("fp"))
	if security == "reality" {
		publicKey := strings.TrimSpace(query.Get("pbk"))
		if serverName == "" || publicKey == "" {
			return rawOutbound{}, ManualServer{}, errors.New("Reality VLESS requires sni and pbk")
		}
		reality := map[string]any{"serverName": serverName, "publicKey": publicKey}
		if fingerprint != "" {
			reality["fingerprint"] = fingerprint
		}
		if shortID := strings.TrimSpace(query.Get("sid")); shortID != "" {
			reality["shortId"] = shortID
		}
		if spiderX := strings.TrimSpace(query.Get("spx")); spiderX != "" {
			reality["spiderX"] = spiderX
		}
		stream["realitySettings"] = reality
	} else if serverName != "" || fingerprint != "" {
		tls := map[string]any{}
		if serverName != "" {
			tls["serverName"] = serverName
		}
		if fingerprint != "" {
			tls["fingerprint"] = fingerprint
		}
		stream["tlsSettings"] = tls
	}
	applyManualTransportSettings(stream, network, query)
	object := map[string]any{
		"tag": tag, "protocol": "vless",
		"settings":       map[string]any{"vnext": []any{map[string]any{"address": address, "port": port, "users": []any{user}}}},
		"streamSettings": stream,
	}
	raw, err := json.Marshal(object)
	if err != nil {
		return rawOutbound{}, ManualServer{}, err
	}
	var typed outbound
	if err := json.Unmarshal(raw, &typed); err != nil {
		return rawOutbound{}, ManualServer{}, err
	}
	if reason := validateVLESSOutbound(typed); reason != "" {
		return rawOutbound{}, ManualServer{}, fmt.Errorf("manual VLESS outbound is not supported: %s", reason)
	}
	return rawOutbound{Outbound: typed, Raw: raw}, ManualServer{ID: tag, Name: name, Address: address, Port: port, Protocol: "vless", Security: security, Network: network}, nil
}

func manualServerTag(name, identity string) string {
	var slug strings.Builder
	for _, char := range strings.ToLower(name) {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') {
			slug.WriteRune(char)
		} else if slug.Len() > 0 && !strings.HasSuffix(slug.String(), "-") {
			slug.WriteByte('-')
		}
		if slug.Len() >= 32 {
			break
		}
	}
	label := strings.Trim(slug.String(), "-")
	if label == "" {
		label = "server"
	}
	return "manual-" + label + "-" + identity[:12]
}

func applyManualTransportSettings(stream map[string]any, network string, query url.Values) {
	path := strings.TrimSpace(query.Get("path"))
	host := strings.TrimSpace(query.Get("host"))
	switch network {
	case "ws":
		settings := map[string]any{}
		if path != "" {
			settings["path"] = path
		}
		if host != "" {
			settings["headers"] = map[string]any{"Host": host}
		}
		stream["wsSettings"] = settings
	case "grpc":
		if serviceName := strings.TrimSpace(query.Get("serviceName")); serviceName != "" {
			stream["grpcSettings"] = map[string]any{"serviceName": serviceName}
		}
	case "httpupgrade":
		stream["httpupgradeSettings"] = map[string]any{"host": host, "path": path}
	case "xhttp":
		stream["xhttpSettings"] = map[string]any{"host": host, "path": path, "mode": strings.TrimSpace(query.Get("mode"))}
	}
}

func loadManualOutbounds(path string, missingOK bool) ([]rawOutbound, error) {
	raw, err := readSubscriptionFile(path)
	if errors.Is(err, os.ErrNotExist) && missingOK {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	items, err := extractRawOutbounds(raw)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if item.Outbound.Protocol != "vless" || !strings.HasPrefix(item.Outbound.Tag, "manual-") || validateVLESSOutbound(item.Outbound) != "" {
			return nil, errors.New("manual VLESS store contains an invalid outbound")
		}
	}
	return items, nil
}

func safeManualServers(items []rawOutbound) ([]ManualServer, error) {
	servers := make([]ManualServer, 0, len(items))
	for _, item := range items {
		if len(item.Outbound.Settings.VNext) != 1 {
			return nil, errors.New("manual VLESS store contains an invalid server")
		}
		server := item.Outbound.Settings.VNext[0]
		name := strings.TrimPrefix(item.Outbound.Tag, "manual-")
		if index := strings.LastIndex(name, "-"); index > 0 {
			name = name[:index]
		}
		servers = append(servers, ManualServer{
			ID: item.Outbound.Tag, Name: name, Address: server.Address, Port: server.Port,
			Protocol: "vless", Security: item.Outbound.StreamSettings.Security, Network: item.Outbound.StreamSettings.Network,
		})
	}
	return servers, nil
}

func storeManualOutbounds(path string, items []rawOutbound) error {
	if !filepath.IsAbs(path) {
		return errors.New("manual VLESS store path must be absolute")
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(parent) {
		return errors.New("manual VLESS store parent must not contain symlinks")
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("manual VLESS store is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	outbounds := make([]json.RawMessage, 0, len(items))
	for _, item := range items {
		outbounds = append(outbounds, append(json.RawMessage(nil), item.Raw...))
	}
	raw, err := json.Marshal(map[string]any{"outbounds": outbounds})
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writeFileAtomic(path, raw, 0o600)
}
