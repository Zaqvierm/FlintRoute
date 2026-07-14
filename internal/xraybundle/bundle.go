package xraybundle

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"router-policy/internal/config"
)

const MaxBytes = 4 << 20

var (
	digestPattern = regexp.MustCompile(`^sha256:([0-9a-f]{64})$`)
	tagPattern    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

type Bundle struct {
	Raw       []byte
	Inbounds  []json.RawMessage
	Outbounds []json.RawMessage
	Rules     []json.RawMessage
}

type inbound struct {
	Tag      string `json:"tag"`
	Listen   string `json:"listen"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type outbound struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
}

type rule struct {
	Type        string   `json:"type"`
	InboundTags []string `json:"inboundTag"`
	OutboundTag string   `json:"outboundTag"`
}

func Path(stateDir, digest string) (string, error) {
	match := digestPattern.FindStringSubmatch(digest)
	if strings.TrimSpace(stateDir) == "" || len(match) != 2 {
		return "", errors.New("valid state directory and Xray bundle SHA-256 are required")
	}
	return filepath.Join(stateDir, "xray", "bundles", match[1]+".json"), nil
}

func Store(stateDir, sourcePath, digest string) (string, error) {
	raw, err := readRegularSecret(sourcePath)
	if err != nil {
		return "", err
	}
	if Hash(raw) != digest {
		return "", errors.New("Xray bundle hash mismatch")
	}
	if _, err := parse(raw); err != nil {
		return "", err
	}
	target, err := Path(stateDir, digest)
	if err != nil {
		return "", err
	}
	if err := writeAtomic(target, raw); err != nil {
		return "", err
	}
	return target, nil
}

func Load(stateDir, digest string) (Bundle, error) {
	path, err := Path(stateDir, digest)
	if err != nil {
		return Bundle{}, err
	}
	raw, err := readRegularSecret(path)
	if err != nil {
		return Bundle{}, err
	}
	if Hash(raw) != digest {
		return Bundle{}, errors.New("Xray bundle hash mismatch")
	}
	return parse(raw)
}

func ValidateRoutes(bundle Bundle, routes []config.Route) error {
	inboundByTag := make(map[string]inbound, len(bundle.Inbounds))
	portSeen := map[int]bool{}
	for _, raw := range bundle.Inbounds {
		var value inbound
		if err := json.Unmarshal(raw, &value); err != nil {
			return errors.New("invalid Xray bundle inbound")
		}
		if !tagPattern.MatchString(value.Tag) || value.Listen != "127.0.0.1" || value.Protocol != "socks" || value.Port < 1024 || value.Port > 65535 {
			return errors.New("unsafe Xray bundle inbound")
		}
		if _, exists := inboundByTag[value.Tag]; exists || portSeen[value.Port] {
			return errors.New("duplicate Xray bundle inbound")
		}
		inboundByTag[value.Tag] = value
		portSeen[value.Port] = true
	}

	outboundByTag := make(map[string]outbound, len(bundle.Outbounds))
	for _, raw := range bundle.Outbounds {
		var value outbound
		if err := json.Unmarshal(raw, &value); err != nil {
			return errors.New("invalid Xray bundle outbound")
		}
		if !tagPattern.MatchString(value.Tag) || value.Protocol != "vless" {
			return errors.New("unsafe Xray bundle outbound")
		}
		if _, exists := outboundByTag[value.Tag]; exists {
			return errors.New("duplicate Xray bundle outbound")
		}
		outboundByTag[value.Tag] = value
	}
	if len(outboundByTag) == 0 || len(inboundByTag) != len(outboundByTag) || len(bundle.Rules) != len(outboundByTag) {
		return errors.New("incomplete Xray bundle topology")
	}

	ruleByOutbound := make(map[string]string, len(bundle.Rules))
	for _, raw := range bundle.Rules {
		var value rule
		if err := json.Unmarshal(raw, &value); err != nil || value.Type != "field" || len(value.InboundTags) != 1 {
			return errors.New("invalid Xray bundle routing rule")
		}
		inboundTag := value.InboundTags[0]
		if _, ok := inboundByTag[inboundTag]; !ok {
			return errors.New("Xray bundle rule references unknown inbound")
		}
		if _, ok := outboundByTag[value.OutboundTag]; !ok {
			return errors.New("Xray bundle rule references unknown outbound")
		}
		if _, exists := ruleByOutbound[value.OutboundTag]; exists {
			return errors.New("duplicate Xray bundle routing rule")
		}
		ruleByOutbound[value.OutboundTag] = inboundTag
	}

	vlessRoutes := map[string]config.Route{}
	for _, route := range routes {
		if route.Type != "vless" {
			continue
		}
		if _, exists := vlessRoutes[route.Tag]; exists {
			return errors.New("duplicate VLESS route")
		}
		vlessRoutes[route.Tag] = route
	}
	if len(vlessRoutes) != len(outboundByTag) {
		return errors.New("candidate VLESS routes do not match Xray bundle")
	}
	for tag, route := range vlessRoutes {
		if _, ok := outboundByTag[tag]; !ok {
			return fmt.Errorf("candidate VLESS route %s is absent from Xray bundle", tag)
		}
		inboundTag, ok := ruleByOutbound[tag]
		if !ok || inboundTag != "socks-"+tag {
			return fmt.Errorf("Xray bundle route %s has no bound SOCKS inbound", tag)
		}
		host, portText, err := net.SplitHostPort(route.SOCKS5)
		if err != nil || host != "127.0.0.1" {
			return fmt.Errorf("candidate VLESS route %s has unsafe SOCKS address", tag)
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port != inboundByTag[inboundTag].Port {
			return fmt.Errorf("candidate VLESS route %s SOCKS port does not match bundle", tag)
		}
	}
	return nil
}

func Hash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func parse(raw []byte) (Bundle, error) {
	var root struct {
		Inbounds  []json.RawMessage `json:"inbounds"`
		Outbounds []json.RawMessage `json:"outbounds"`
		Routing   struct {
			Rules []json.RawMessage `json:"rules"`
		} `json:"routing"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&root); err != nil {
		return Bundle{}, errors.New("invalid Xray bundle JSON")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Bundle{}, errors.New("trailing data in Xray bundle")
	}
	if len(root.Inbounds) == 0 || len(root.Outbounds) == 0 || len(root.Routing.Rules) == 0 {
		return Bundle{}, errors.New("incomplete Xray bundle")
	}
	return Bundle{Raw: append([]byte(nil), raw...), Inbounds: root.Inbounds, Outbounds: root.Outbounds, Rules: root.Routing.Rules}, nil
}

func readRegularSecret(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("Xray bundle must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > MaxBytes {
		return nil, errors.New("Xray bundle size limit exceeded")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return nil, errors.New("Xray bundle must have mode 0600")
	}
	return os.ReadFile(path)
}

func writeAtomic(path string, raw []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	tmp := path + ".tmp." + hex.EncodeToString(random)
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := file.Write(raw); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	remove = false
	return nil
}
