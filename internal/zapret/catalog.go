package zapret

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	MaxProfiles      = 16
	MaxStrategyBytes = 16 * 1024
	maxStrategyLines = 64
)

var (
	profileIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	versionPattern   = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,2}$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	valuePattern     = regexp.MustCompile(`^[A-Za-z0-9,+._-]+$`)
	allowedOptions   = map[string]bool{
		"--qnum": true, "--filter-tcp": true, "--filter-udp": true,
		"--dpi-desync": true, "--dpi-desync-split-pos": true,
		"--dpi-desync-fooling": true, "--dpi-desync-ttl": true,
		"--orig-ttl": true, "--orig-mod-start": true, "--orig-mod-cutoff": true,
	}
)

type Profile struct {
	ID              string   `json:"id"`
	Provider        string   `json:"provider"`
	ProviderVersion string   `json:"provider_version"`
	BinaryDigest    string   `json:"binary_digest"`
	RouteType       string   `json:"route_type"`
	IPFamilies      []string `json:"ip_families"`
	Transports      []string `json:"transports"`
	Ports           []uint16 `json:"ports"`
	Queue           uint16   `json:"queue"`
	Safety          string   `json:"safety"`
	StrategyDigest  string   `json:"strategy_digest"`
	Strategy        []byte   `json:"-"`
}

type Catalog struct {
	profiles map[string]Profile
}

func NewCatalog(profiles []Profile) (*Catalog, error) {
	if len(profiles) == 0 {
		return nil, errors.New("Zapret catalog must contain at least one profile")
	}
	if len(profiles) > MaxProfiles {
		return nil, fmt.Errorf("Zapret catalog exceeds %d profiles", MaxProfiles)
	}
	catalog := &Catalog{profiles: make(map[string]Profile, len(profiles))}
	for _, profile := range profiles {
		if err := validateProfile(profile); err != nil {
			return nil, fmt.Errorf("profile %q: %w", profile.ID, err)
		}
		if _, exists := catalog.profiles[profile.ID]; exists {
			return nil, fmt.Errorf("duplicate Zapret profile %q", profile.ID)
		}
		catalog.profiles[profile.ID] = cloneProfile(profile)
	}
	return catalog, nil
}

func (c *Catalog) Lookup(id string) (Profile, bool) {
	if c == nil {
		return Profile{}, false
	}
	profile, ok := c.profiles[id]
	if !ok {
		return Profile{}, false
	}
	return cloneProfile(profile), true
}

func (c *Catalog) Len() int {
	if c == nil {
		return 0
	}
	return len(c.profiles)
}

func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validateProfile(profile Profile) error {
	if !profileIDPattern.MatchString(profile.ID) {
		return errors.New("invalid profile ID")
	}
	if profile.Provider != "nfqws-v1" {
		return errors.New("unsupported provider")
	}
	if !versionPattern.MatchString(profile.ProviderVersion) {
		return errors.New("invalid provider version")
	}
	if !digestPattern.MatchString(profile.BinaryDigest) || !digestPattern.MatchString(profile.StrategyDigest) {
		return errors.New("binary and strategy SHA-256 pins are required")
	}
	if profile.RouteType != "zapret" || profile.Safety != "reviewed" {
		return errors.New("profile must be a reviewed Zapret route")
	}
	if profile.Queue == 0 || len(profile.IPFamilies) == 0 || len(profile.Transports) == 0 || len(profile.Ports) == 0 {
		return errors.New("queue, address families, transports and ports are required")
	}
	if err := validateSet(profile.IPFamilies, map[string]bool{"ipv4": true, "ipv6": true}, "IP family"); err != nil {
		return err
	}
	if err := validateSet(profile.Transports, map[string]bool{"tcp": true, "udp": true}, "transport"); err != nil {
		return err
	}
	for _, port := range profile.Ports {
		if port == 0 {
			return errors.New("port 0 is not allowed")
		}
	}
	if err := validatePorts(profile.Ports); err != nil {
		return err
	}
	if Digest(profile.Strategy) != profile.StrategyDigest {
		return errors.New("strategy digest mismatch")
	}
	return validateStrategy(profile.Strategy, profile.Queue, profile.Transports, profile.Ports)
}

func validateSet(values []string, allowed map[string]bool, label string) error {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if !allowed[value] {
			return fmt.Errorf("unsupported %s %q", label, value)
		}
		if seen[value] {
			return fmt.Errorf("duplicate %s %q", label, value)
		}
		seen[value] = true
	}
	return nil
}

func validatePorts(ports []uint16) error {
	seen := make(map[uint16]bool, len(ports))
	for _, port := range ports {
		if seen[port] {
			return fmt.Errorf("duplicate port %d", port)
		}
		seen[port] = true
	}
	return nil
}

func validateStrategy(raw []byte, queue uint16, transports []string, ports []uint16) error {
	if len(raw) == 0 || len(raw) > MaxStrategyBytes || strings.ContainsRune(string(raw), '\r') {
		return errors.New("strategy size or line endings are invalid")
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) == 0 || len(lines) > maxStrategyLines {
		return errors.New("strategy line count is invalid")
	}
	queueSeen := false
	filterTransports := make(map[string]bool)
	filterPorts := make(map[uint16]bool)
	for index, line := range lines {
		if line == "--new" {
			if index == 0 || index == len(lines)-1 || lines[index-1] == "--new" {
				return errors.New("strategy profile separator is misplaced")
			}
			continue
		}
		if line == "" || strings.ContainsAny(line, " \t;&|`$\\/@") {
			return fmt.Errorf("unsafe strategy line %q", line)
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !allowedOptions[key] || !valuePattern.MatchString(value) {
			return fmt.Errorf("unsupported strategy option %q", line)
		}
		if key == "--qnum" {
			if queueSeen {
				return errors.New("duplicate queue option")
			}
			parsed, err := strconv.ParseUint(value, 10, 16)
			if err != nil || uint16(parsed) != queue {
				return errors.New("strategy queue does not match profile")
			}
			queueSeen = true
		}
		if key == "--filter-tcp" || key == "--filter-udp" {
			transport := strings.TrimPrefix(key, "--filter-")
			filterTransports[transport] = true
			for _, rawPort := range strings.Split(value, ",") {
				parsed, err := strconv.ParseUint(rawPort, 10, 16)
				if err != nil || parsed == 0 {
					return fmt.Errorf("invalid %s filter port %q", transport, rawPort)
				}
				filterPorts[uint16(parsed)] = true
			}
		}
	}
	if !queueSeen {
		return errors.New("strategy queue is missing")
	}
	if !sameStringSet(filterTransports, transports) || !samePortSet(filterPorts, ports) {
		return errors.New("strategy filters do not match profile scope")
	}
	return nil
}

func sameStringSet(actual map[string]bool, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for _, value := range expected {
		if !actual[value] {
			return false
		}
	}
	return true
}

func samePortSet(actual map[uint16]bool, expected []uint16) bool {
	if len(actual) != len(expected) {
		return false
	}
	for _, value := range expected {
		if !actual[value] {
			return false
		}
	}
	return true
}

func cloneProfile(profile Profile) Profile {
	profile.IPFamilies = append([]string(nil), profile.IPFamilies...)
	profile.Transports = append([]string(nil), profile.Transports...)
	profile.Ports = append([]uint16(nil), profile.Ports...)
	profile.Strategy = append([]byte(nil), profile.Strategy...)
	return profile
}
