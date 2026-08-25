// Package zapretprofile contains the typed, offline model for multiple
// device-scoped nfqws profiles. It has no process, shell, nft or filesystem
// side effects. Production activation remains a separate ownership-gated
// operation.
package zapretprofile

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	StrategyTLSFakeTTL3         = "tls-fake-ttl3-v1"
	StrategyTVFakeMultidisorder = "tv-fake-multidisorder-v1"
)

var (
	idPattern    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	tokenPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,63}$`)
)

type Scope struct {
	IPv4 string `json:"ipv4,omitempty"`
	MAC  string `json:"mac,omitempty"`
}

type PortRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type Rule struct {
	Protocol           string      `json:"protocol"`
	Ports              []PortRange `json:"ports"`
	Verdict            string      `json:"verdict"`
	ConntrackFirstPack int         `json:"conntrack_first_packets,omitempty"`
}

type Profile struct {
	ID           string `json:"id"`
	Scope        Scope  `json:"scope"`
	QueueNum     int    `json:"queue_num"`
	Strategy     string `json:"strategy"`
	Binary       string `json:"binary"`
	ActiveConfig string `json:"active_config"`
	InitScript   string `json:"init_script"`
	Rules        []Rule `json:"rules"`
}

func (s Scope) Validate() error {
	if (s.IPv4 == "") == (s.MAC == "") {
		return errors.New("scope must contain exactly one IPv4 or MAC selector")
	}
	if s.IPv4 != "" {
		addr, err := netip.ParseAddr(s.IPv4)
		if err != nil || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLoopback() || addr.BitLen() != 32 {
			return errors.New("scope IPv4 selector is invalid")
		}
	}
	if s.MAC != "" {
		mac, err := net.ParseMAC(s.MAC)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
			return errors.New("scope MAC selector is invalid")
		}
	}
	return nil
}

func (p PortRange) Validate() error {
	if p.Start < 1 || p.Start > 65535 || p.End < p.Start || p.End > 65535 {
		return errors.New("port range is invalid")
	}
	return nil
}

func (r Rule) Validate() error {
	if r.Protocol != "tcp" && r.Protocol != "udp" {
		return errors.New("rule protocol must be tcp or udp")
	}
	if r.Verdict != "queue" && r.Verdict != "drop" {
		return errors.New("rule verdict must be queue or drop")
	}
	if len(r.Ports) == 0 || len(r.Ports) > 32 {
		return errors.New("rule port count is out of bounds")
	}
	if r.ConntrackFirstPack < 0 || r.ConntrackFirstPack > 64 {
		return errors.New("rule conntrack bound is out of bounds")
	}
	for _, port := range r.Ports {
		if err := port.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (p Profile) Validate() error {
	if !idPattern.MatchString(p.ID) {
		return errors.New("profile id is invalid")
	}
	if err := p.Scope.Validate(); err != nil {
		return fmt.Errorf("profile %s scope: %w", p.ID, err)
	}
	if p.QueueNum < 2 || p.QueueNum > 65535 {
		return fmt.Errorf("profile %s queue must be in 2..65535", p.ID)
	}
	if p.Binary != "/usr/bin/nfqws" {
		return fmt.Errorf("profile %s binary is not project-owned", p.ID)
	}
	if p.ActiveConfig != "/etc/router-policy/zapret/profiles/"+p.ID+".conf" {
		return fmt.Errorf("profile %s config path is not allowlisted", p.ID)
	}
	if p.InitScript != "/etc/init.d/router-policy-zapret-"+p.ID {
		return fmt.Errorf("profile %s init path is not allowlisted", p.ID)
	}
	switch p.Strategy {
	case StrategyTLSFakeTTL3, StrategyTVFakeMultidisorder:
	default:
		return fmt.Errorf("profile %s strategy is unsupported", p.ID)
	}
	if len(p.Rules) == 0 || len(p.Rules) > 16 {
		return fmt.Errorf("profile %s rule count is out of bounds", p.ID)
	}
	seen := map[string]bool{}
	for _, rule := range p.Rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("profile %s rule: %w", p.ID, err)
		}
		key := ruleKey(rule)
		if seen[key] {
			return fmt.Errorf("profile %s has duplicate rule", p.ID)
		}
		seen[key] = true
		if rule.Verdict == "queue" && rule.Protocol != "tcp" {
			return fmt.Errorf("profile %s may queue only TCP in the typed model", p.ID)
		}
		if rule.Verdict == "drop" && rule.Protocol != "udp" {
			return fmt.Errorf("profile %s may drop only UDP in the typed model", p.ID)
		}
	}
	return nil
}

func ValidateProfiles(profiles []Profile) error {
	if len(profiles) == 0 {
		return errors.New("at least one profile is required")
	}
	if len(profiles) > 16 {
		return errors.New("profile count exceeds 16")
	}
	seenIDs := map[string]bool{}
	seenQueues := map[int]string{}
	seenScopes := map[string]string{}
	for _, profile := range profiles {
		if err := profile.Validate(); err != nil {
			return err
		}
		if seenIDs[profile.ID] {
			return fmt.Errorf("duplicate profile id %s", profile.ID)
		}
		if previous := seenQueues[profile.QueueNum]; previous != "" {
			return fmt.Errorf("queue %d is shared by %s and %s", profile.QueueNum, previous, profile.ID)
		}
		selector := profile.Scope.IPv4 + "|" + strings.ToLower(profile.Scope.MAC)
		if previous := seenScopes[selector]; previous != "" {
			return fmt.Errorf("device selector is shared by %s and %s", previous, profile.ID)
		}
		seenIDs[profile.ID] = true
		seenQueues[profile.QueueNum] = profile.ID
		seenScopes[selector] = profile.ID
	}
	return nil
}

func RenderNft(family, table, generation string, profiles []Profile) (string, error) {
	if family != "inet" || !tokenPattern.MatchString(table) || !tokenPattern.MatchString(generation) {
		return "", errors.New("nft identity is invalid")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table %s %s {\n", family, table)
	fmt.Fprintf(&b, "  comment \"router-policy owner=flintroute generation=%s\"\n", generation)
	rules, err := RenderRules(profiles)
	if err != nil {
		return "", err
	}
	b.WriteString(rules)
	b.WriteString("}\n")
	return b.String(), nil
}

// RenderRules returns the owned postrouting chain for device-scoped profiles.
// The caller embeds this chain in the single FlintRoute nft table; it must not
// be installed as a second table because table replacement is the transaction
// boundary and foreign tables are never owned by FlintRoute.
func RenderRules(profiles []Profile) (string, error) {
	if err := ValidateProfiles(profiles); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("  chain rp_zapret_device {\n")
	b.WriteString("    type filter hook postrouting priority mangle; policy accept;\n")
	for _, profile := range profiles {
		for _, rule := range profile.Rules {
			ports := renderPorts(rule.Ports)
			selector := renderSelector(profile.Scope)
			ct := ""
			if rule.ConntrackFirstPack > 0 {
				ct = fmt.Sprintf(" ct original packets 1-%d", rule.ConntrackFirstPack)
			}
			if rule.Verdict == "drop" {
				fmt.Fprintf(&b, "    %s %s dport %s%s counter drop comment \"router-policy profile=%s action=drop\"\n", selector, rule.Protocol, ports, ct, profile.ID)
				continue
			}
			fmt.Fprintf(&b, "    %s %s dport %s%s counter queue flags bypass to %d comment \"router-policy profile=%s action=queue\"\n", selector, rule.Protocol, ports, ct, profile.QueueNum, profile.ID)
		}
	}
	b.WriteString("  }\n")
	return b.String(), nil
}

func RenderNFQWS(profile Profile) ([]string, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	args := []string{"--qnum=" + strconv.Itoa(profile.QueueNum)}
	switch profile.Strategy {
	case StrategyTLSFakeTTL3:
		args = append(args,
			"--filter-tcp=80,443",
			"--dpi-desync=fake,fakedsplit",
			"--dpi-desync-split-pos=method+2",
			"--dpi-desync-fooling=md5sig",
		)
	case StrategyTVFakeMultidisorder:
		args = append(args,
			"--filter-tcp="+renderPorts(profile.queuePorts()),
			"--dpi-desync=fake,multidisorder",
			"--dpi-desync-split-pos=1,midsld",
			"--dpi-desync-fooling=badseq,md5sig",
		)
	}
	return args, nil
}

// RenderConfig produces the exact line-oriented @config consumed by nfqws.
// It is intentionally generated from the validated typed profile and never
// accepts a shell fragment or arbitrary executable argument.
func RenderConfig(profile Profile) ([]byte, error) {
	args, err := RenderNFQWS(profile)
	if err != nil {
		return nil, err
	}
	return []byte(strings.Join(args, "\n") + "\n"), nil
}

// RenderInitScript produces a fixed procd owner for one device-scoped queue.
// The profile ID is validated before interpolation and all paths remain in the
// allowlisted FlintRoute roots.
func RenderInitScript(profile Profile) ([]byte, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf(`#!/bin/sh /etc/rc.common

USE_PROCD=1
START=95
STOP=11

PROG="/usr/bin/nfqws"
CONFIG="/etc/router-policy/zapret/profiles/%s.conf"

start_service() {
	[ -x "$PROG" ] || return 1
	[ -s "$CONFIG" ] || return 1
	procd_open_instance router-policy-zapret-%s
	procd_set_param command "$PROG" "@$CONFIG"
	procd_set_param file "$CONFIG"
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_set_param respawn 3600 5 5
	procd_close_instance
}

reload_service() {
	stop
	start
}
`, profile.ID, profile.ID)), nil
}

func (p Profile) queuePorts() []PortRange {
	ports := make([]PortRange, 0)
	for _, rule := range p.Rules {
		if rule.Verdict == "queue" && rule.Protocol == "tcp" {
			ports = append(ports, rule.Ports...)
		}
	}
	return ports
}

func ruleKey(rule Rule) string {
	return rule.Protocol + ":" + rule.Verdict + ":" + renderPorts(rule.Ports) + ":" + strconv.Itoa(rule.ConntrackFirstPack)
}

func renderSelector(scope Scope) string {
	if scope.IPv4 != "" {
		return "ip saddr " + scope.IPv4
	}
	return "ether saddr " + strings.ToLower(scope.MAC)
}

func renderPorts(ports []PortRange) string {
	values := make([]string, 0, len(ports))
	for _, port := range ports {
		if port.Start == port.End {
			values = append(values, strconv.Itoa(port.Start))
		} else {
			values = append(values, strconv.Itoa(port.Start)+"-"+strconv.Itoa(port.End))
		}
	}
	sort.Strings(values)
	if len(values) == 1 {
		return values[0]
	}
	return "{" + strings.Join(values, ", ") + "}"
}
