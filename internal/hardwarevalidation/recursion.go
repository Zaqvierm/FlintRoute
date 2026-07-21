package hardwarevalidation

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"router-policy/internal/probe"
)

const recursionBypassComment = `comment "rp action=xray_recursion_bypass"`

type ProxyRecursionOptions struct {
	RunDir  string
	Route   string
	Domain  string
	Service string
}

type ProxyRecursionResult struct {
	CheckedAt             string `json:"checked_at"`
	Route                 string `json:"route"`
	BypassMark            string `json:"bypass_mark"`
	ProtectedOutbounds    int    `json:"protected_outbounds"`
	PreroutingRulePresent bool   `json:"prerouting_rule_present"`
	OutputRulePresent     bool   `json:"output_rule_present"`
	OutputPacketsBefore   uint64 `json:"output_packets_before"`
	OutputPacketsAfter    uint64 `json:"output_packets_after"`
	VLESSProbeVerified    bool   `json:"vless_probe_verified"`
	Passed                bool   `json:"passed"`
	Reason                string `json:"reason,omitempty"`
}

type recursionConfig struct {
	Xray struct {
		ActiveConfig string `json:"active_config"`
	} `json:"xray"`
	OpenWrt struct {
		NFTFamily      string `json:"nft_family"`
		NFTTable       string `json:"nft_table"`
		XrayBypassMark string `json:"xray_bypass_mark"`
	} `json:"openwrt"`
	Routes []struct {
		Type string `json:"type"`
		Tag  string `json:"tag"`
	} `json:"routes"`
}

// VerifyProxyRecursion proves that the installed Xray config marks every real
// outbound, nftables bypasses that mark before policy classification, and a
// live VLESS probe increments the bypass counter. Endpoint addresses are never
// written to the evidence bundle.
func (h Harness) VerifyProxyRecursion(ctx context.Context, options ProxyRecursionOptions) (ProxyRecursionResult, error) {
	result := ProxyRecursionResult{CheckedAt: h.now().Format("2006-01-02T15:04:05Z07:00"), Route: options.Route}
	finish := func(reason string) (ProxyRecursionResult, error) {
		result.Reason = reason
		if err := writeJSON(options.RunDir+string(os.PathSeparator)+"proxy-recursion.json", result); err != nil {
			return result, err
		}
		if reason != "" {
			return result, errors.New(reason)
		}
		return result, nil
	}
	if h.Runner == nil {
		return result, errors.New("runner is required")
	}
	if err := ensureRunDir(options.RunDir); err != nil {
		return result, err
	}
	for name, value := range map[string]string{"route": options.Route, "domain": options.Domain, "service": options.Service} {
		if value == "" || !caseIDPattern.MatchString(strings.ToLower(value)) {
			return finish(fmt.Sprintf("invalid %s", name))
		}
	}

	rawConfig, err := readBounded(h.Paths.Config, maxCasesBytes)
	if err != nil {
		return finish("active config cannot be read")
	}
	var cfg recursionConfig
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return finish("active config is invalid JSON")
	}
	if cfg.Xray.ActiveConfig == "" || cfg.OpenWrt.NFTFamily == "" || cfg.OpenWrt.NFTTable == "" {
		return finish("recursion protection config is incomplete")
	}
	mark, err := parseBypassMark(cfg.OpenWrt.XrayBypassMark)
	if err != nil {
		return finish("Xray bypass mark is invalid")
	}
	result.BypassMark = cfg.OpenWrt.XrayBypassMark
	foundRoute := false
	for _, route := range cfg.Routes {
		if route.Tag == options.Route && route.Type == "vless" {
			foundRoute = true
			break
		}
	}
	if !foundRoute {
		return finish("selected recursion probe route is not VLESS")
	}

	protected, targetProtected, err := inspectXrayOutboundMarks(cfg.Xray.ActiveConfig, options.Route, mark)
	if err != nil {
		return finish(err.Error())
	}
	result.ProtectedOutbounds = protected
	if !targetProtected {
		return finish("selected VLESS outbound lacks the bypass mark")
	}

	prerouting, err := h.Runner.Run(ctx, h.Paths.NftBinary, "list", "chain", cfg.OpenWrt.NFTFamily, cfg.OpenWrt.NFTTable, "rp_prerouting")
	if err != nil {
		return finish("cannot inspect prerouting recursion guard")
	}
	result.PreroutingRulePresent = strings.Contains(string(prerouting), recursionBypassComment)
	beforeRaw, err := h.Runner.Run(ctx, h.Paths.NftBinary, "list", "chain", cfg.OpenWrt.NFTFamily, cfg.OpenWrt.NFTTable, "probe_output")
	if err != nil {
		return finish("cannot inspect output recursion guard")
	}
	before, present, err := recursionBypassPackets(beforeRaw)
	if err != nil {
		return finish("cannot parse output recursion guard counter")
	}
	result.OutputRulePresent = present
	result.OutputPacketsBefore = before
	if !result.PreroutingRulePresent || !result.OutputRulePresent {
		return finish("live nftables recursion guard is incomplete")
	}

	probeRaw, err := h.Runner.Run(ctx, h.Paths.RouterPolicy, "probe-route", "--no-persist", "--route", options.Route, options.Domain, options.Service)
	if err != nil {
		return finish("VLESS recursion probe command failed")
	}
	var routeResult probe.RouteResult
	if err := json.Unmarshal(probeRaw, &routeResult); err != nil {
		return finish("VLESS recursion probe returned invalid JSON")
	}
	result.VLESSProbeVerified = routeResult.Status == "OK" && routeResult.PathVerified && !routeResult.Simulation && routeResult.RouteType == "vless" && routeResult.PathEvidence != nil && routeResult.PathEvidence.RouteType == "vless" && routeResult.PathEvidence.RouteTag == options.Route && routeResult.PathEvidence.XrayOutboundTag == options.Route && routeResult.PathEvidence.SOCKS5Loopback
	if !result.VLESSProbeVerified {
		return finish("VLESS recursion probe lacks bound path evidence")
	}

	afterRaw, err := h.Runner.Run(ctx, h.Paths.NftBinary, "list", "chain", cfg.OpenWrt.NFTFamily, cfg.OpenWrt.NFTTable, "probe_output")
	if err != nil {
		return finish("cannot re-read output recursion guard")
	}
	after, present, err := recursionBypassPackets(afterRaw)
	if err != nil || !present {
		return finish("output recursion guard disappeared after probe")
	}
	result.OutputPacketsAfter = after
	if after <= before {
		return finish("live VLESS traffic did not hit the recursion bypass")
	}
	result.Passed = true
	return finish("")
}

func inspectXrayOutboundMarks(path, targetTag string, expected uint64) (int, bool, error) {
	raw, err := readBounded(path, maxCommandOutput)
	if err != nil {
		return 0, false, errors.New("active Xray config cannot be read")
	}
	var cfg struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return 0, false, errors.New("active Xray config is invalid JSON")
	}
	if len(cfg.Outbounds) == 0 {
		return 0, false, errors.New("active Xray config has no outbounds")
	}
	protected := 0
	targetProtected := false
	for _, rawOutbound := range cfg.Outbounds {
		var outbound struct {
			Tag            string `json:"tag"`
			Protocol       string `json:"protocol"`
			StreamSettings struct {
				Sockopt struct {
					Mark json.Number `json:"mark"`
				} `json:"sockopt"`
			} `json:"streamSettings"`
		}
		decoder := json.NewDecoder(strings.NewReader(string(rawOutbound)))
		decoder.UseNumber()
		if err := decoder.Decode(&outbound); err != nil || outbound.Tag == "" || outbound.Protocol == "" {
			return 0, false, errors.New("active Xray config has an invalid outbound")
		}
		if outbound.Protocol == "blackhole" {
			continue
		}
		value, err := strconv.ParseUint(outbound.StreamSettings.Sockopt.Mark.String(), 10, 64)
		if err != nil || value != expected {
			return 0, false, fmt.Errorf("Xray outbound %s lacks the configured bypass mark", outbound.Tag)
		}
		protected++
		if outbound.Tag == targetTag && outbound.Protocol == "vless" {
			targetProtected = true
		}
	}
	return protected, targetProtected, nil
}

func parseBypassMark(value string) (uint64, error) {
	if !strings.HasPrefix(value, "0x") || len(value) <= 2 {
		return 0, errors.New("invalid mark")
	}
	return strconv.ParseUint(value[2:], 16, 32)
}

func recursionBypassPackets(raw []byte) (uint64, bool, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, recursionBypassComment) {
			continue
		}
		fields := strings.Fields(line)
		for index := 0; index+2 < len(fields); index++ {
			if fields[index] == "counter" && fields[index+1] == "packets" {
				packets, err := strconv.ParseUint(fields[index+2], 10, 64)
				return packets, true, err
			}
		}
		return 0, true, errors.New("counter is missing")
	}
	return 0, false, scanner.Err()
}
