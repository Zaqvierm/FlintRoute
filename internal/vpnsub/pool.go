package vpnsub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type SubscriptionSource struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	ProviderID           string `json:"provider_id"`
	ProviderName         string `json:"provider_name"`
	AddedAt              string `json:"added_at,omitempty"`
	ExpiresAt            string `json:"expires_at,omitempty"`
	ExpiryKnown          bool   `json:"expiry_known"`
	ServerCount          int    `json:"server_count"`
	Manual               bool   `json:"manual,omitempty"`
	OriginalSourceMasked string `json:"original_source_masked,omitempty"`
	ResolvedSourceMasked string `json:"resolved_source_masked,omitempty"`
	SourceType           string `json:"source_type,omitempty"`
	CryptoVersion        string `json:"crypto_version,omitempty"`
	ResolutionStatus     string `json:"resolution_status,omitempty"`
}

type ProviderMatch struct {
	LeftProviderID  string  `json:"left_provider_id"`
	RightProviderID string  `json:"right_provider_id"`
	MatchedServers  int     `json:"matched_servers"`
	ComparedServers int     `json:"compared_servers"`
	Overlap         float64 `json:"overlap"`
	Recommendation  string  `json:"recommendation"`
}

type PoolSnapshot struct {
	GeneratedAt     string               `json:"generated_at"`
	BundleHash      string               `json:"bundle_hash,omitempty"`
	TariffMbps      float64              `json:"tariff_mbps"`
	Sources         []SubscriptionSource `json:"sources"`
	ProviderMatches []ProviderMatch      `json:"provider_matches,omitempty"`
	Servers         []ServerStatus       `json:"servers"`
}

type PoolSettings struct {
	TariffMbps float64 `json:"tariff_mbps"`
}

type ServerMetrics struct {
	PathVerified      bool
	LatencyMS         int64
	JitterMS          int64
	MeasuredMbps      float64
	TariffMbps        float64
	SuccessfulProbes  int
	FailedProbes      int
	ConsecutiveErrors int
	Quarantined       bool
}

type ScoreBreakdown struct {
	Total                float64 `json:"total"`
	Latency              float64 `json:"latency"`
	Jitter               float64 `json:"jitter"`
	Throughput           float64 `json:"throughput"`
	Stability            float64 `json:"stability"`
	EffectiveThroughput  float64 `json:"effective_throughput_mbps"`
	MeasuredThroughput   float64 `json:"measured_throughput_mbps"`
	ConfiguredTariffMbps float64 `json:"configured_tariff_mbps"`
	Eligible             bool    `json:"eligible"`
	Reason               string  `json:"reason,omitempty"`
}

func ScoreServer(metrics ServerMetrics) ScoreBreakdown {
	result := ScoreBreakdown{
		MeasuredThroughput: metrics.MeasuredMbps, ConfiguredTariffMbps: metrics.TariffMbps,
	}
	if !metrics.PathVerified {
		result.Reason = "path_not_verified"
		return result
	}
	if metrics.Quarantined {
		result.Reason = "server_quarantined"
		return result
	}
	if metrics.ConsecutiveErrors >= 3 {
		result.Reason = "consecutive_failures"
		return result
	}
	result.Eligible = true
	latency := float64(metrics.LatencyMS)
	if latency <= 0 {
		latency = 500
	}
	result.Latency = clamp(100-latency/3, 0, 100)
	result.Jitter = clamp(100-float64(metrics.JitterMS)*2, 0, 100)
	totalProbes := metrics.SuccessfulProbes + metrics.FailedProbes
	if totalProbes == 0 {
		result.Stability = 50
	} else {
		result.Stability = 100 * float64(metrics.SuccessfulProbes) / float64(totalProbes)
	}
	if metrics.TariffMbps > 0 && metrics.MeasuredMbps > 0 {
		result.EffectiveThroughput = minFloat(metrics.MeasuredMbps, metrics.TariffMbps)
		result.Throughput = clamp(100*result.EffectiveThroughput/metrics.TariffMbps, 0, 100)
	} else {
		result.Throughput = 50
	}
	result.Total = result.Latency*0.35 + result.Jitter*0.10 + result.Throughput*0.20 + result.Stability*0.35
	return result
}

func serverStatusFor(item rawOutbound) ServerStatus {
	status := ServerStatus{Tag: item.Outbound.Tag, LogicalID: "srv_" + prefix(item.Identity, 16), SourceCount: item.Sources}
	status.Name = strings.TrimSpace(item.Outbound.Remarks)
	if status.Name == "" {
		status.Name = strings.TrimSpace(item.Outbound.Tag)
	}
	if len(item.Outbound.Settings.VNext) == 1 {
		endpoint := item.Outbound.Settings.VNext[0]
		status.Hostname = strings.TrimSpace(endpoint.Address)
		status.Port = endpoint.Port
	}
	status.Transport = strings.TrimSpace(item.Outbound.StreamSettings.Network)
	status.Security = strings.TrimSpace(item.Outbound.StreamSettings.Security)
	status.Country, status.CountrySource = inferCountry(status.Name)
	return status
}

func enrichServerInventory(ctx context.Context, servers []ServerStatus, checks []OutboundCheck, selectedTag string, now time.Time, resolver func(context.Context, string) []string) []ServerStatus {
	checkByTag := make(map[string]OutboundCheck, len(checks))
	for _, check := range checks {
		checkByTag[check.Tag] = check
	}
	resolverCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for index := range servers {
		server := &servers[index]
		if resolver != nil {
			server.ResolvedIPs = resolver(resolverCtx, server.Hostname)
		}
		check, exists := checkByTag[server.Tag]
		server.LastCheckedAt = now.UTC().Format(time.RFC3339)
		if server.Country == "" && exists && check.ExternalCountry != "" && check.ExternalCountry != "UNKNOWN" {
			server.Country = check.ExternalCountry
			server.CountrySource = "verified_egress"
		}
		if !exists || check.Status != "OK" {
			server.Health = "failed"
			server.Quarantined = true
			server.FailedProbes = 1
			if exists && server.Reason == "" {
				server.Reason = check.Reason
			}
			continue
		}
		server.PathVerified = true
		server.LatencyMS = check.LatencyMS
		server.AverageMS = check.LatencyMS
		server.Health = healthLabel(check.LatencyMS)
		server.Selected = server.Tag == selectedTag
		server.Standby = !server.Selected
	}
	return servers
}

func resolveServerIPs(ctx context.Context, hostname string) []string {
	if address, err := netip.ParseAddr(hostname); err == nil {
		return []string{address.String()}
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", hostname)
	if err != nil {
		return nil
	}
	result := make([]string, 0, len(addresses))
	seen := map[string]bool{}
	for _, address := range addresses {
		if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
			continue
		}
		value := address.String()
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func analyzeSubscriptionSources(urls []string, paths []string, fetched []FetchSummary, now time.Time) ([]SubscriptionSource, []ProviderMatch, map[string][]string, error) {
	if len(urls) != len(paths) || len(paths) != len(fetched) {
		return nil, nil, nil, errors.New("subscription source analysis inputs do not match")
	}
	sources := make([]SubscriptionSource, 0, len(paths))
	serverSets := make([]map[string]bool, 0, len(paths))
	serverSources := make(map[string][]string)
	for index, path := range paths {
		raw, err := readSubscriptionFile(path)
		if err != nil {
			return nil, nil, nil, err
		}
		outbounds, err := extractRawOutbounds(raw)
		if err != nil {
			return nil, nil, nil, err
		}
		sourceID := "sub_" + shortHash(urls[index])
		set := map[string]bool{}
		for _, outbound := range outbounds {
			if outbound.Outbound.Protocol != "vless" {
				continue
			}
			identity, err := outboundIdentity(outbound.Raw)
			if err == nil {
				set[identity] = true
				logicalID := "srv_" + prefix(identity, 16)
				if !containsString(serverSources[logicalID], sourceID) {
					serverSources[logicalID] = append(serverSources[logicalID], sourceID)
				}
			}
		}
		originSource := urls[index]
		if fetched[index].ResolvedSource != "" {
			// Provider identity is derived from the resolved URL in memory. The
			// credential-bearing value is never exposed in the pool snapshot.
			originSource = fetched[index].ResolvedSource
		}
		parsed, _ := url.Parse(originSource)
		origin := strings.ToLower(parsed.Scheme + "://" + parsed.Host)
		providerName := fetched[index].ProviderName
		if providerName == "" {
			providerName = parsed.Hostname()
		}
		source := SubscriptionSource{
			ID: sourceID, Name: "Subscription " + itoa(index+1),
			ProviderID: "provider_" + shortHash(origin), ProviderName: providerName,
			AddedAt: now.UTC().Format(time.RFC3339), ExpiresAt: fetched[index].ExpiresAt,
			ExpiryKnown: fetched[index].ExpiresAt != "", ServerCount: len(set),
			OriginalSourceMasked: fetched[index].OriginalSourceMasked,
			ResolvedSourceMasked: fetched[index].ResolvedSourceMasked,
			SourceType:           fetched[index].SourceType, CryptoVersion: fetched[index].CryptoVersion,
			ResolutionStatus: "resolved",
		}
		sources = append(sources, source)
		serverSets = append(serverSets, set)
	}
	var matches []ProviderMatch
	for left := 0; left < len(sources); left++ {
		for right := left + 1; right < len(sources); right++ {
			if sources[left].ProviderID == sources[right].ProviderID {
				continue
			}
			matched := overlapCount(serverSets[left], serverSets[right])
			compared := minInt(len(serverSets[left]), len(serverSets[right]))
			if compared == 0 {
				continue
			}
			overlap := float64(matched) / float64(compared)
			if overlap >= 0.8 {
				matches = append(matches, ProviderMatch{
					LeftProviderID: sources[left].ProviderID, RightProviderID: sources[right].ProviderID,
					MatchedServers: matched, ComparedServers: compared, Overlap: overlap,
					Recommendation: "confirmation_required",
				})
			}
		}
	}
	for key := range serverSources {
		sort.Strings(serverSources[key])
	}
	return sources, matches, serverSources, nil
}

func attachServerSources(servers []ServerStatus, sourceIDs map[string][]string, tariffMbps float64) []ServerStatus {
	for index := range servers {
		server := &servers[index]
		server.SourceIDs = append([]string(nil), sourceIDs[server.LogicalID]...)
		if len(server.SourceIDs) > 0 {
			server.SourceCount = len(server.SourceIDs)
		}
		server.TariffMbps = tariffMbps
		breakdown := ScoreServer(ServerMetrics{
			PathVerified: server.PathVerified, LatencyMS: server.LatencyMS, JitterMS: server.JitterMS,
			MeasuredMbps: server.MeasuredMbps, TariffMbps: tariffMbps,
			SuccessfulProbes: boolInt(server.PathVerified), FailedProbes: server.FailedProbes,
			Quarantined: server.Quarantined,
		})
		server.EffectiveMbps = breakdown.EffectiveThroughput
		server.Score = breakdown.Total
		server.ScoreReason = breakdown.Reason
	}
	return servers
}

func RefreshPoolScores(servers []ServerStatus, tariffMbps float64) []ServerStatus {
	return attachServerSources(servers, serverSourceMap(servers), tariffMbps)
}

func serverSourceMap(servers []ServerStatus) map[string][]string {
	result := make(map[string][]string, len(servers))
	for _, server := range servers {
		result[server.LogicalID] = append([]string(nil), server.SourceIDs...)
	}
	return result
}

func StorePool(path string, snapshot PoolSnapshot) error {
	if !filepath.IsAbs(path) {
		return errors.New("VLESS pool path must be absolute")
	}
	raw, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(raw, '\n'), 0o600)
}

func LoadPool(path string) (PoolSnapshot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return PoolSnapshot{}, err
	}
	var snapshot PoolSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return PoolSnapshot{}, errors.New("VLESS pool snapshot is invalid")
	}
	return snapshot, nil
}

func PoolPath(stateDir string) string { return filepath.Join(stateDir, "xray", "pool.json") }

func PoolSettingsPath(stateDir string) string {
	return filepath.Join(stateDir, "xray", "pool-settings.json")
}

func LoadTariffMbps(stateDir string) float64 {
	raw, err := os.ReadFile(PoolSettingsPath(stateDir))
	if err != nil {
		return 300
	}
	var settings PoolSettings
	if json.Unmarshal(raw, &settings) != nil || settings.TariffMbps < 1 || settings.TariffMbps > 100000 {
		return 300
	}
	return settings.TariffMbps
}

func SaveTariffMbps(stateDir string, value float64) error {
	if value < 1 || value > 100000 {
		return errors.New("internet tariff speed must be between 1 and 100000 Mbps")
	}
	raw, err := json.Marshal(PoolSettings{TariffMbps: value})
	if err != nil {
		return err
	}
	return writeFileAtomic(PoolSettingsPath(stateDir), append(raw, '\n'), 0o600)
}

func inferCountry(name string) (string, string) {
	lower := " " + strings.ToLower(name) + " "
	countries := []struct {
		code  string
		words []string
	}{
		{"DE", []string{" germany ", " deutschland ", " frankfurt ", " berlin ", " de-", "[de]", "🇩🇪"}},
		{"NL", []string{" netherlands ", " amsterdam ", " nl-", "[nl]", "🇳🇱"}},
		{"FI", []string{" finland ", " helsinki ", " fi-", "[fi]", "🇫🇮"}},
		{"FR", []string{" france ", " paris ", " fr-", "[fr]", "🇫🇷"}},
		{"GB", []string{" united kingdom ", " london ", " uk-", "[gb]", "🇬🇧"}},
		{"US", []string{" united states ", " usa ", " new york ", " us-", "[us]", "🇺🇸"}},
		{"SE", []string{" sweden ", " stockholm ", " se-", "[se]", "🇸🇪"}},
		{"CH", []string{" switzerland ", " zurich ", " ch-", "[ch]", "🇨🇭"}},
	}
	for _, country := range countries {
		for _, word := range country.words {
			if strings.Contains(lower, word) {
				return country.code, "node_name"
			}
		}
	}
	return "", "unknown"
}

func healthLabel(latency int64) string {
	switch {
	case latency > 0 && latency <= 80:
		return "excellent"
	case latency <= 180:
		return "good"
	default:
		return "degraded"
	}
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func prefix(value string, length int) string {
	if len(value) <= length {
		return value
	}
	return value[:length]
}

func overlapCount(left, right map[string]bool) int {
	count := 0
	for value := range left {
		if right[value] {
			count++
		}
	}
	return count
}

func clamp(value, minimum, maximum float64) float64 {
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func minFloat(left, right float64) float64 {
	if left < right {
		return left
	}
	return right
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func itoa(value int) string {
	if value >= 0 && value <= 9 {
		return string(rune('0' + value))
	}
	return "source"
}
