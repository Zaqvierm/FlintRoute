package vpnsub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/xraybundle"
)

type CheckerFactory func(*config.Config, config.Service) OutboundChecker

type SubscriptionService struct {
	Runner         XrayRunner
	HTTPClient     *http.Client
	CheckerFactory CheckerFactory
	Parallelism    int
	CheckAttempts  int
	SpeedTester    ThroughputTester
}

func (s *SubscriptionService) Prepare(ctx context.Context, cfg *config.Config) (PreparedBundle, error) {
	if s == nil || s.Runner == nil || cfg == nil {
		return PreparedBundle{}, errors.New("VPN subscription service is not configured")
	}
	if cfg.Storage.StateDir == "" || cfg.Xray.SubscriptionSecretFile == "" {
		return PreparedBundle{}, errors.New("VPN subscription paths are not configured")
	}
	probeService, err := subscriptionProbeService(cfg)
	if err != nil {
		return PreparedBundle{}, err
	}
	checkerFactory := s.CheckerFactory
	if checkerFactory == nil {
		checkerFactory = func(active *config.Config, service config.Service) OutboundChecker {
			return EngineOutboundChecker{Config: active, Service: service}
		}
	}
	checker := checkerFactory(cfg, probeService)
	if checker == nil {
		return PreparedBundle{}, errors.New("VPN subscription outbound checker is not configured")
	}

	downloadRoot := filepath.Join(cfg.Storage.StateDir, "xray", "downloads")
	if err := os.MkdirAll(downloadRoot, 0o700); err != nil {
		return PreparedBundle{}, err
	}
	temporaryDir, err := os.MkdirTemp(downloadRoot, ".prepare-")
	if err != nil {
		return PreparedBundle{}, err
	}
	defer os.RemoveAll(temporaryDir)
	if err := os.Chmod(temporaryDir, 0o700); err != nil {
		return PreparedBundle{}, err
	}

	subscriptionURLs := []string{}
	if info, statErr := os.Lstat(cfg.Xray.SubscriptionSecretFile); statErr == nil && info.Size() > 0 {
		subscriptionURLs, err = ReadSubscriptionURLFiles(cfg.Xray.SubscriptionSecretFile)
		if err != nil {
			return PreparedBundle{}, errors.New("VPN subscription secret file is invalid")
		}
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return PreparedBundle{}, errors.New("VPN subscription secret file is invalid")
	}
	maxBytes := cfg.Policy.MaxSubscriptionBytes
	if maxBytes <= 0 || maxBytes > maxSubscriptionFileBytes {
		maxBytes = maxSubscriptionFileBytes
	}
	timeout := time.Duration(cfg.Policy.MaxProbeSeconds) * time.Second
	if timeout <= 0 || timeout > time.Minute {
		timeout = 30 * time.Second
	}
	downloadPaths := make([]string, 0, len(subscriptionURLs))
	fetchSummaries := make([]FetchSummary, 0, len(subscriptionURLs))
	totalBytes := 0
	for index, subscriptionURL := range subscriptionURLs {
		downloadPath := filepath.Join(temporaryDir, fmt.Sprintf("subscription-%d.json", index+1))
		fetched, err := FetchSubscription(ctx, s.HTTPClient, subscriptionURL, downloadPath, FetchOptions{MaxBytes: maxBytes, MaxRedirects: 3, Timeout: timeout})
		if err != nil {
			return PreparedBundle{}, fmt.Errorf("VPN subscription source %d failed: %w", index+1, err)
		}
		totalBytes += fetched.Bytes
		downloadPaths = append(downloadPaths, downloadPath)
		fetchSummaries = append(fetchSummaries, fetched)
	}
	sources, providerMatches, serverSources, err := analyzeSubscriptionSources(subscriptionURLs, downloadPaths, fetchSummaries, time.Now().UTC())
	if err != nil {
		return PreparedBundle{}, err
	}
	manualPath := ManualServersPath(cfg.Storage.StateDir)
	if info, statErr := os.Lstat(manualPath); statErr == nil && info.Size() > 0 {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return PreparedBundle{}, errors.New("manual VLESS store is unsafe")
		}
		if _, err := ListManualServers(manualPath); err != nil {
			return PreparedBundle{}, errors.New("manual VLESS store is invalid")
		}
		downloadPaths = append(downloadPaths, manualPath)
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return PreparedBundle{}, errors.New("manual VLESS store is invalid")
	}
	mergedPath := filepath.Join(temporaryDir, "subscription-merged.json")
	mergedHash, err := mergeSubscriptionFiles(downloadPaths, mergedPath)
	if err != nil {
		return PreparedBundle{}, err
	}
	manager := Manager{
		StateDir: cfg.Storage.StateDir, Runner: s.Runner, Checker: checker,
		Parallelism: s.Parallelism, CheckAttempts: s.CheckAttempts, ResolveIPs: resolveServerIPs,
		SpeedTester: s.SpeedTester, TariffMbps: LoadTariffMbps(cfg.Storage.StateDir),
	}
	result, err := manager.PrepareBundle(ctx, mergedPath, cfg.Xray.ProbeSocksBasePort)
	if err != nil {
		return result, err
	}
	result.SubscriptionHash = mergedHash
	result.SubscriptionBytes = totalBytes
	result.Sources = sources
	result.ProviderMatches = providerMatches
	result.TariffMbps = LoadTariffMbps(cfg.Storage.StateDir)
	if info, statErr := os.Lstat(manualPath); statErr == nil && info.Size() > 0 {
		manualServers, listErr := ListManualServers(manualPath)
		if listErr != nil {
			return result, errors.New("manual VLESS store is invalid")
		}
		result.Sources = append(result.Sources, SubscriptionSource{ID: "manual", Name: "Manual servers", ProviderID: "manual", ProviderName: "Added manually", Manual: true, ServerCount: len(manualServers)})
		for _, server := range result.Servers {
			if strings.HasPrefix(server.Tag, "manual-") {
				serverSources[server.LogicalID] = []string{"manual"}
			}
		}
	}
	result.Servers = attachServerSources(result.Servers, serverSources, result.TariffMbps)
	snapshot := PoolSnapshot{GeneratedAt: time.Now().UTC().Format(time.RFC3339), BundleHash: result.BundleHash, TariffMbps: result.TariffMbps, Sources: result.Sources, ProviderMatches: result.ProviderMatches, Servers: result.Servers}
	if err := StorePool(PoolPath(cfg.Storage.StateDir), snapshot); err != nil {
		return result, err
	}
	return result, nil
}

// MeasureServer starts the content-addressed candidate bundle for the duration
// of one bounded measurement. Pool SOCKS listeners are candidate resources and
// must never be assumed to survive Prepare.
func (s *SubscriptionService) MeasureServer(ctx context.Context, cfg *config.Config, logicalID string) (SpeedMeasurement, ServerStatus, error) {
	if s == nil || s.Runner == nil || s.SpeedTester == nil || cfg == nil || cfg.Storage.StateDir == "" {
		return SpeedMeasurement{}, ServerStatus{}, errors.New("managed VLESS speed measurement is not configured")
	}
	snapshot, err := LoadPool(PoolPath(cfg.Storage.StateDir))
	if err != nil {
		return SpeedMeasurement{}, ServerStatus{}, errors.New("VLESS pool cannot be read; run server verification again")
	}
	index := -1
	for current := range snapshot.Servers {
		if snapshot.Servers[current].LogicalID == logicalID {
			index = current
			break
		}
	}
	if index < 0 || !snapshot.Servers[index].PathVerified {
		return SpeedMeasurement{}, ServerStatus{}, errors.New("selected VLESS server does not have a verified path")
	}
	host, _, splitErr := net.SplitHostPort(snapshot.Servers[index].SOCKS5)
	address, parseErr := netip.ParseAddr(host)
	if splitErr != nil || parseErr != nil || !address.IsLoopback() {
		return SpeedMeasurement{}, ServerStatus{}, errors.New("selected VLESS server is not bound to a loopback SOCKS endpoint")
	}
	var process CandidateProcess
	stopped := false
	defer func() {
		if process != nil && !stopped {
			_ = process.Stop(context.Background())
		}
	}()
	if cfg.Xray.ActivationMode != "managed" {
		if snapshot.BundleHash == "" {
			return SpeedMeasurement{}, ServerStatus{}, errors.New("VLESS pool has no verified bundle; run server verification again")
		}
		if _, err := xraybundle.Load(cfg.Storage.StateDir, snapshot.BundleHash); err != nil {
			return SpeedMeasurement{}, ServerStatus{}, errors.New("verified VLESS bundle is unavailable or corrupt")
		}
		bundlePath, err := xraybundle.Path(cfg.Storage.StateDir, snapshot.BundleHash)
		if err != nil {
			return SpeedMeasurement{}, ServerStatus{}, errors.New("verified VLESS bundle path is invalid")
		}
		if err := s.Runner.Test(ctx, bundlePath); err != nil {
			return SpeedMeasurement{}, ServerStatus{}, errors.New("verified VLESS bundle failed Xray validation")
		}
		process, err = s.Runner.StartCandidate(ctx, bundlePath)
		if err != nil {
			return SpeedMeasurement{}, ServerStatus{}, errors.New("VLESS measurement candidate could not start")
		}
		if err := s.Runner.WaitReady(ctx, snapshot.Servers); err != nil {
			return SpeedMeasurement{}, ServerStatus{}, errors.New("VLESS measurement candidate did not become ready")
		}
	}
	measurement, err := s.SpeedTester.Measure(ctx, snapshot.Servers[index].SOCKS5, SpeedTestBytes(snapshot.TariffMbps))
	if err != nil {
		return SpeedMeasurement{}, ServerStatus{}, err
	}
	if process != nil {
		if err := process.Stop(ctx); err != nil {
			return SpeedMeasurement{}, ServerStatus{}, errors.New("VLESS measurement candidate could not stop cleanly")
		}
		stopped = true
	}
	applySpeedMeasurement(&snapshot.Servers[index], measurement)
	snapshot.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	snapshot.Servers = RefreshPoolScores(snapshot.Servers, snapshot.TariffMbps)
	if err := StorePool(PoolPath(cfg.Storage.StateDir), snapshot); err != nil {
		return SpeedMeasurement{}, ServerStatus{}, errors.New("VLESS measurement succeeded but the pool could not be updated")
	}
	return measurement, snapshot.Servers[index], nil
}

func mergeSubscriptionFiles(paths []string, outputPath string) (string, error) {
	if len(paths) == 0 {
		return "", errors.New("no VPN subscription sources were downloaded")
	}
	rawOutbounds := make([]json.RawMessage, 0)
	for index, path := range paths {
		raw, err := readSubscriptionFile(path)
		if err != nil {
			return "", fmt.Errorf("read VPN subscription source %d: %w", index+1, err)
		}
		outbounds, err := extractRawOutbounds(raw)
		if err != nil {
			return "", fmt.Errorf("parse VPN subscription source %d: %w", index+1, err)
		}
		for _, outbound := range outbounds {
			rawOutbounds = append(rawOutbounds, append(json.RawMessage(nil), outbound.Raw...))
		}
	}
	merged, err := json.Marshal(map[string]any{"outbounds": rawOutbounds})
	if err != nil {
		return "", err
	}
	merged = append(merged, '\n')
	if err := writeFileAtomic(outputPath, merged, 0o600); err != nil {
		return "", err
	}
	return "sha256:" + sha256Hex(merged), nil
}

func subscriptionProbeService(cfg *config.Config) (config.Service, error) {
	if cfg == nil {
		return config.Service{}, errors.New("VPN subscription verification target is not configured")
	}
	for _, endpoint := range cfg.GeoIP.Endpoints {
		parsed, err := url.Parse(strings.TrimSpace(endpoint.URL))
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
			continue
		}
		return config.Service{
			Category:           "GEO_LOCKED",
			Domains:            []string{strings.ToLower(parsed.Hostname())},
			AllowedPaths:       []string{"vless"},
			ForbiddenPaths:     []string{"direct", "smart_dns", "zapret"},
			RequireNonRUEgress: true,
			ProbeURLs: []config.ProbeCheck{{
				Name:          "subscription-egress",
				URL:           parsed.String(),
				Required:      true,
				ExpectedCodes: []int{http.StatusOK},
				BodyMode:      "optional",
			}},
		}, nil
	}
	return config.Service{}, errors.New("VPN subscription verification target is not configured")
}
