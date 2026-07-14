package vpnsub

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"router-policy/internal/config"
)

type CheckerFactory func(*config.Config, config.Service) OutboundChecker

type SubscriptionService struct {
	Runner         XrayRunner
	HTTPClient     *http.Client
	CheckerFactory CheckerFactory
	Parallelism    int
	CheckAttempts  int
}

func (s *SubscriptionService) Prepare(ctx context.Context, cfg *config.Config) (PreparedBundle, error) {
	if s == nil || s.Runner == nil || cfg == nil {
		return PreparedBundle{}, errors.New("VPN subscription service is not configured")
	}
	if cfg.Storage.StateDir == "" || cfg.Xray.SubscriptionSecretFile == "" {
		return PreparedBundle{}, errors.New("VPN subscription paths are not configured")
	}
	probeService, err := selectProbeService(cfg.Services)
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
		return PreparedBundle{}, errors.New("VPN outbound checker is not configured")
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

	subscriptionURL, err := ReadSubscriptionURLFile(cfg.Xray.SubscriptionSecretFile)
	if err != nil {
		return PreparedBundle{}, errors.New("VPN subscription secret file is invalid")
	}
	downloadPath := filepath.Join(temporaryDir, "subscription.json")
	maxBytes := cfg.Policy.MaxSubscriptionBytes
	if maxBytes <= 0 || maxBytes > maxSubscriptionFileBytes {
		maxBytes = maxSubscriptionFileBytes
	}
	timeout := time.Duration(cfg.Policy.MaxProbeSeconds) * time.Second
	if timeout <= 0 || timeout > time.Minute {
		timeout = 30 * time.Second
	}
	fetched, err := FetchSubscription(ctx, s.HTTPClient, subscriptionURL, downloadPath, FetchOptions{MaxBytes: maxBytes, MaxRedirects: 3, Timeout: timeout})
	if err != nil {
		return PreparedBundle{}, err
	}
	manager := Manager{
		StateDir: cfg.Storage.StateDir, Runner: s.Runner, Checker: checker,
		Parallelism: s.Parallelism, CheckAttempts: s.CheckAttempts,
	}
	result, err := manager.PrepareBundle(ctx, downloadPath, cfg.Xray.ProbeSocksBasePort)
	if err != nil {
		return result, err
	}
	result.SubscriptionHash = fetched.SHA256
	result.SubscriptionBytes = fetched.Bytes
	return result, nil
}

func selectProbeService(services map[string]config.Service) (config.Service, error) {
	names := make([]string, 0, len(services))
	for name := range services {
		names = append(names, name)
	}
	sort.Strings(names)
	var fallback *config.Service
	for _, name := range names {
		service := services[name]
		if len(service.Domains) == 0 || len(service.ProbeURLs) == 0 {
			continue
		}
		if fallback == nil {
			copy := service
			fallback = &copy
		}
		if service.RequireNonRUEgress {
			return service, nil
		}
	}
	if fallback != nil {
		return *fallback, nil
	}
	return config.Service{}, errors.New("no service is configured for VLESS verification")
}
