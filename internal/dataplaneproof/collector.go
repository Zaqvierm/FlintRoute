package dataplaneproof

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"router-policy/internal/artifact"
	"router-policy/internal/config"
	"router-policy/internal/evidence"
	"router-policy/internal/probe"
)

type RouteProber interface {
	ProbeRoute(context.Context, *config.Config, string, string, config.Service, config.Route) probe.RouteResult
}

type Options struct {
	Config       *config.Config
	PlanPath     string
	OutputPath   string
	Binding      artifact.Binding
	ManifestHash string
	Prober       RouteProber
	Now          func() time.Time
	Parallelism  int
}

type collectedRoute struct {
	index    int
	required artifact.RouteProof
	proof    evidence.RouteResult
	err      error
}

func Collect(ctx context.Context, opts Options) (evidence.Report, error) {
	if opts.Config == nil || opts.Prober == nil || opts.PlanPath == "" || opts.OutputPath == "" {
		return evidence.Report{}, errors.New("config, prober, plan and output are required")
	}
	if opts.Binding.TransactionID == "" || opts.Binding.RevisionID == "" || opts.Binding.CandidateHash == "" || opts.ManifestHash == "" {
		return evidence.Report{}, errors.New("complete evidence binding is required")
	}
	plan, err := artifact.LoadVerificationPlan(opts.PlanPath, opts.Binding)
	if err != nil {
		return evidence.Report{}, err
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	report := evidence.Report{
		Binding:              opts.Binding,
		ArtifactManifestHash: opts.ManifestHash,
		DNSLeakFree:          true,
		IPv6LeakFree:         true,
		CheckedAt:            now().UTC(),
	}
	parallelism := opts.Parallelism
	if parallelism <= 0 {
		parallelism = opts.Config.Policy.ParallelServerChecks
	}
	if parallelism <= 0 {
		parallelism = 1
	}
	if parallelism > 4 {
		parallelism = 4
	}
	if parallelism > len(plan.RequiredRouteProof) {
		parallelism = len(plan.RequiredRouteProof)
	}
	collected, err := collectRoutes(ctx, opts, plan.RequiredRouteProof, parallelism)
	if err != nil {
		return evidence.Report{}, err
	}
	for _, item := range collected {
		required, proof := item.required, item.proof
		if required.RequiresDNS && (proof.DNSResolver == "" || proof.DNSProtocol == "" || net.ParseIP(proof.ResolvedIP) == nil) {
			report.DNSLeakFree = false
		}
		if required.Type == "drop" {
			report.GeoLockedKillSwitch = report.GeoLockedKillSwitch || (proof.DropIPv4Enforced && proof.DropIPv6Enforced && proof.DropDNSEnforced)
			report.IPv6LeakFree = report.IPv6LeakFree && proof.DropIPv6Enforced
		} else if required.RequiresIPv6 {
			report.IPv6LeakFree = report.IPv6LeakFree && proof.IPv6Verified
		}
		report.Routes = append(report.Routes, proof)
	}
	if err := evidence.VerifyReport(plan, report, opts.Binding, opts.ManifestHash); err != nil {
		return evidence.Report{}, err
	}
	if err := writeAtomicJSON(opts.OutputPath, report); err != nil {
		return evidence.Report{}, err
	}
	return report, nil
}

func collectRoutes(ctx context.Context, opts Options, required []artifact.RouteProof, parallelism int) ([]collectedRoute, error) {
	if len(required) == 0 {
		return nil, errors.New("verification plan has no required routes")
	}
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan int)
	results := make(chan collectedRoute, len(required))
	var workers sync.WaitGroup
	for worker := 0; worker < parallelism; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				item := collectRoute(workerCtx, opts, index, required[index])
				results <- item
				if item.err != nil {
					cancel()
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index := range required {
			select {
			case jobs <- index:
			case <-workerCtx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()
	ordered := make([]collectedRoute, len(required))
	completed := 0
	var firstErr error
	for item := range results {
		if item.err != nil && firstErr == nil {
			firstErr = item.err
		}
		if item.err == nil {
			ordered[item.index] = item
			completed++
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	if completed != len(required) {
		return nil, errors.New("data-plane evidence collection was interrupted")
	}
	return ordered, nil
}

func collectRoute(ctx context.Context, opts Options, index int, required artifact.RouteProof) collectedRoute {
	item := collectedRoute{index: index, required: required}
	route, ok := opts.Config.RouteByTag(required.Tag)
	if !ok || route.Type != required.Type {
		item.err = fmt.Errorf("verification route is missing from candidate: %s", required.Tag)
		return item
	}
	serviceName, domain, service, err := selectProbeTarget(opts.Config, route)
	if err != nil {
		item.err = err
		return item
	}
	result := opts.Prober.ProbeRoute(ctx, opts.Config, domain, serviceName, service, route)
	if result.Status != "OK" || !result.PathVerified || result.PathEvidence == nil {
		item.err = fmt.Errorf("route %s probe is not verified: status=%s reason=%s", route.Tag, result.Status, result.ReasonCode)
		return item
	}
	item.proof = *result.PathEvidence
	if err := evidence.ValidateRouteProof(required, item.proof, opts.Binding, opts.ManifestHash); err != nil {
		item.err = err
	}
	return item
}

type probeTarget struct {
	name    string
	domain  string
	service config.Service
	score   int
}

func selectProbeTarget(cfg *config.Config, route config.Route) (string, string, config.Service, error) {
	candidates := make([]probeTarget, 0, len(cfg.Services))
	for name, service := range cfg.Services {
		if !config.PathAllowed(service, route, cfg.Policy) || len(service.Domains) == 0 {
			continue
		}
		if route.Type != "drop" && len(service.ProbeURLs) == 0 {
			continue
		}
		score := 0
		if route.Type == "vless" && service.RequireNonRUEgress {
			score += 100
		}
		if route.Type == "direct" && service.Category == "DIRECT_ONLY" {
			score += 100
		}
		if route.Type == "zapret" && service.Category != "DIRECT_ONLY" && !service.RequireNonRUEgress {
			score += 50
		}
		candidates = append(candidates, probeTarget{name: name, domain: service.Domains[0], service: service, score: score})
	}
	if len(candidates) == 0 {
		return "", "", config.Service{}, fmt.Errorf("no compatible probe service for route %s", route.Tag)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].name < candidates[j].name
	})
	target := candidates[0]
	return target.name, target.domain, target.service, nil
}

func writeAtomicJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".data-plane-evidence-*")
	if err != nil {
		return err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
