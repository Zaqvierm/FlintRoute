package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"router-policy/internal/adapter"
	"router-policy/internal/api"
	"router-policy/internal/artifact"
	"router-policy/internal/auth"
	"router-policy/internal/config"
	"router-policy/internal/dataplane"
	"router-policy/internal/dataplaneproof"
	"router-policy/internal/domaincache"
	"router-policy/internal/evidence"
	"router-policy/internal/geoip"
	"router-policy/internal/planner"
	"router-policy/internal/platform"
	"router-policy/internal/probe"
	"router-policy/internal/security"
	"router-policy/internal/state"
	"router-policy/internal/tspu"
	"router-policy/internal/vpnsub"
	"router-policy/internal/zapret"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "router-policy:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		usage()
		return nil
	}

	cfgPath := os.Getenv("ROUTER_POLICY_CONFIG")
	if cfgPath == "" {
		cfgPath = filepath.Join("config", "default.json")
	}

	switch args[0] {
	case "run":
		fs := flag.NewFlagSet("run", flag.ContinueOnError)
		listen := fs.String("listen", "127.0.0.1:8787", "listen address")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return runHTTPProcess(cfgPath, *listen, false, true)
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		listen := fs.String("listen", "127.0.0.1:8787", "listen address")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return runHTTPProcess(cfgPath, *listen, false, false)
	case "serve-dev":
		fs := flag.NewFlagSet("serve-dev", flag.ContinueOnError)
		listen := fs.String("listen", "127.0.0.1:8787", "listen address")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return runHTTPProcess(cfgPath, *listen, true, false)
	case "auth":
		if len(args) < 2 || args[1] != "setup-token" || len(args) > 3 || (len(args) == 3 && args[2] != "--if-needed") {
			return errors.New("usage: router-policy auth setup-token [--if-needed]")
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		store, err := auth.Open(cfg)
		if err != nil {
			return err
		}
		if len(args) == 3 && store.HasUsers() {
			return printJSON(map[string]any{"setup_required": false})
		}
		token, meta, err := store.CreateSetupToken()
		if err != nil {
			return err
		}
		return printJSON(map[string]any{"setup_required": true, "setup_token": token, "expires_at": meta.ExpiresAt, "uses_left": meta.UsesLeft})
	case "internal-verify-rollback-token":
		if len(args) != 2 {
			return errors.New("rollback token hash is required")
		}
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, 129))
		if err != nil || len(raw) > 128 || !adapter.VerifyRollbackToken(args[1], string(bytes.TrimSpace(raw))) {
			return errors.New("rollback token verification failed")
		}
		return nil
	case "internal-verify-artifacts":
		fs := flag.NewFlagSet("internal-verify-artifacts", flag.ContinueOnError)
		root := fs.String("root", "", "artifact root")
		txID := fs.String("transaction", "", "transaction id")
		revision := fs.String("revision", "", "revision id")
		candidateHash := fs.String("candidate-hash", "", "candidate hash")
		manifestHash := fs.String("manifest-hash", "", "manifest hash")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		_, err := artifact.Verify(*root, artifact.Binding{TransactionID: *txID, RevisionID: *revision, CandidateHash: *candidateHash}, *manifestHash)
		return err
	case "internal-verify-candidate":
		fs := flag.NewFlagSet("internal-verify-candidate", flag.ContinueOnError)
		candidatePath := fs.String("candidate", "", "candidate config")
		expectedHash := fs.String("candidate-hash", "", "canonical candidate hash")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		candidate, err := config.Load(*candidatePath)
		if err != nil {
			return err
		}
		canonical, err := json.Marshal(candidate)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(canonical)
		actualHash := "sha256:" + hex.EncodeToString(sum[:])
		if actualHash != *expectedHash {
			return fmt.Errorf("candidate canonical hash mismatch")
		}
		return nil
	case "internal-verify-zapret-provider":
		fs := flag.NewFlagSet("internal-verify-zapret-provider", flag.ContinueOnError)
		binary := fs.String("binary", "/usr/bin/nfqws", "nfqws binary")
		profileID := fs.String("profile", "", "reviewed profile ID")
		providerVersion := fs.String("provider-version", "", "pinned nfqws version")
		binaryDigest := fs.String("binary-digest", "", "pinned nfqws SHA-256")
		strategyPath := fs.String("strategy", "", "reviewed strategy config")
		strategyDigest := fs.String("strategy-digest", "", "pinned strategy SHA-256")
		familiesRaw := fs.String("ip-families", "ipv4", "comma-separated IP families")
		transportsRaw := fs.String("transports", "tcp", "comma-separated transports")
		portsRaw := fs.String("ports", "80,443", "comma-separated ports")
		queue := fs.Uint("queue", 0, "NFQUEUE number")
		tempDir := fs.String("temp-dir", "", "secure temporary directory")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || *profileID == "" || *providerVersion == "" || *binaryDigest == "" || *strategyPath == "" || *strategyDigest == "" || *queue == 0 || *queue > 65535 {
			return errors.New("incomplete Zapret provider verification request")
		}
		strategyFile, err := os.Open(*strategyPath)
		if err != nil {
			return fmt.Errorf("open reviewed Zapret strategy: %w", err)
		}
		strategy, readErr := io.ReadAll(io.LimitReader(strategyFile, zapret.MaxStrategyBytes+1))
		closeErr := strategyFile.Close()
		if readErr != nil {
			return fmt.Errorf("read reviewed Zapret strategy: %w", readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close reviewed Zapret strategy: %w", closeErr)
		}
		ports, err := parseZapretPorts(*portsRaw)
		if err != nil {
			return err
		}
		profile := zapret.Profile{
			ID: *profileID, Provider: "nfqws-v1", ProviderVersion: *providerVersion,
			BinaryDigest: *binaryDigest, RouteType: "zapret", IPFamilies: splitZapretValues(*familiesRaw),
			Transports: splitZapretValues(*transportsRaw), Ports: ports, Queue: uint16(*queue),
			Safety: "reviewed", StrategyDigest: *strategyDigest, Strategy: strategy,
		}
		catalog, err := zapret.NewCatalog([]zapret.Profile{profile})
		if err != nil {
			return err
		}
		provider, err := zapret.NewNFQWSv1(*binary, *tempDir, nil)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		verification, err := provider.Validate(ctx, catalog, profile.ID)
		if err != nil {
			return err
		}
		return printJSON(verification)
	case "internal-generate-artifacts":
		fs := flag.NewFlagSet("internal-generate-artifacts", flag.ContinueOnError)
		candidatePath := fs.String("candidate", "", "candidate config")
		root := fs.String("root", "", "artifact root")
		txID := fs.String("transaction", "", "transaction id")
		revision := fs.String("revision", "", "revision id")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		candidate, err := config.Load(*candidatePath)
		if err != nil {
			return err
		}
		canonical, err := json.Marshal(candidate)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(canonical)
		candidateHash := "sha256:" + hex.EncodeToString(sum[:])
		manifest, manifestHash, err := artifact.Generate(candidate, *root, artifact.Binding{TransactionID: *txID, RevisionID: *revision, CandidateHash: candidateHash}, time.Now().UTC())
		if err != nil {
			return err
		}
		return printJSON(map[string]any{"candidate_hash": candidateHash, "artifact_manifest_hash": manifestHash, "deployment_ready": manifest.DeploymentReady, "block_reason": manifest.BlockReason, "simulation": manifest.Simulation})
	case "internal-validate-ip-plan", "internal-apply-ip-plan":
		fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
		planPath := fs.String("plan", "", "ip plan")
		txID := fs.String("transaction", "", "transaction id")
		revision := fs.String("revision", "", "revision id")
		candidateHash := fs.String("candidate-hash", "", "candidate hash")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		plan, err := artifact.LoadIPPlan(*planPath, artifact.Binding{TransactionID: *txID, RevisionID: *revision, CandidateHash: *candidateHash})
		if err != nil {
			return err
		}
		if args[0] == "internal-validate-ip-plan" {
			fmt.Printf("deployment_ready=%t\n", plan.DeploymentReady)
			fmt.Printf("simulation=%t\n", plan.Simulation)
			fmt.Printf("flow_offloading_required=%t\n", plan.FlowOffloading.Required)
			fmt.Printf("flow_offloading_action=%s\n", plan.FlowOffloading.Action)
			fmt.Printf("flow_offloading_status=%s\n", plan.FlowOffloading.Status)
			fmt.Printf("xray_enabled=%t\n", plan.TransparentProxy.Enabled)
			fmt.Printf("xray_managed=%t\n", plan.TransparentProxy.Enabled && !plan.TransparentProxy.CandidateOnly)
			fmt.Printf("zapret_enabled=%t\n", plan.Zapret.Enabled)
			fmt.Printf("zapret_managed=%t\n", plan.Zapret.Enabled && !plan.Zapret.CandidateOnly)
			if plan.BlockReason != "" {
				fmt.Printf("reason=%s\n", plan.BlockReason)
			}
			return nil
		}
		if plan.Simulation && os.Getenv("ROUTER_POLICY_ALLOW_SIMULATED_DIAGNOSTICS") != "1" {
			return fmt.Errorf("simulated diagnostics are forbidden for production apply")
		}
		ipBinary := os.Getenv("ROUTER_POLICY_IP_BIN")
		if ipBinary == "" {
			ipBinary = "ip"
		}
		uciBinary := os.Getenv("ROUTER_POLICY_UCI_BIN")
		if uciBinary == "" {
			uciBinary = "uci"
		}
		return dataplane.ApplyIPPlanWithUCI(context.Background(), dataplane.ExecRunner{}, ipBinary, uciBinary, plan)
	case "internal-snapshot-ip-state":
		fs := flag.NewFlagSet("internal-snapshot-ip-state", flag.ContinueOnError)
		planPath := fs.String("plan", "", "ip plan")
		txID := fs.String("transaction", "", "transaction id")
		revision := fs.String("revision", "", "revision id")
		candidateHash := fs.String("candidate-hash", "", "candidate hash")
		outPath := fs.String("out", "", "ip state snapshot output path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *outPath == "" {
			return errors.New("--out is required")
		}
		plan, err := artifact.LoadIPPlan(*planPath, artifact.Binding{TransactionID: *txID, RevisionID: *revision, CandidateHash: *candidateHash})
		if err != nil {
			return err
		}
		if !plan.DeploymentReady {
			return writeIPStateSnapshot(*outPath, dataplane.IPStateSnapshot{}, "plan_not_deployment_ready", false)
		}
		ipBinary := os.Getenv("ROUTER_POLICY_IP_BIN")
		if ipBinary == "" {
			ipBinary = "ip"
		}
		snap, err := dataplane.SnapshotIPState(context.Background(), dataplane.ExecCommandRunner{}, ipBinary, plan)
		if err != nil {
			return err
		}
		return writeIPStateSnapshot(*outPath, snap, "", true)
	case "internal-rollback-ip-state":
		fs := flag.NewFlagSet("internal-rollback-ip-state", flag.ContinueOnError)
		planPath := fs.String("plan", "", "ip plan")
		txID := fs.String("transaction", "", "transaction id")
		revision := fs.String("revision", "", "revision id")
		candidateHash := fs.String("candidate-hash", "", "candidate hash")
		preStatePath := fs.String("pre-state", "", "pre-apply ip state snapshot")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		plan, err := artifact.LoadIPPlan(*planPath, artifact.Binding{TransactionID: *txID, RevisionID: *revision, CandidateHash: *candidateHash})
		if err != nil {
			return err
		}
		if !plan.DeploymentReady {
			fmt.Println("ip_state_rollback=skipped")
			fmt.Println("reason=plan_not_deployment_ready")
			return nil
		}
		raw, err := os.ReadFile(*preStatePath)
		if err != nil {
			return fmt.Errorf("read ip state snapshot: %w", err)
		}
		var pre dataplane.IPStateSnapshot
		if err := json.Unmarshal(raw, &pre); err != nil {
			return fmt.Errorf("invalid ip state snapshot: %w", err)
		}
		ipBinary := os.Getenv("ROUTER_POLICY_IP_BIN")
		if ipBinary == "" {
			ipBinary = "ip"
		}
		runner := dataplane.ExecCommandRunner{}
		if err := dataplane.RollbackIPState(context.Background(), runner, ipBinary, plan, pre); err != nil {
			return err
		}
		if err := dataplane.VerifyIPState(context.Background(), runner, ipBinary, plan, pre); err != nil {
			return err
		}
		fmt.Println("ip_state_rollback=true")
		fmt.Printf("routes=%d`n", len(pre.Routes))
		fmt.Printf("rules=%d`n", len(pre.Rules))
		return nil
	case "internal-verify-data-plane":
		fs := flag.NewFlagSet("internal-verify-data-plane", flag.ContinueOnError)
		planPath := fs.String("plan", "", "verification plan")
		evidencePath := fs.String("evidence", "", "data-plane evidence")
		txID := fs.String("transaction", "", "transaction id")
		revision := fs.String("revision", "", "revision id")
		candidateHash := fs.String("candidate-hash", "", "candidate hash")
		manifestHash := fs.String("manifest-hash", "", "manifest hash")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		_, err := evidence.LoadAndVerify(*planPath, *evidencePath, artifact.Binding{TransactionID: *txID, RevisionID: *revision, CandidateHash: *candidateHash}, *manifestHash)
		return err
	case "internal-collect-data-plane-evidence":
		fs := flag.NewFlagSet("internal-collect-data-plane-evidence", flag.ContinueOnError)
		planPath := fs.String("plan", "", "verification plan")
		outputPath := fs.String("out", "", "data-plane evidence output")
		txID := fs.String("transaction", "", "transaction id")
		revision := fs.String("revision", "", "revision id")
		candidateHash := fs.String("candidate-hash", "", "candidate hash")
		manifestHash := fs.String("manifest-hash", "", "manifest hash")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		allowSimulation := cfg.Platform.Target == "test" && os.Getenv("ROUTER_POLICY_ALLOW_SIMULATED_DIAGNOSTICS") == "1"
		report, err := dataplaneproof.Collect(context.Background(), dataplaneproof.Options{
			Config: cfg, PlanPath: *planPath, OutputPath: *outputPath,
			Binding:      artifact.Binding{TransactionID: *txID, RevisionID: *revision, CandidateHash: *candidateHash},
			ManifestHash: *manifestHash, Prober: probe.NewActiveOpenWrtEngine(cfg, allowSimulation),
		})
		if err != nil {
			return err
		}
		return printJSON(map[string]any{"collected": true, "routes": len(report.Routes), "checked_at": report.CheckedAt})
	case "validate-config":
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		return printJSON(map[string]any{"valid": true, "version": cfg.Version, "services": len(cfg.Services), "routes": len(cfg.Routes)})
	case "status":
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		return printJSON(map[string]any{
			"config":     cfgPath,
			"platform":   cfg.Platform.Target,
			"state_dir":  cfg.Storage.StateDir,
			"runtime":    cfg.Storage.RuntimeDir,
			"services":   len(cfg.Services),
			"routes":     len(cfg.Routes),
			"apply_safe": !cfg.Platform.RequireConfirmedDiagnostics,
		})
	case "routes":
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		return printJSON(cfg.Routes)
	case "services":
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		names := make([]string, 0, len(cfg.Services))
		for name := range cfg.Services {
			names = append(names, name)
		}
		return printJSON(names)
	case "candidates":
		fs := flag.NewFlagSet("candidates", flag.ContinueOnError)
		tspu := fs.Bool("tspu", false, "domain is in TSPU list")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() < 2 {
			return errors.New("usage: router-policy candidates [--tspu] DOMAIN SERVICE")
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		tspuResult, err := tspuMatchForDomain(cfg, fs.Arg(0), *tspu, time.Now().UTC())
		if err != nil {
			return err
		}
		plan, err := planner.BuildCandidates(cfg, fs.Arg(0), fs.Arg(1), planner.Options{TSPUResult: tspuResult})
		if err != nil {
			return err
		}
		return printJSON(plan)
	case "probe-route":
		fs := flag.NewFlagSet("probe-route", flag.ContinueOnError)
		routeTag := fs.String("route", "", "route tag")
		noPersist := fs.Bool("no-persist", false, "return live probe evidence without opening the state database")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() < 2 || *routeTag == "" {
			return errors.New("usage: router-policy probe-route --route ROUTE DOMAIN SERVICE")
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		route, ok := cfg.RouteByTag(*routeTag)
		if !ok {
			return fmt.Errorf("route not found: %s", *routeTag)
		}
		service, ok := cfg.Services[fs.Arg(1)]
		if !ok {
			return fmt.Errorf("service not found: %s", fs.Arg(1))
		}
		allowSimulation := cfg.Platform.Target == "test" && os.Getenv("ROUTER_POLICY_ALLOW_SIMULATED_DIAGNOSTICS") == "1"
		engine := probe.NewActiveOpenWrtEngine(cfg, allowSimulation)
		if *noPersist {
			result := engine.ProbeRoute(context.Background(), cfg, fs.Arg(0), fs.Arg(1), service, route)
			return printJSON(result)
		}
		stateStore, healthTracker, err := openHealthTracker(cfg)
		if err != nil {
			return err
		}
		defer stateStore.Close()
		result := engine.ProbeRoute(context.Background(), cfg, fs.Arg(0), fs.Arg(1), service, route)
		healthTracker.Observe(result, cfg.Policy, time.Now().UTC())
		if err := persistProbeState(stateStore, healthTracker, []probe.RouteResult{result}); err != nil {
			return err
		}
		return printJSON(result)
	case "check-domain":
		fs := flag.NewFlagSet("check-domain", flag.ContinueOnError)
		tspu := fs.Bool("tspu", false, "domain is in TSPU list")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return errors.New("usage: router-policy check-domain [--tspu] DOMAIN [SERVICE]")
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		domain := fs.Arg(0)
		serviceName := ""
		if fs.NArg() >= 2 {
			serviceName = fs.Arg(1)
		}
		stateStore, healthTracker, err := openHealthTracker(cfg)
		if err != nil {
			return err
		}
		defer stateStore.Close()
		activeConfig, activeRevision, err := loadCLIActiveConfig(stateStore, cfg)
		if err != nil {
			return err
		}
		decisionCache, err := domaincache.New(stateStore, activeConfig.Storage.MaxAutoDomains)
		if err != nil {
			return err
		}
		tspuResult, err := tspuMatchForDomain(activeConfig, domain, *tspu, time.Now().UTC())
		if err != nil {
			return err
		}
		allowSimulation := activeConfig.Platform.Target == "test" && os.Getenv("ROUTER_POLICY_ALLOW_SIMULATED_DIAGNOSTICS") == "1"
		engine := probe.NewActiveOpenWrtEngine(activeConfig, allowSimulation)
		result, err := planner.CheckDomain(context.Background(), activeConfig, domain, serviceName, planner.Options{
			TSPUResult: tspuResult, ProbeEngine: engine, HealthTracker: healthTracker,
			DecisionCache: decisionCache, ActiveRevision: activeRevision,
		})
		if err != nil {
			return err
		}
		if !result.Cached {
			if err := persistProbeState(stateStore, healthTracker, result.Results); err != nil {
				return err
			}
		}
		return printJSON(result)
	case "tspu-update":
		fs := flag.NewFlagSet("tspu-update", flag.ContinueOnError)
		out := fs.String("out", "", "output TSPU cache path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		cfg, err := loadRuntimeConfig(cfgPath)
		if err != nil {
			return err
		}
		outPath := *out
		if outPath == "" {
			outPath = filepath.Join(cfg.Storage.StateDir, "tspu-cache.json")
		}
		cache, err := tspu.RefreshFile(context.Background(), nil, cfg, outPath, time.Now().UTC())
		if err != nil {
			return err
		}
		return printJSON(map[string]any{
			"updated": true, "status": "OK", "entries": len(cache.Entries), "fresh_sources": cache.FreshSources,
			"sha256": cache.SHA256, "previous_sha256": cache.PreviousSHA256,
			"sources": cache.Sources, "output": outPath, "expires_at": cache.ExpiresAt,
		})
	case "tspu-check":
		fs := flag.NewFlagSet("tspu-check", flag.ContinueOnError)
		cachePath := fs.String("cache", "", "TSPU cache path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return errors.New("usage: router-policy tspu-check [--cache CACHE_JSON] DOMAIN")
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		path := *cachePath
		if path == "" {
			path = filepath.Join(cfg.Storage.StateDir, "tspu-cache.json")
		}
		cache, err := tspu.Load(path)
		if err != nil {
			return err
		}
		match, ok := tspu.Find(cache, fs.Arg(0), time.Now().UTC())
		status := "NO_MATCH"
		if ok {
			status = match.Status
		}
		return printJSON(map[string]any{"matched": ok, "status": status, "result": match, "cache_sha256": cache.SHA256})
	case "geoip-update":
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		result, err := geoip.Update(context.Background(), nil, cfg.GeoIP.SourceURL, cfg.GeoIP.Database, cfg.GeoIP.MaxDatabaseBytes, time.Now().UTC())
		if err != nil {
			return err
		}
		return printJSON(result)
	case "geoip-status":
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		metadata, err := geoip.Verify(cfg.GeoIP.Database, time.Duration(cfg.GeoIP.MaxAgeHours)*time.Hour, time.Now().UTC())
		if err != nil {
			return printJSON(map[string]any{"status": "UNVERIFIED", "reason": err.Error()})
		}
		return printJSON(map[string]any{"status": "OK", "sha256": metadata.SHA256, "bytes": metadata.Bytes, "database_type": metadata.DatabaseType, "source_version": metadata.SourceVersion, "updated_at": metadata.UpdatedAt})
	case "init-db":
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		store, err := state.Open(cfg)
		if err != nil {
			return err
		}
		defer store.Close()
		return printJSON(map[string]any{"ok": true, "mode": store.Mode(), "path": store.Path()})
	case "store-result":
		if len(args) < 2 {
			return errors.New("usage: router-policy store-result RESULT_JSON")
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		store, err := state.Open(cfg)
		if err != nil {
			return err
		}
		defer store.Close()
		var result probe.RouteResult
		b, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &result); err != nil {
			return err
		}
		if err := store.StoreProbeResult(result); err != nil {
			return err
		}
		return printJSON(map[string]any{"stored": true})
	case "subscription-normalize":
		if len(args) < 2 {
			return errors.New("usage: router-policy subscription-normalize SUBSCRIPTION_JSON")
		}
		summary, err := vpnsub.NormalizeFile(args[1])
		if err != nil {
			return err
		}
		return printJSON(summary)
	case "subscription-fetch":
		fs := flag.NewFlagSet("subscription-fetch", flag.ContinueOnError)
		urlFile := fs.String("url-file", "", "mode-0600 file containing the HTTPS subscription URL")
		out := fs.String("out", "", "mode-0600 subscription output")
		maxBytes := fs.Int64("max-bytes", 4<<20, "maximum subscription bytes")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *urlFile == "" || *out == "" || fs.NArg() != 0 {
			return errors.New("usage: router-policy subscription-fetch --url-file URL_SECRET --out SUBSCRIPTION_JSON")
		}
		subscriptionURL, err := vpnsub.ReadSubscriptionURLFile(*urlFile)
		if err != nil {
			return err
		}
		summary, err := vpnsub.FetchSubscription(context.Background(), nil, subscriptionURL, *out, vpnsub.FetchOptions{MaxBytes: *maxBytes})
		if err != nil {
			return err
		}
		return printJSON(summary)
	case "subscription-routes":
		fs := flag.NewFlagSet("subscription-routes", flag.ContinueOnError)
		basePort := fs.Int("base-port", 12000, "first local SOCKS port")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return errors.New("usage: router-policy subscription-routes [--base-port PORT] SUBSCRIPTION_JSON")
		}
		routes, err := vpnsub.GenerateRoutesFile(fs.Arg(0), *basePort)
		if err != nil {
			return err
		}
		return printJSON(routes)
	case "subscription-xray":
		fs := flag.NewFlagSet("subscription-xray", flag.ContinueOnError)
		basePort := fs.Int("base-port", 12000, "first local SOCKS port")
		out := fs.String("out", "", "output Xray config path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() < 1 || *out == "" {
			return errors.New("usage: router-policy subscription-xray [--base-port PORT] --out OUTPUT_JSON SUBSCRIPTION_JSON")
		}
		summary, err := vpnsub.GenerateXrayConfigFile(fs.Arg(0), *out, *basePort)
		if err != nil {
			return err
		}
		return printJSON(summary)
	case "install-dry-run":
		return printJSON(map[string]any{
			"dry_run": true,
			"steps": []string{
				"diagnose platform",
				"backup config",
				"install files",
				"install procd services",
				"run config validation",
				"refuse activation until --activate",
			},
		})
	case "security":
		if len(args) < 2 || args[1] != "audit" {
			return errors.New("usage: router-policy security audit")
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		return printJSON(security.Audit(cfg))
	case "daemon":
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		interval := time.Duration(cfg.Policy.HealthCheckIntervalSeconds) * time.Second
		if interval <= 0 {
			interval = 5 * time.Minute
		}
		fmt.Fprintln(os.Stderr, "router-policy daemon started")
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			for _, serviceName := range []string{"openai", "telegram", "youtube"} {
				svc, ok := cfg.Services[serviceName]
				if !ok || len(svc.Domains) == 0 {
					continue
				}
				result, err := planner.CheckDomain(context.Background(), cfg, svc.Domains[0], serviceName, planner.Options{})
				if err == nil {
					_ = printJSON(result)
				} else {
					fmt.Fprintln(os.Stderr, "check failed:", serviceName, err)
				}
			}
			<-ticker.C
		}
	case "version":
		return printJSON(map[string]any{"name": "router-policy", "built_at": time.Now().UTC().Format(time.RFC3339)})
	default:
		usage()
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func usage() {
	fmt.Println(`router-policy:
  run [--listen 127.0.0.1:8787]
  serve [--listen 127.0.0.1:8787]
  serve-dev [--listen 127.0.0.1:8787]
  auth setup-token [--if-needed]
  status
  validate-config
  routes
  services
  candidates [--tspu] DOMAIN SERVICE
  probe-route --route ROUTE DOMAIN SERVICE
  check-domain [--tspu] DOMAIN [SERVICE]
  tspu-update [--out CACHE_JSON]
  tspu-check [--cache CACHE_JSON] DOMAIN
  geoip-update
  geoip-status
  init-db
  store-result RESULT_JSON
  subscription-normalize SUBSCRIPTION_JSON
  subscription-routes [--base-port PORT] SUBSCRIPTION_JSON
  subscription-xray [--base-port PORT] --out OUTPUT_JSON SUBSCRIPTION_JSON
  daemon
  install-dry-run
  security audit
  version`)
}

func runHTTPProcess(cfgPath, listen string, development bool, scheduler bool) error {
	if !safeListenAddress(listen) {
		return fmt.Errorf("refusing non-loopback listen address %q; LAN listener needs TLS, firewall and WAN-deny verification first", listen)
	}
	cfg, err := loadRuntimeConfig(cfgPath)
	if err != nil {
		return err
	}
	var provider platform.Provider = platform.OpenWrtProvider{}
	var productionAdapter adapter.Interface
	var subscriptionPreparer api.SubscriptionPreparer
	if development {
		provider = platform.DevelopmentMockProvider{}
		productionAdapter = adapter.NewFilesystem(cfg)
	} else {
		productionAdapter, err = adapter.NewOpenWrt(cfg, cfgPath)
		if err != nil {
			return err
		}
		if runner, runnerErr := vpnsub.NewExecXrayRunner(); runnerErr == nil {
			subscriptionPreparer = &vpnsub.SubscriptionService{
				Runner: runner, Parallelism: cfg.Policy.ParallelServerChecks, CheckAttempts: cfg.Policy.FailAfterConsecutiveErrors,
			}
		}
	}
	app, err := api.NewServerWithOptions(cfg, api.Options{Provider: provider, ProductionAdapter: productionAdapter, SubscriptionPreparer: subscriptionPreparer, Development: development})
	if err != nil {
		return err
	}
	defer app.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if scheduler {
		app.StartScheduler(ctx)
	}
	srv := &http.Server{
		Addr:              listen,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       60 * time.Second,
	}
	mode := "production"
	if development {
		mode = "development-simulation"
	}
	fmt.Fprintln(os.Stderr, "router-policy", mode, "listening on", listen)
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		err := <-errCh
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func loadRuntimeConfig(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if len(cfg.TSPUSources) > 0 {
		return cfg, nil
	}
	factoryPath := filepath.Join(filepath.Dir(path), "factory-default.json")
	factory, err := config.Load(factoryPath)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load factory config for TSPU sources: %w", err)
	}
	cfg.TSPUSources = append([]config.TSPUSource(nil), factory.TSPUSources...)
	return cfg, nil
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func writeIPStateSnapshot(path string, snap dataplane.IPStateSnapshot, reason string, captured bool) error {
	raw, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if captured {
		fmt.Println("ip_state_captured=true")
	} else {
		fmt.Println("ip_state_captured=false")
	}
	fmt.Printf("routes=%d`n", len(snap.Routes))
	fmt.Printf("rules=%d`n", len(snap.Rules))
	if reason != "" {
		fmt.Printf("reason=%s`n", reason)
	}
	return nil
}

func openHealthTracker(cfg *config.Config) (*state.Store, *probe.HealthTracker, error) {
	store, err := state.Open(cfg)
	if err != nil {
		return nil, nil, err
	}
	health, err := store.ListRouteHealth()
	if err != nil {
		_ = store.Close()
		return nil, nil, err
	}
	return store, probe.NewHealthTracker(health), nil
}

func persistProbeState(store *state.Store, tracker *probe.HealthTracker, results []probe.RouteResult) error {
	for _, result := range results {
		if err := store.StoreProbeResult(result); err != nil {
			return err
		}
	}
	for _, health := range tracker.Snapshot() {
		if err := store.SaveRouteHealth(health); err != nil {
			return err
		}
	}
	return nil
}

func loadCLIActiveConfig(store *state.Store, fallback *config.Config) (*config.Config, string, error) {
	if store == nil || fallback == nil {
		return nil, "", errors.New("state store and fallback config are required")
	}
	active := fallback
	var persisted config.Config
	if err := store.LoadJSON("meta", "active_config", &persisted); err == nil {
		if err := persisted.Validate(); err != nil {
			return nil, "", fmt.Errorf("persisted active config is invalid: %w", err)
		}
		active = &persisted
	} else if !errors.Is(err, state.ErrNotFound) {
		return nil, "", err
	}
	var revision string
	if err := store.LoadJSON("meta", "active_revision", &revision); err != nil && !errors.Is(err, state.ErrNotFound) {
		return nil, "", err
	}
	return active, revision, nil
}

func tspuMatchForDomain(cfg *config.Config, domain string, forced bool, now time.Time) (tspu.Match, error) {
	if forced {
		return tspu.Match{Domain: domain, Matched: domain, MatchType: "manual", Source: "cli", Confidence: 1, Status: "MATCH", Evidence: "manual_cli_override"}, nil
	}
	path := filepath.Join(cfg.Storage.StateDir, "tspu-cache.json")
	cache, err := tspu.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return tspu.Match{Domain: domain, Status: "UNAVAILABLE", Evidence: "tspu_cache_not_found"}, nil
	}
	if err != nil {
		return tspu.Match{}, fmt.Errorf("load TSPU cache: %w", err)
	}
	if match, ok := tspu.Find(cache, domain, now); ok {
		return match, nil
	}
	return tspu.Match{Domain: domain, Status: "NO_MATCH", Evidence: "tspu_cache_no_match"}, nil
}

func safeListenAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func splitZapretValues(raw string) []string {
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		values = append(values, strings.TrimSpace(part))
	}
	return values
}

func parseZapretPorts(raw string) ([]uint16, error) {
	values := splitZapretValues(raw)
	ports := make([]uint16, 0, len(values))
	for _, value := range values {
		parsed, err := strconv.ParseUint(value, 10, 16)
		if err != nil || parsed == 0 {
			return nil, fmt.Errorf("invalid Zapret port %q", value)
		}
		ports = append(ports, uint16(parsed))
	}
	return ports, nil
}
