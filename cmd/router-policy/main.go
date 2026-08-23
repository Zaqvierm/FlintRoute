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
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"router-policy/internal/adapter"
	"router-policy/internal/api"
	"router-policy/internal/artifact"
	"router-policy/internal/auth"
	"router-policy/internal/component"
	"router-policy/internal/config"
	"router-policy/internal/dataplane"
	"router-policy/internal/dataplaneproof"
	"router-policy/internal/domaincache"
	"router-policy/internal/evidence"
	"router-policy/internal/geoip"
	"router-policy/internal/lifecycle"
	"router-policy/internal/managementproof"
	"router-policy/internal/planner"
	"router-policy/internal/platform"
	"router-policy/internal/probe"
	"router-policy/internal/security"
	"router-policy/internal/state"
	storagepolicy "router-policy/internal/storage"
	"router-policy/internal/tspu"
	"router-policy/internal/vpnsub"
	"router-policy/internal/watchdog"
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
	case "management-proof":
		if len(args) < 2 || args[1] != "issue-headless" {
			return errors.New("usage: router-policy management-proof issue-headless --transaction TX --revision REV [--ttl 15m]")
		}
		fs := flag.NewFlagSet("management-proof issue-headless", flag.ContinueOnError)
		transactionID := fs.String("transaction", "", "validated transaction ID")
		revisionID := fs.String("revision", "", "validated revision ID")
		ttl := fs.Duration("ttl", 15*time.Minute, "proof lifetime, at most 1h")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		manager, err := newManagementProofManager(cfg)
		if err != nil {
			return err
		}
		proof, err := manager.IssueHeadlessSSH(context.Background(), managementproof.Binding{TransactionID: *transactionID, RevisionID: *revisionID}, os.Getenv("SSH_CONNECTION"), *ttl)
		if err != nil {
			return err
		}
		path, _ := manager.ProofPath(managementproof.Binding{TransactionID: *transactionID, RevisionID: *revisionID})
		return printJSON(map[string]any{"issued": true, "mode": proof.Mode, "transaction_id": proof.TransactionID, "revision_id": proof.RevisionID, "interface": proof.Interface, "subnet": proof.Subnet, "expires_at": proof.ExpiresAt, "proof_path": path})
	case "internal-verify-management-proof":
		fs := flag.NewFlagSet("internal-verify-management-proof", flag.ContinueOnError)
		transactionID := fs.String("transaction", "", "transaction ID")
		revisionID := fs.String("revision", "", "revision ID")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		manager, err := newManagementProofManager(cfg)
		if err != nil {
			return err
		}
		proof, err := manager.Verify(managementproof.Binding{TransactionID: *transactionID, RevisionID: *revisionID})
		if err != nil {
			return err
		}
		adminHTTPHealth := manager.ProbeAdminHTTP(context.Background(), proof)
		fmt.Printf("proof_valid=true\nmanagement_mode=%s\nmanagement_interface=%s\nmanagement_subnet=%s\nmanagement_client_ip=%s\nmanagement_local_ip=%s\ncontrol_plane_url=%s\nadmin_http_url=%s\nadmin_http_required=%t\nadmin_http_health=%t\nproof_expires_at=%s\n", proof.Mode, proof.Interface, proof.Subnet, proof.ClientIP, proof.LocalIP, proof.ControlPlaneURL, proof.AdminHTTPURL, proof.AdminHTTPAvailable, adminHTTPHealth, proof.ExpiresAt)
		return nil
	case "lifecycle":
		if len(args) < 2 {
			return errors.New("usage: router-policy lifecycle status|begin|add-process|add-file|add-network|finish")
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		baselineVerifier := lifecycle.OpenWrtBaselineVerifier{}
		manager := lifecycle.Manager{StateDir: cfg.Storage.StateDir, RuntimeDir: cfg.Storage.RuntimeDir, Inspector: lifecycle.LinuxProcessInspector{}, Executor: lifecycle.OpenWrtResourceExecutor{}, Verifier: baselineVerifier}
		switch args[1] {
		case "status":
			fs := flag.NewFlagSet("lifecycle status", flag.ContinueOnError)
			jsonOutput := fs.Bool("json", false, "print JSON")
			if err := fs.Parse(args[2:]); err != nil {
				return err
			}
			manifests, manifestIssues, err := manager.ListWithIssues()
			if err != nil {
				return err
			}
			diagnosticCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			services := lifecycle.DiagnoseServices(diagnosticCtx, lifecycle.ExecRunner{}, lifecycle.LinuxProcessInspector{}, []lifecycle.ServiceSpec{
				{Component: "xray", Service: "router-policy-xray", Instance: "router-policy-xray", Executable: cfg.Xray.Binary, ConfigPath: cfg.Xray.ActiveConfig, SystemServices: []string{"xray"}},
				{Component: "zapret", Service: "router-policy-zapret", Instance: "router-policy-zapret", Executable: cfg.Zapret.Binary, ConfigPath: cfg.Zapret.ActiveConfig, SystemServices: []string{"zapret", "nfqws"}},
			})
			result := map[string]any{"schema_version": lifecycle.ManifestSchemaVersion, "test_runs": manifests, "manifest_issues": manifestIssues, "services": services, "persistent_root": cfg.Storage.StateDir, "runtime_root": cfg.Storage.RuntimeDir}
			if *jsonOutput {
				return printJSON(result)
			}
			fmt.Printf("test runs: %d\npersistent root: %s\nruntime root: %s\n", len(manifests), cfg.Storage.StateDir, cfg.Storage.RuntimeDir)
			return nil
		case "begin":
			fs := flag.NewFlagSet("lifecycle begin", flag.ContinueOnError)
			runID := fs.String("id", "", "test-run ID")
			lease := fs.Duration("lease", time.Hour, "bounded test-run lease")
			if err := fs.Parse(args[2:]); err != nil {
				return err
			}
			manifest, err := manager.BeginTestRun(*runID, *lease, baselineVerifier.Capture())
			if err != nil {
				return err
			}
			return printJSON(manifest)
		case "add-process":
			fs := flag.NewFlagSet("lifecycle add-process", flag.ContinueOnError)
			runID := fs.String("id", "", "test-run ID")
			resourceID := fs.String("resource", "", "resource ID")
			pid := fs.Int("pid", 0, "process PID")
			executable := fs.String("executable", "", "expected executable")
			configPath := fs.String("config", "", "expected test config path")
			service := fs.String("service", "", "managed service")
			instance := fs.String("instance", "", "managed instance")
			if err := fs.Parse(args[2:]); err != nil {
				return err
			}
			identity, err := (lifecycle.LinuxProcessInspector{}).Inspect(*pid)
			if err != nil {
				return err
			}
			if *executable == "" || filepath.Clean(identity.Executable) != filepath.Clean(*executable) || *configPath == "" || !strings.Contains(strings.Join(identity.CommandLine, "\x00"), *configPath) || !strings.Contains(strings.Join(identity.CommandLine, "\x00"), *runID) {
				return errors.New("process identity does not prove executable, config path and test-run ID")
			}
			identity.Executable, identity.ConfigPath, identity.Service, identity.Instance = *executable, *configPath, *service, *instance
			manifest, err := manager.AddResource(*runID, lifecycle.Resource{ID: *resourceID, Kind: lifecycle.ResourceProcess, Process: &identity, AllowCleanup: true})
			if err != nil {
				return err
			}
			return printJSON(manifest)
		case "add-file":
			fs := flag.NewFlagSet("lifecycle add-file", flag.ContinueOnError)
			runID := fs.String("id", "", "test-run ID")
			resourceID := fs.String("resource", "", "resource ID")
			path := fs.String("path", "", "owned runtime file")
			if err := fs.Parse(args[2:]); err != nil {
				return err
			}
			manifest, err := manager.AddResource(*runID, lifecycle.Resource{ID: *resourceID, Kind: lifecycle.ResourceFile, Path: *path, AllowCleanup: true})
			if err != nil {
				return err
			}
			return printJSON(manifest)
		case "add-network":
			fs := flag.NewFlagSet("lifecycle add-network", flag.ContinueOnError)
			runID := fs.String("id", "", "test-run ID")
			resourceID := fs.String("resource", "", "resource ID")
			kind := fs.String("kind", "", "nft-table, ip-rule, route or listener")
			family := fs.String("family", "", "inet, ipv4 or ipv6")
			table := fs.String("table", "", "nft or IP routing table")
			address := fs.String("address", "", "route prefix or loopback listener")
			priority := fs.String("priority", "", "IP rule priority")
			if err := fs.Parse(args[2:]); err != nil {
				return err
			}
			resource := lifecycle.Resource{ID: *resourceID, Kind: lifecycle.ResourceKind(*kind), Family: *family, Table: *table, Address: *address, AllowCleanup: true}
			if *priority != "" {
				resource.Metadata = map[string]string{"priority": *priority}
			}
			switch resource.Kind {
			case lifecycle.ResourceNFTTable, lifecycle.ResourceIPRule, lifecycle.ResourceRoute, lifecycle.ResourceListener:
			default:
				return errors.New("network resource kind is not allowlisted")
			}
			manifest, err := manager.Load(*runID)
			if err != nil {
				return err
			}
			resource.Owner = manifest.Owner
			if resource.Kind != lifecycle.ResourceListener {
				if _, _, _, err := (lifecycle.OpenWrtResourceExecutor{}).Cleanup(manifest, resource, false); err != nil {
					return fmt.Errorf("network resource ownership is not provable: %w", err)
				}
			} else {
				host, port, splitErr := net.SplitHostPort(resource.Address)
				if splitErr != nil || (host != "127.0.0.1" && host != "::1") {
					return errors.New("only loopback test listeners may be registered")
				}
				if _, parseErr := strconv.ParseUint(port, 10, 16); parseErr != nil {
					return errors.New("listener port is invalid")
				}
			}
			manifest, err = manager.AddResource(*runID, resource)
			if err != nil {
				return err
			}
			return printJSON(manifest)
		case "finish":
			fs := flag.NewFlagSet("lifecycle finish", flag.ContinueOnError)
			runID := fs.String("id", "", "test-run ID")
			result := fs.String("result", "completed", "test result")
			if err := fs.Parse(args[2:]); err != nil {
				return err
			}
			manifest, err := manager.FinishTestRun(*runID, *result)
			if err != nil {
				return err
			}
			return printJSON(manifest)
		default:
			return errors.New("usage: router-policy lifecycle status|begin|add-process|add-file|add-network|finish")
		}
	case "cleanup":
		if len(args) < 2 || args[1] != "stale" {
			return errors.New("usage: router-policy cleanup stale [--dry-run|--apply] [--json]")
		}
		fs := flag.NewFlagSet("cleanup stale", flag.ContinueOnError)
		dryRun := fs.Bool("dry-run", false, "show cleanup actions without changing resources")
		apply := fs.Bool("apply", false, "apply ownership-verified cleanup")
		jsonOutput := fs.Bool("json", false, "print JSON")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if *dryRun && *apply {
			return errors.New("--dry-run and --apply are mutually exclusive")
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		manager := lifecycle.Manager{StateDir: cfg.Storage.StateDir, RuntimeDir: cfg.Storage.RuntimeDir, Inspector: lifecycle.LinuxProcessInspector{}, Executor: lifecycle.OpenWrtResourceExecutor{}, Verifier: lifecycle.OpenWrtBaselineVerifier{}}
		report, err := manager.CleanupStale(*apply)
		if err != nil {
			return err
		}
		if *jsonOutput {
			return printJSON(report)
		}
		fmt.Printf("dry-run: %t\nstale runs: %d\nactions: %d\nambiguous skipped: %d\n", report.DryRun, report.StaleRuns, len(report.Actions), report.AmbiguousSkipped)
		return nil
	case "maintenance":
		if len(args) < 2 {
			return errors.New("usage: router-policy maintenance begin|end|status")
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		path := filepath.Join(cfg.Storage.RuntimeDir, "watchdog-inhibit.json")
		switch args[1] {
		case "begin":
			fs := flag.NewFlagSet("maintenance begin", flag.ContinueOnError)
			owner := fs.String("owner", "", "operation owner")
			reason := fs.String("reason", "", "maintenance reason")
			lease := fs.Duration("lease", 15*time.Minute, "bounded inhibit lease")
			if err := fs.Parse(args[2:]); err != nil {
				return err
			}
			value, err := watchdog.WriteInhibit(path, *owner, *reason, time.Now().UTC(), *lease)
			if err != nil {
				return err
			}
			return printJSON(value)
		case "end":
			if len(args) != 2 {
				return errors.New("usage: router-policy maintenance end")
			}
			if info, err := os.Lstat(path); err == nil {
				if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
					return errors.New("refusing non-regular watchdog inhibit target")
				}
				return os.Remove(path)
			} else if errors.Is(err, os.ErrNotExist) {
				return nil
			} else {
				return err
			}
		case "status":
			value, active, err := watchdog.ReadInhibit(path, time.Now().UTC())
			if err != nil {
				return err
			}
			return printJSON(map[string]any{"active": active, "inhibit": value})
		default:
			return errors.New("usage: router-policy maintenance begin|end|status")
		}
	case "watchdog":
		fs := flag.NewFlagSet("watchdog", flag.ContinueOnError)
		healthURL := fs.String("health-url", "http://127.0.0.1:8787/api/v1/health", "local health URL")
		interval := fs.Duration("interval", time.Minute, "health interval")
		startupGrace := fs.Duration("startup-grace", 90*time.Second, "startup grace")
		failureThreshold := fs.Int("failure-threshold", 3, "consecutive failures before restart")
		inhibitPath := fs.String("inhibit-file", "/tmp/router-policy/watchdog-inhibit.json", "maintenance inhibit file")
		serviceScript := fs.String("service-script", "/etc/init.d/router-policy", "managed control-plane service")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return runWatchdog(*healthURL, *interval, *startupGrace, *failureThreshold, *inhibitPath, *serviceScript)
	case "backup":
		if len(args) < 2 {
			return errors.New("usage: router-policy backup register|prune")
		}
		switch args[1] {
		case "register":
			fs := flag.NewFlagSet("backup register", flag.ContinueOnError)
			root := fs.String("root", "", "operation backup directory")
			operation := fs.String("operation", "", "operation ID")
			version := fs.String("version", "unknown", "installed version")
			reason := fs.String("reason", "", "backup reason")
			retentionClass := fs.String("retention-class", "installer-fallback", "retention class")
			if err := fs.Parse(args[2:]); err != nil {
				return err
			}
			manifest, err := storagepolicy.RegisterDirectory(*root, *operation, *version, *reason, *retentionClass, time.Now().UTC())
			if err != nil {
				return err
			}
			return printJSON(manifest)
		case "prune":
			fs := flag.NewFlagSet("backup prune", flag.ContinueOnError)
			root := fs.String("root", "/root/router-policy-backups", "project backup registry root")
			apply := fs.Bool("apply", false, "delete older verified backups")
			dryRun := fs.Bool("dry-run", false, "show retention actions")
			maxBackups := fs.Int("max", 2, "maximum verified fallbacks")
			maxBytes := fs.Int64("max-bytes", 128*1024*1024, "maximum total verified bytes")
			if err := fs.Parse(args[2:]); err != nil {
				return err
			}
			if *apply && *dryRun {
				return errors.New("--dry-run and --apply are mutually exclusive")
			}
			plan, err := storagepolicy.PlanRetention(*root, *maxBackups, *maxBytes, *apply)
			if err != nil {
				return err
			}
			return printJSON(plan)
		default:
			return errors.New("usage: router-policy backup register|prune")
		}
	case "storage":
		if len(args) < 2 || args[1] != "migrate" {
			return errors.New("usage: router-policy storage migrate --dry-run [--legacy-root /root]")
		}
		fs := flag.NewFlagSet("storage migrate", flag.ContinueOnError)
		dryRun := fs.Bool("dry-run", false, "plan migration without changing files")
		apply := fs.Bool("apply", false, "migrate only validated legacy backups")
		legacyRoot := fs.String("legacy-root", "/root", "root containing legacy backup directories")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if *dryRun && *apply {
			return errors.New("--dry-run and --apply are mutually exclusive")
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		var plan storagepolicy.MigrationPlan
		if *apply {
			plan, err = storagepolicy.ApplyMigration(cfg.Storage.StateDir, cfg.Storage.RuntimeDir, *legacyRoot, time.Now().UTC())
		} else {
			plan, err = storagepolicy.PlanMigration(cfg.Storage.StateDir, cfg.Storage.RuntimeDir, *legacyRoot)
		}
		if err != nil {
			return err
		}
		return printJSON(plan)
	case "zapret-blockcheck-import":
		fs := flag.NewFlagSet("zapret-blockcheck-import", flag.ContinueOnError)
		reportPath := fs.String("report", "", "blockcheck output file")
		binaryPath := fs.String("binary", "/usr/bin/nfqws", "nfqws binary")
		providerVersion := fs.String("provider-version", "", "nfqws version")
		queue := fs.Uint("queue", 0, "NFQUEUE number")
		domain := fs.String("domain", "", "domain used by blockcheck")
		bundleID := fs.String("bundle-id", "", "dynamic service bundle ID")
		failureRoute := fs.String("failure-route", "drop", "route tag used when all profiles fail")
		catalogOut := fs.String("catalog-out", "", "write the validated adaptive catalog atomically")
		networkFingerprint := fs.String("network-fingerprint", "", "sha256 network identity")
		save := fs.Bool("save", false, "save the bounded top-three set in persistent state")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || *reportPath == "" || *providerVersion == "" || *queue == 0 || *queue > 65535 || *domain == "" || *bundleID == "" {
			return errors.New("usage: router-policy zapret-blockcheck-import --report FILE --binary FILE --provider-version VERSION --queue N --domain DOMAIN --bundle-id ID")
		}
		report, err := readBoundedRegularFile(*reportPath, zapret.MaxBlockcheckReportBytes)
		if err != nil {
			return fmt.Errorf("read blockcheck report: %w", err)
		}
		binaryDigest, err := regularFileSHA256(*binaryPath)
		if err != nil {
			return fmt.Errorf("hash nfqws binary: %w", err)
		}
		candidates, err := zapret.ParseBlockcheckReport(report, zapret.BlockcheckParseOptions{
			Queue: uint16(*queue), ProviderVersion: *providerVersion, BinaryDigest: binaryDigest,
		})
		if err != nil {
			return err
		}
		catalog, err := zapret.BuildBlockcheckCatalog(candidates, *bundleID, *domain, *failureRoute)
		if err != nil {
			return err
		}
		evidence := make([]map[string]any, 0, len(candidates))
		for _, candidate := range candidates {
			profile := candidate.Profile
			evidence = append(evidence, map[string]any{
				"profile_id": profile.ID, "domains": candidate.Domains, "tests": candidate.Tests,
				"occurrences": candidate.Occurrences, "first_line": candidate.FirstLine,
			})
		}
		document := map[string]any{
			"schema_version": 1, "source": "blockcheck", "candidate_count": len(catalog.Profiles),
			"network_fingerprint": *networkFingerprint, "domain": *domain, "bundle_id": *bundleID,
			"catalog": catalog, "evidence": evidence,
		}
		if *catalogOut != "" {
			raw, err := json.MarshalIndent(catalog, "", "  ")
			if err != nil {
				return err
			}
			if err := writePrivateFileAtomic(*catalogOut, append(raw, '\n')); err != nil {
				return fmt.Errorf("write adaptive Zapret catalog: %w", err)
			}
			document["catalog_saved"] = true
		}
		if *save {
			if !validSHA256Digest(*networkFingerprint) {
				return errors.New("--save requires a sha256 network fingerprint")
			}
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			store, err := state.Open(cfg)
			if err != nil {
				return err
			}
			saveErr := store.SaveJSON("zapret_blockcheck", *networkFingerprint+"|"+*bundleID, document)
			closeErr := store.Close()
			if saveErr != nil {
				return saveErr
			}
			if closeErr != nil {
				return closeErr
			}
			document["saved"] = true
		}
		return printJSON(document)
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
	case "internal-print-managed-marks":
		if len(args) != 1 {
			return errors.New("usage: router-policy internal-print-managed-marks")
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		marks := []struct {
			name  string
			value string
		}{
			{"direct", cfg.OpenWrt.DirectMark},
			{"zapret", cfg.OpenWrt.ZapretMark},
			{"xray", cfg.OpenWrt.XrayMark},
			{"xray_tproxy", cfg.OpenWrt.XrayTProxyMark},
			{"xray_bypass", cfg.OpenWrt.XrayBypassMark},
			{"drop", cfg.OpenWrt.DropMark},
		}
		for _, mark := range marks {
			if mark.value == "" || seen[mark.value] {
				continue
			}
			seen[mark.value] = true
			fmt.Printf("managed_mark=%s\n", mark.value)
			fmt.Printf("managed_mark_name=%s\n", mark.name)
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
	case "internal-validate-ip-plan", "internal-apply-ip-plan", "internal-verify-applied-ip-plan":
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
		if args[0] == "internal-verify-applied-ip-plan" {
			ipBinary := os.Getenv("ROUTER_POLICY_IP_BIN")
			if ipBinary == "" {
				ipBinary = "ip"
			}
			if err := dataplane.VerifyAppliedIPPlan(context.Background(), dataplane.ExecCommandRunner{}, ipBinary, plan); err != nil {
				return err
			}
			fmt.Println("ip_plan_active=true")
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
	case "internal-verify-state-backup":
		fs := flag.NewFlagSet("internal-verify-state-backup", flag.ContinueOnError)
		path := fs.String("path", "", "state backup path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || *path == "" {
			return errors.New("usage: router-policy internal-verify-state-backup --path BACKUP")
		}
		if err := state.VerifyDatabaseFile(*path); err != nil {
			return err
		}
		return printJSON(map[string]any{"verified": true})
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
  management-proof issue-headless --transaction TX --revision REV [--ttl 15m]
  lifecycle status [--json]
  lifecycle begin --id RUN_ID [--lease 1h]
  lifecycle add-process --id RUN_ID --resource ID --pid PID --executable PATH --config PATH
  lifecycle add-file --id RUN_ID --resource ID --path PATH
  lifecycle add-network --id RUN_ID --resource ID --kind KIND [--family FAMILY --table TABLE --address VALUE]
  lifecycle finish --id RUN_ID [--result RESULT]
  cleanup stale [--dry-run|--apply] [--json]
  zapret-blockcheck-import --report FILE --binary FILE --provider-version VERSION --queue N --domain DOMAIN --bundle-id ID
  maintenance begin --owner OWNER --reason REASON [--lease 15m]
  maintenance end|status
  watchdog [--health-url URL] [--interval 1m] [--startup-grace 90s]
  backup register --root DIR --operation ID --reason REASON
  backup prune [--root DIR] [--dry-run|--apply]
  storage migrate [--dry-run|--apply] [--legacy-root /root]
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

func newManagementProofManager(cfg *config.Config) (*managementproof.Manager, error) {
	bootIDPath := os.Getenv("ROUTER_POLICY_BOOT_ID_PATH")
	return managementproof.New(cfg.Storage.StateDir, cfg.Storage.RuntimeDir, managementproof.Options{BootIDPath: bootIDPath})
}

func runWatchdog(healthURL string, interval, startupGrace time.Duration, failureThreshold int, inhibitPath, serviceScript string) error {
	parsed, err := url.Parse(healthURL)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" {
		return fmt.Errorf("watchdog health URL must use loopback HTTP")
	}
	if interval < time.Second || startupGrace < 0 || failureThreshold < 1 || failureThreshold > 20 {
		return fmt.Errorf("invalid watchdog timing")
	}
	if serviceScript == "" || filepath.Clean(serviceScript) != "/etc/init.d/router-policy" {
		return fmt.Errorf("watchdog may only restart the authoritative router-policy service")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	client := &http.Client{Timeout: min(interval/2, 5*time.Second)}
	controller := watchdog.Controller{StartedAt: time.Now().UTC(), StartupGrace: startupGrace, FailureThreshold: failureThreshold}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		now := time.Now().UTC()
		_, inhibited, inhibitErr := watchdog.ReadInhibit(inhibitPath, now)
		if inhibitErr != nil {
			inhibited = false
		}
		healthy := false
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		if response, requestErr := client.Do(request); requestErr == nil {
			healthy = response.StatusCode >= 200 && response.StatusCode < 300
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			response.Body.Close()
		}
		decision := controller.Observe(now, healthy, inhibited)
		if decision.Action == "restart" {
			// procd is the sole lifecycle owner.  This process only records a
			// bounded observation; it must never issue a second restart command.
			fmt.Fprintf(os.Stderr, "watchdog action=restart_suppressed service=%s\n", serviceScript)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func runHTTPProcess(cfgPath, listen string, development bool, scheduler bool) error {
	if !allowedListenAddress(listen) {
		return fmt.Errorf("refusing non-loopback listen address %q; set ROUTER_POLICY_ALLOW_FIREWALLED_BIND=1 only with a source-restricted firewall rule", listen)
	}
	cfg, err := loadRuntimeConfig(cfgPath)
	if err != nil {
		return err
	}
	var provider platform.Provider = platform.OpenWrtProvider{}
	var productionAdapter adapter.Interface
	var subscriptionPreparer api.SubscriptionPreparer
	var zapretSetupChecker zapret.SetupChecker
	var componentManager api.ComponentManager
	var zapretCalibration *zapret.CalibrationManager
	var vlessThroughputTester vpnsub.ThroughputTester
	if development {
		provider = platform.DevelopmentMockProvider{}
		productionAdapter = adapter.NewFilesystem(cfg)
	} else {
		productionAdapter, err = adapter.NewOpenWrt(cfg, cfgPath)
		if err != nil {
			return err
		}
		runner, runnerErr := vpnsub.NewManagedExecXrayRunner(cfg.Xray.Binary)
		if runnerErr != nil {
			return runnerErr
		}
		vlessThroughputTester = vpnsub.NewCloudflareThroughputTester()
		subscriptionPreparer = &vpnsub.SubscriptionService{
			Runner: runner, Parallelism: cfg.Policy.ParallelServerChecks, CheckAttempts: cfg.Policy.FailAfterConsecutiveErrors,
			SpeedTester: vlessThroughputTester,
		}
		zapretSetupChecker = zapret.LocalSetupChecker{}
		componentManager = &component.Manager{
			StateDir: cfg.Storage.StateDir, RuntimeDir: cfg.Storage.RuntimeDir,
			Driver: component.OpenWrtDriver{
				StateDir:   cfg.Storage.StateDir,
				XrayBinary: cfg.Xray.Binary, XrayService: cfg.Xray.InitScript,
				ZapretBinary: cfg.Zapret.Binary, ZapretService: cfg.Zapret.InitScript,
				ZapretRoot: "/usr/lib/router-policy/components/zapret",
			},
			Releases: component.GitHubReleaseSource{},
		}
		zapretRelease := component.SupportedCatalog()[component.KindZapret]
		zapretCalibration = zapret.NewCalibrationManager(zapret.ExecCalibrationRunner{
			Script:      "/usr/lib/router-policy/scripts/calibrate-zapret.sh",
			QuickScript: "/usr/lib/router-policy/scripts/quick-zapret-check.sh",
			Blockcheck:  filepath.Join("/usr/lib/router-policy/components/zapret", zapretRelease.Version, "blockcheck.sh"),
			Config:      cfgPath, RouterPolicyBin: "/usr/bin/router-policy", NFQWSBin: cfg.Zapret.Binary, ManagedQueue: cfg.Zapret.QueueNum,
			ZapretInit: cfg.Zapret.InitScript, RuntimeDir: cfg.Storage.RuntimeDir,
			CatalogOut: "/etc/router-policy/zapret/catalog.json",
		})
	}
	app, err := api.NewServerWithOptions(cfg, api.Options{Provider: provider, ProductionAdapter: productionAdapter, SubscriptionPreparer: subscriptionPreparer, ZapretSetupChecker: zapretSetupChecker, ComponentManager: componentManager, ZapretCalibration: zapretCalibration, VLESSThroughputTester: vlessThroughputTester, Development: development, DeferRecovery: !development})
	if err != nil {
		if api.IsRescueRequired(err) {
			databasePath := cfg.Storage.Database
			if databasePath == "" {
				databasePath = filepath.Join(cfg.Storage.StateDir, "router-policy.bbolt")
			}
			fmt.Fprintln(os.Stderr, "router-policy rescue mode: persistent state is unreadable")
			return runRescueHTTPProcess(listen, api.NewRescueHandler(err, databasePath))
		}
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
		// SSE clients reconnect after this bounded window; keeping the global
		// deadline finite prevents a stalled writer from pinning a goroutine.
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
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

func runRescueHTTPProcess(requestedListen string, handler http.Handler) error {
	_, port, err := net.SplitHostPort(requestedListen)
	if err != nil || port == "" {
		port = "8787"
	}
	server := &http.Server{
		Addr:              net.JoinHostPort("127.0.0.1", port),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return <-errCh
	}
}

func loadRuntimeConfig(path string) (*config.Config, error) {
	bootstrap, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	cfg := bootstrap
	databasePath := bootstrap.Storage.Database
	if databasePath == "" {
		databasePath = filepath.Join(bootstrap.Storage.StateDir, "router-policy.bbolt")
	}
	_, databaseExistedErr := os.Lstat(databasePath)
	databaseExisted := databaseExistedErr == nil
	if databaseExistedErr != nil && !errors.Is(databaseExistedErr, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect state database: %w", databaseExistedErr)
	}
	// The packaged file is immutable bootstrap data. Once a committed control
	// plane revision exists, bbolt is the only source of the active config.
	// Opening the store here is short-lived; NewServerWithOptions opens it again
	// after this function returns and owns the long-lived handle.
	store, storeErr := state.Open(bootstrap)
	if storeErr != nil {
		return nil, fmt.Errorf("open state for active config: %w", storeErr)
	}
	rescue := func(cause error) (*config.Config, error) {
		_ = store.Close()
		return nil, &state.RescueError{Path: databasePath, Cause: cause}
	}
	var activeRevision string
	revisionErr := store.LoadJSON("meta", "active_revision", &activeRevision)
	if revisionErr != nil && !errors.Is(revisionErr, state.ErrNotFound) {
		return rescue(fmt.Errorf("load active revision: %w", revisionErr))
	}
	var persisted config.Config
	activeConfigErr := store.LoadJSON("meta", "active_config", &persisted)
	if activeConfigErr == nil {
		if err := persisted.Validate(); err != nil {
			return rescue(fmt.Errorf("persisted active config is invalid: %w", err))
		}
		if revisionErr != nil || strings.TrimSpace(activeRevision) == "" {
			return rescue(errors.New("active config exists without a committed active revision"))
		}
		cfg = &persisted
	} else if errors.Is(activeConfigErr, state.ErrNotFound) {
		// A missing state file is the one legitimate bootstrap case. Once the
		// database already existed, missing active_config/active_revision is
		// corruption or an interrupted initialization and must enter rescue;
		// silently using default.json could activate an uncommitted candidate.
		if databaseExisted || revisionErr == nil {
			return rescue(errors.New("committed active config is missing"))
		}
	} else {
		return rescue(fmt.Errorf("load persisted active config: %w", activeConfigErr))
	}
	if err := store.Close(); err != nil {
		return nil, fmt.Errorf("close state after active config load: %w", err)
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

func readBoundedRegularFile(path string, limit int) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("invalid file size limit")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > int64(limit) {
		return nil, errors.New("input must be a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(raw) > limit {
		return nil, errors.New("input exceeds size limit")
	}
	return raw, nil
}

func regularFileSHA256(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("target is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func validSHA256Digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func writePrivateFileAtomic(path string, raw []byte) error {
	if path == "" {
		return errors.New("output path is required")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("output target is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return errors.New("output directory is unavailable")
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp-"+strconv.Itoa(os.Getpid()))
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	removeTemp = false
	if runtime.GOOS != "windows" {
		parent, err := os.Open(dir)
		if err != nil {
			return err
		}
		syncErr := parent.Sync()
		closeErr := parent.Close()
		if syncErr != nil {
			return syncErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
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
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func allowedListenAddress(addr string) bool {
	if safeListenAddress(addr) {
		return true
	}
	if os.Getenv("ROUTER_POLICY_ALLOW_FIREWALLED_BIND") != "1" {
		return false
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	return err == nil && portNumber > 0 && net.ParseIP(host) != nil
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
