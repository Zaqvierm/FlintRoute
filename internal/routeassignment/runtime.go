// Package routeassignment materializes the small, revision-bound dnsmasq
// overlay used by automatic route-only assignment. It never changes Xray,
// Zapret, nft topology, IP rules, or service state.
package routeassignment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"router-policy/internal/artifact"
	"router-policy/internal/config"
)

const manifestVersion = 1

const maxAssignments = 256

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type Request struct {
	Generation           string
	RevisionID           string
	CandidateHash        string
	ArtifactManifestHash string
	Domain               string
	RouteTag             string
	RouteType            string
	RouteSetID           string
	AssignmentID         string
	MappingHash          string
	RequestID            string
}

type Assignment struct {
	Domain       string `json:"domain"`
	RouteTag     string `json:"route_tag"`
	RouteType    string `json:"route_type"`
	RouteSetID   string `json:"route_set_id"`
	AssignmentID string `json:"assignment_id"`
	MappingHash  string `json:"mapping_hash"`
}

type manifest struct {
	Version              int          `json:"version"`
	Generation           string       `json:"generation"`
	RevisionID           string       `json:"revision_id"`
	CandidateHash        string       `json:"candidate_hash"`
	ArtifactManifestHash string       `json:"artifact_manifest_hash"`
	Assignments          []Assignment `json:"assignments"`
}

type Options struct {
	DNSMasqInit string
	Runner      CommandRunner
	Now         func() time.Time
}

type CommandRunner interface {
	Run(context.Context, string, ...string) error
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run()
}

func Apply(ctx context.Context, cfg *config.Config, request Request, options Options) error {
	if err := validateRequest(request); err != nil {
		return err
	}
	active, binding, plan, err := loadActive(cfg, request)
	if err != nil {
		return err
	}
	if err := validateRoute(active, plan, request); err != nil {
		return err
	}
	path, err := includePath(active)
	if err != nil {
		return err
	}
	manifestPath := filepath.Join(active.Storage.StateDir, "route-assignments.json")
	backupDir := filepath.Join(active.Storage.StateDir, "route-assignment-backups")
	previous, err := readManifest(manifestPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if previous.Version != 0 && (previous.Generation != binding.Generation || previous.RevisionID != binding.RevisionID || previous.CandidateHash != binding.CandidateHash || previous.ArtifactManifestHash != request.ArtifactManifestHash) {
		return errors.New("route assignment manifest is bound to another active revision")
	}
	if previous.Version == 0 {
		previous = manifest{Version: manifestVersion, Generation: binding.Generation, RevisionID: binding.RevisionID, CandidateHash: binding.CandidateHash, ArtifactManifestHash: request.ArtifactManifestHash}
	}
	backup := filepath.Join(backupDir, request.RequestID+".json")
	if err := writeJSONAtomic(backup, previous, 0o600); err != nil {
		return fmt.Errorf("save route assignment rollback state: %w", err)
	}
	updated := previous
	updated.Assignments = replaceAssignment(updated.Assignments, assignmentFrom(request))
	if len(updated.Assignments) > maxAssignments {
		return errors.New("route assignment manifest capacity exceeded")
	}
	if err := materialize(ctx, active, plan, updated, manifestPath, path, options); err != nil {
		return err
	}
	return nil
}

func Rollback(ctx context.Context, cfg *config.Config, request Request, options Options) error {
	if err := validateRequest(request); err != nil {
		return err
	}
	active, binding, plan, err := loadActive(cfg, request)
	if err != nil {
		return err
	}
	if err := validateRoute(active, plan, request); err != nil {
		return err
	}
	path, err := includePath(active)
	if err != nil {
		return err
	}
	manifestPath := filepath.Join(active.Storage.StateDir, "route-assignments.json")
	backup := filepath.Join(active.Storage.StateDir, "route-assignment-backups", request.RequestID+".json")
	previous, err := readManifest(backup)
	if errors.Is(err, os.ErrNotExist) {
		// A repeated rollback is safe: the current mapping is removed only when
		// it still matches this exact request.
		current, readErr := readManifest(manifestPath)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}
		current.Assignments = removeMatching(current.Assignments, assignmentFrom(request))
		if current.Version == 0 {
			current = manifest{Version: manifestVersion, Generation: binding.Generation, RevisionID: binding.RevisionID, CandidateHash: binding.CandidateHash, ArtifactManifestHash: request.ArtifactManifestHash}
		}
		return materialize(ctx, active, plan, current, manifestPath, path, options)
	}
	if err != nil {
		return err
	}
	if previous.Generation != binding.Generation || previous.RevisionID != binding.RevisionID || previous.CandidateHash != binding.CandidateHash || previous.ArtifactManifestHash != request.ArtifactManifestHash {
		return errors.New("route assignment rollback state is bound to another active revision")
	}
	if err := materialize(ctx, active, plan, previous, manifestPath, path, options); err != nil {
		return err
	}
	_ = os.Remove(backup)
	return nil
}

// Reconcile reapplies the persistent, revision-bound assignment manifest to
// the volatile dnsmasq include after a reboot. It is intentionally idempotent.
func Reconcile(ctx context.Context, cfg *config.Config, options Options) error {
	return reconcile(ctx, cfg, nil, options)
}

// ReconcileBound is the helper-facing variant. The command-line binding is
// checked against the durable last-good binding before any overlay is
// materialized, so a stale or forged helper response cannot claim evidence
// for a different revision than the one actually reconciled.
func ReconcileBound(ctx context.Context, cfg *config.Config, expected Request, options Options) error {
	return reconcile(ctx, cfg, &expected, options)
}

func reconcile(ctx context.Context, cfg *config.Config, expected *Request, options Options) error {
	if cfg == nil {
		return errors.New("config is required")
	}
	activePath := filepath.Join(cfg.Storage.StateDir, "last-good", "router-policy-config.json")
	active, err := config.Load(activePath)
	if err != nil {
		return fmt.Errorf("load committed route assignment config: %w", err)
	}
	values, err := readBinding(filepath.Join(active.Storage.StateDir, "last-good", "active-transaction.env"))
	if errors.Is(err, os.ErrNotExist) {
		values, err = readBinding(filepath.Join(active.Storage.StateDir, "last-good", "transaction.env"))
	}
	if err != nil {
		return err
	}
	if expected != nil && (expected.Generation != values["revision_id"] || expected.RevisionID != values["revision_id"] || expected.CandidateHash != values["candidate_hash"] || expected.ArtifactManifestHash != values["artifact_manifest_hash"]) {
		return errors.New("route assignment reconcile binding does not match committed revision")
	}
	plan, err := loadPlan(active, values)
	if err != nil {
		return err
	}
	request := Request{Generation: values["revision_id"], RevisionID: values["revision_id"], CandidateHash: values["candidate_hash"], ArtifactManifestHash: values["artifact_manifest_hash"], Domain: "placeholder.example", RouteTag: "direct", RouteType: "direct", RouteSetID: "placeholder", AssignmentID: "placeholder", MappingHash: "sha256:" + strings.Repeat("0", 64), RequestID: "reconcile"}
	entries, err := readManifest(filepath.Join(active.Storage.StateDir, "route-assignments.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if entries.Generation != request.Generation || entries.RevisionID != request.RevisionID || entries.CandidateHash != request.CandidateHash || entries.ArtifactManifestHash != request.ArtifactManifestHash {
		// A full committed revision invalidates route-only mappings from the
		// previous generation.  Clear only the exact owned overlay; never treat
		// a foreign include as ours.  Rewriting an empty, newly-bound manifest
		// keeps the transition crash-safe and makes the operation idempotent.
		path, pathErr := includePath(active)
		if pathErr != nil {
			return pathErr
		}
		if raw, readErr := os.ReadFile(path); readErr == nil {
			if !bytes.Contains(raw, []byte("# FlintRoute owned route-only overlay")) {
				return errors.New("route assignment include is not owned; refusing stale cleanup")
			}
		} else if !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}
		fresh := manifest{Version: manifestVersion, Generation: request.Generation, RevisionID: request.RevisionID, CandidateHash: request.CandidateHash, ArtifactManifestHash: request.ArtifactManifestHash}
		return materialize(ctx, active, plan, fresh, filepath.Join(active.Storage.StateDir, "route-assignments.json"), path, options)
	}
	path, err := includePath(active)
	if err != nil {
		return err
	}
	return materialize(ctx, active, plan, entries, filepath.Join(active.Storage.StateDir, "route-assignments.json"), path, options)
}

type binding struct {
	Generation           string
	RevisionID           string
	CandidateHash        string
	ArtifactManifestHash string
}

func loadActive(cfg *config.Config, request Request) (*config.Config, binding, artifact.IPPlan, error) {
	if cfg == nil {
		return nil, binding{}, artifact.IPPlan{}, errors.New("config is required")
	}
	activePath := filepath.Join(cfg.Storage.StateDir, "last-good", "router-policy-config.json")
	active, err := config.Load(activePath)
	if err != nil {
		return nil, binding{}, artifact.IPPlan{}, fmt.Errorf("load committed route assignment config: %w", err)
	}
	values, err := readBinding(filepath.Join(active.Storage.StateDir, "last-good", "active-transaction.env"))
	if errors.Is(err, os.ErrNotExist) {
		values, err = readBinding(filepath.Join(active.Storage.StateDir, "last-good", "transaction.env"))
	}
	if err != nil {
		return nil, binding{}, artifact.IPPlan{}, err
	}
	b := binding{Generation: values["revision_id"], RevisionID: values["revision_id"], CandidateHash: values["candidate_hash"], ArtifactManifestHash: values["artifact_manifest_hash"]}
	if b.RevisionID != request.RevisionID || b.CandidateHash != request.CandidateHash || b.ArtifactManifestHash != request.ArtifactManifestHash || b.Generation != request.Generation {
		return nil, binding{}, artifact.IPPlan{}, errors.New("route assignment active revision binding mismatch")
	}
	canonical, err := json.Marshal(active)
	if err != nil {
		return nil, binding{}, artifact.IPPlan{}, err
	}
	sum := sha256.Sum256(canonical)
	if "sha256:"+hex.EncodeToString(sum[:]) != request.CandidateHash {
		return nil, binding{}, artifact.IPPlan{}, errors.New("route assignment active config hash mismatch")
	}
	plan, err := loadPlan(active, values)
	if err != nil {
		return nil, binding{}, artifact.IPPlan{}, err
	}
	return active, b, plan, nil
}

func loadPlan(active *config.Config, values map[string]string) (artifact.IPPlan, error) {
	path := filepath.Join(active.Storage.StateDir, "last-good", "generated", artifact.IPPlanFile)
	return artifact.LoadIPPlan(path, artifact.Binding{TransactionID: values["transaction_id"], RevisionID: values["revision_id"], CandidateHash: values["candidate_hash"]})
}

func validateRequest(request Request) error {
	if request.Generation == "" || request.RevisionID == "" || request.CandidateHash == "" || request.ArtifactManifestHash == "" || request.RequestID == "" || !tokenPattern.MatchString(request.RequestID) {
		return errors.New("route assignment identity is incomplete")
	}
	if request.Generation != request.RevisionID || !safeHash(request.CandidateHash) || !safeHash(request.ArtifactManifestHash) || !safeHash(request.MappingHash) {
		return errors.New("route assignment identity is invalid")
	}
	if !safeDomain(request.Domain) || !tokenPattern.MatchString(request.RouteTag) || !tokenPattern.MatchString(request.RouteSetID) || !tokenPattern.MatchString(request.AssignmentID) {
		return errors.New("route assignment object identity is invalid")
	}
	switch request.RouteType {
	case "direct", "drop", "zapret", "smart_dns", "vless":
	default:
		return errors.New("route assignment type is not allowlisted")
	}
	return nil
}

func validateRoute(cfg *config.Config, plan artifact.IPPlan, request Request) error {
	route, ok := cfg.RouteByTag(request.RouteTag)
	if !ok || !route.Enabled() || route.Type != request.RouteType {
		return errors.New("route assignment route is not enabled or type does not match")
	}
	if routeID(request.RouteTag) != request.RouteSetID || assignmentID(request.Domain) != request.AssignmentID {
		return errors.New("route assignment object binding mismatch")
	}
	if request.RouteType == "vless" {
		found := false
		for _, proxy := range plan.DNSProxies {
			if proxy.RouteTag == request.RouteTag {
				found = true
				break
			}
		}
		if !found {
			return errors.New("route assignment VLESS DNS proxy is not in the committed plan")
		}
	}
	return nil
}

func materialize(ctx context.Context, cfg *config.Config, plan artifact.IPPlan, value manifest, manifestPath, include string, options Options) error {
	if value.Version == 0 {
		value.Version = manifestVersion
	}
	sort.Slice(value.Assignments, func(i, j int) bool { return value.Assignments[i].AssignmentID < value.Assignments[j].AssignmentID })
	content, err := render(cfg, plan, value)
	if err != nil {
		return err
	}
	oldManifest, oldManifestErr := os.ReadFile(manifestPath)
	oldInclude, oldIncludeErr := os.ReadFile(include)
	if oldManifestErr != nil && !errors.Is(oldManifestErr, os.ErrNotExist) {
		return oldManifestErr
	}
	if oldIncludeErr != nil && !errors.Is(oldIncludeErr, os.ErrNotExist) {
		return oldIncludeErr
	}
	if options.Runner == nil {
		options.Runner = execRunner{}
	}
	init := options.DNSMasqInit
	if init == "" {
		init = "/etc/init.d/dnsmasq"
	}
	restore := func() error {
		var restoreErr error
		if oldManifestErr == nil {
			restoreErr = writeAtomic(manifestPath, oldManifest, 0o600)
		} else if errors.Is(oldManifestErr, os.ErrNotExist) {
			restoreErr = os.Remove(manifestPath)
			if errors.Is(restoreErr, os.ErrNotExist) {
				restoreErr = nil
			}
		}
		if oldIncludeErr == nil {
			if err := writeAtomic(include, oldInclude, 0o644); restoreErr == nil && err != nil {
				restoreErr = err
			}
		} else if errors.Is(oldIncludeErr, os.ErrNotExist) {
			if err := os.Remove(include); restoreErr == nil && !errors.Is(err, os.ErrNotExist) {
				restoreErr = err
			}
		}
		return restoreErr
	}
	restoreAndReload := func(cause error) error {
		restoreErr := restore()
		if restoreErr != nil {
			return fmt.Errorf("%w; restore failed: %v", cause, restoreErr)
		}
		// Restoring the files is not enough: dnsmasq may already have loaded
		// the candidate include.  Reload the restored, owned configuration and
		// prove readiness before returning the original failure.
		if reloadErr := options.Runner.Run(ctx, init, "restart"); reloadErr != nil {
			return fmt.Errorf("%w; restored files but dnsmasq reload failed: %v", cause, reloadErr)
		}
		if readyErr := options.Runner.Run(ctx, init, "running"); readyErr != nil {
			return fmt.Errorf("%w; restored files but dnsmasq readiness failed: %v", cause, readyErr)
		}
		return cause
	}
	if err := writeJSONAtomic(manifestPath, value, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(include, []byte(content), 0o644); err != nil {
		return restoreAndReload(err)
	}
	if err := options.Runner.Run(ctx, init, "restart"); err != nil {
		return restoreAndReload(fmt.Errorf("dnsmasq restart after route assignment: %w", err))
	}
	if err := options.Runner.Run(ctx, init, "running"); err != nil {
		return restoreAndReload(fmt.Errorf("dnsmasq readiness after route assignment: %w", err))
	}
	return nil
}

func render(cfg *config.Config, plan artifact.IPPlan, value manifest) (string, error) {
	family := cfg.OpenWrt.NFTFamily
	if family == "" {
		family = "inet"
	}
	table := cfg.OpenWrt.NFTTable
	if table == "" {
		table = "router_policy"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# FlintRoute owned route-only overlay revision=%s\n", value.RevisionID)
	for _, assignment := range value.Assignments {
		fmt.Fprintf(&b, "nftset=/%s/4#%s#%s#route_%s_v4,6#%s#%s#route_%s_v6\n", assignment.Domain, family, table, assignment.RouteSetID, family, table, assignment.RouteSetID)
		route, ok := cfg.RouteByTag(assignment.RouteTag)
		if !ok || !route.Enabled() || route.Type != assignment.RouteType {
			return "", errors.New("route assignment references unavailable route")
		}
		switch assignment.RouteType {
		case "direct", "drop":
			// The route nft set is sufficient for these routes; no resolver
			// override is required.
		case "smart_dns":
			server, err := dnsmasqServer(route.DNSServer)
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "server=/%s/%s\n", assignment.Domain, server)
		case "vless":
			for _, proxy := range plan.DNSProxies {
				if proxy.RouteTag == assignment.RouteTag {
					fmt.Fprintf(&b, "server=/%s/%s#%d\n", assignment.Domain, proxy.Listen, proxy.Port)
					break
				}
			}
		}
	}
	return b.String(), nil
}

func includePath(cfg *config.Config) (string, error) {
	target := filepath.Clean(cfg.OpenWrt.DNSMasqInclude)
	if target == "." || !filepath.IsAbs(target) || filepath.Base(target) != "router-policy.conf" {
		return "", errors.New("dnsmasq include path is not allowlisted")
	}
	path := filepath.Join(filepath.Dir(target), "router-policy-route-assignments.conf")
	if filepath.Dir(path) != filepath.Dir(target) {
		return "", errors.New("route assignment include path escaped dnsmasq confdir")
	}
	return path, nil
}

func readManifest(path string) (manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return manifest{}, err
	}
	var value manifest
	if err := json.Unmarshal(raw, &value); err != nil {
		return manifest{}, fmt.Errorf("invalid route assignment manifest: %w", err)
	}
	if value.Version != manifestVersion {
		return manifest{}, errors.New("unsupported route assignment manifest version")
	}
	if value.Generation == "" || value.Generation != value.RevisionID || !tokenPattern.MatchString(value.Generation) || !tokenPattern.MatchString(value.RevisionID) || !safeHash(value.CandidateHash) || !safeHash(value.ArtifactManifestHash) {
		return manifest{}, errors.New("route assignment manifest binding is invalid")
	}
	if len(value.Assignments) > maxAssignments {
		return manifest{}, errors.New("route assignment manifest capacity exceeded")
	}
	for _, assignment := range value.Assignments {
		if !safeDomain(assignment.Domain) || !tokenPattern.MatchString(assignment.RouteTag) || !tokenPattern.MatchString(assignment.RouteSetID) || !tokenPattern.MatchString(assignment.AssignmentID) || !safeHash(assignment.MappingHash) {
			return manifest{}, errors.New("route assignment manifest object is invalid")
		}
		switch assignment.RouteType {
		case "direct", "drop", "zapret", "smart_dns", "vless":
		default:
			return manifest{}, errors.New("route assignment manifest route type is not allowlisted")
		}
		if assignment.RouteSetID != routeID(assignment.RouteTag) || assignment.AssignmentID != assignmentID(assignment.Domain) {
			return manifest{}, errors.New("route assignment manifest object binding mismatch")
		}
	}
	return value, nil
}

func readBinding(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	result := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || key == "" {
			continue
		}
		result[key] = value
	}
	for _, key := range []string{"transaction_id", "revision_id", "candidate_hash", "artifact_manifest_hash"} {
		if result[key] == "" {
			return nil, fmt.Errorf("route assignment binding missing %s", key)
		}
	}
	return result, nil
}

func replaceAssignment(items []Assignment, next Assignment) []Assignment {
	for i := range items {
		if items[i].AssignmentID == next.AssignmentID {
			items[i] = next
			return items
		}
	}
	return append(items, next)
}

func removeMatching(items []Assignment, target Assignment) []Assignment {
	result := items[:0]
	for _, item := range items {
		if item.AssignmentID == target.AssignmentID && item.MappingHash == target.MappingHash {
			continue
		}
		result = append(result, item)
	}
	return result
}

func assignmentFrom(request Request) Assignment {
	return Assignment{Domain: strings.ToLower(request.Domain), RouteTag: request.RouteTag, RouteType: request.RouteType, RouteSetID: request.RouteSetID, AssignmentID: request.AssignmentID, MappingHash: request.MappingHash}
}

func routeID(tag string) string {
	sum := sha256.Sum256([]byte("route:" + strings.ToLower(strings.TrimSpace(tag))))
	return hex.EncodeToString(sum[:6])
}

func assignmentID(domain string) string {
	sum := sha256.Sum256([]byte("assignment:" + strings.ToLower(strings.TrimSpace(domain))))
	return hex.EncodeToString(sum[:6])
}

func safeHash(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, r := range value[len("sha256:"):] {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func safeDomain(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "\r\n\x00/\\ \t") {
		return false
	}
	for _, label := range strings.Split(strings.ToLower(value), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func dnsmasqServer(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || net.ParseIP(host) == nil {
		return "", errors.New("invalid route assignment DNS endpoint")
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]#" + port, nil
	}
	return host + "#" + port, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".route-assignment-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func writeJSONAtomic(path string, value any, mode os.FileMode) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeAtomic(path, append(raw, '\n'), mode)
}
