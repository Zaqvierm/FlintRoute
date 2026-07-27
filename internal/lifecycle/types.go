package lifecycle

import (
	"fmt"
	"regexp"
	"time"
)

const ManifestSchemaVersion = 1

type OwnerClass string

const (
	OwnerProduction  OwnerClass = "production"
	OwnerTransaction OwnerClass = "transaction"
	OwnerTestRun     OwnerClass = "test-run"
	OwnerInstaller   OwnerClass = "installer"
	OwnerRecovery    OwnerClass = "recovery"
)

var ownerIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Owner struct {
	Class OwnerClass `json:"class"`
	ID    string     `json:"id,omitempty"`
}

func (o Owner) String() string {
	if o.Class == OwnerProduction {
		return string(o.Class)
	}
	return string(o.Class) + ":" + o.ID
}

func (o Owner) Validate() error {
	switch o.Class {
	case OwnerProduction:
		if o.ID != "" {
			return fmt.Errorf("production owner must not have an ID")
		}
	case OwnerTransaction, OwnerTestRun, OwnerInstaller, OwnerRecovery:
		if !ownerIDPattern.MatchString(o.ID) {
			return fmt.Errorf("invalid %s owner ID", o.Class)
		}
	default:
		return fmt.Errorf("unknown owner class %q", o.Class)
	}
	return nil
}

type ResourceKind string

const (
	ResourceProcess    ResourceKind = "process"
	ResourceListener   ResourceKind = "listener"
	ResourceNFTTable   ResourceKind = "nft-table"
	ResourceNFTChain   ResourceKind = "nft-chain"
	ResourceNFTSet     ResourceKind = "nft-set"
	ResourceNFTRule    ResourceKind = "nft-rule"
	ResourceFW4Include ResourceKind = "fw4-include"
	ResourceIPRule     ResourceKind = "ip-rule"
	ResourceRoute      ResourceKind = "route"
	ResourceFile       ResourceKind = "file"
	ResourceSnapshot   ResourceKind = "snapshot"
	ResourceArtifact   ResourceKind = "artifact"
	ResourceTimer      ResourceKind = "timer"
	ResourceLock       ResourceKind = "lock"
	ResourceService    ResourceKind = "service"
)

type ProcessIdentity struct {
	PID            int      `json:"pid"`
	StartTimeTicks uint64   `json:"start_time_ticks"`
	Executable     string   `json:"executable"`
	ConfigPath     string   `json:"config_path,omitempty"`
	CommandLine    []string `json:"command_line,omitempty"`
	Service        string   `json:"service,omitempty"`
	Instance       string   `json:"instance,omitempty"`
}

type Resource struct {
	ID           string            `json:"id"`
	Kind         ResourceKind      `json:"kind"`
	Owner        Owner             `json:"owner"`
	Process      *ProcessIdentity  `json:"process,omitempty"`
	Path         string            `json:"path,omitempty"`
	Address      string            `json:"address,omitempty"`
	Family       string            `json:"family,omitempty"`
	Table        string            `json:"table,omitempty"`
	Name         string            `json:"name,omitempty"`
	Arguments    []string          `json:"arguments,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	AllowCleanup bool              `json:"allow_cleanup"`
}

type Baseline struct {
	CapturedAt string          `json:"captured_at"`
	Resources  []Resource      `json:"resources"`
	Checks     []BaselineCheck `json:"checks,omitempty"`
}

type BaselineCheck struct {
	Name      string `json:"name"`
	SHA256    string `json:"sha256,omitempty"`
	Lines     int    `json:"lines"`
	Available bool   `json:"available"`
	Error     string `json:"error,omitempty"`
}

type BaselineComparison struct {
	Name      string `json:"name"`
	Matches   bool   `json:"matches"`
	Available bool   `json:"available"`
	Expected  string `json:"expected,omitempty"`
	Actual    string `json:"actual,omitempty"`
	Error     string `json:"error,omitempty"`
}

type Manifest struct {
	SchemaVersion int        `json:"schema_version"`
	RunID         string     `json:"run_id"`
	Owner         Owner      `json:"owner"`
	CreatedAt     string     `json:"created_at"`
	ExpiresAt     string     `json:"expires_at"`
	Baseline      Baseline   `json:"baseline"`
	Resources     []Resource `json:"resources"`
	CleanupState  string     `json:"cleanup_state"`
	FinalResult   string     `json:"final_result,omitempty"`
}

func (m Manifest) Validate() error {
	if m.SchemaVersion != ManifestSchemaVersion {
		return fmt.Errorf("unsupported lifecycle manifest schema %d", m.SchemaVersion)
	}
	if !ownerIDPattern.MatchString(m.RunID) {
		return fmt.Errorf("invalid run ID")
	}
	if err := m.Owner.Validate(); err != nil {
		return err
	}
	if m.Owner.Class != OwnerTestRun || m.Owner.ID != m.RunID {
		return fmt.Errorf("test-run manifest owner does not match run ID")
	}
	created, err := time.Parse(time.RFC3339, m.CreatedAt)
	if err != nil {
		return fmt.Errorf("invalid created_at: %w", err)
	}
	expires, err := time.Parse(time.RFC3339, m.ExpiresAt)
	if err != nil || !expires.After(created) {
		return fmt.Errorf("invalid expires_at")
	}
	seen := map[string]struct{}{}
	for _, resource := range m.Resources {
		if resource.ID == "" {
			return fmt.Errorf("resource ID is required")
		}
		if _, ok := seen[resource.ID]; ok {
			return fmt.Errorf("duplicate resource ID %q", resource.ID)
		}
		seen[resource.ID] = struct{}{}
		if err := resource.Owner.Validate(); err != nil {
			return fmt.Errorf("resource %s: %w", resource.ID, err)
		}
		if resource.Owner != m.Owner {
			return fmt.Errorf("resource %s owner differs from manifest owner", resource.ID)
		}
		if resource.Kind == ResourceProcess && resource.Process == nil {
			return fmt.Errorf("resource %s has no process identity", resource.ID)
		}
	}
	return nil
}

type CleanupAction struct {
	RunID           string       `json:"run_id"`
	ResourceID      string       `json:"resource_id,omitempty"`
	Kind            ResourceKind `json:"kind,omitempty"`
	Owner           string       `json:"owner"`
	Reason          string       `json:"reason"`
	OwnershipChecks []string     `json:"ownership_checks,omitempty"`
	Action          string       `json:"action"`
	Applied         bool         `json:"applied"`
	Skipped         bool         `json:"skipped"`
}

type CleanupReport struct {
	DryRun              bool                 `json:"dry_run"`
	GeneratedAt         string               `json:"generated_at"`
	StaleRuns           int                  `json:"stale_runs"`
	Actions             []CleanupAction      `json:"actions"`
	ProtectedProduction int                  `json:"protected_production"`
	AmbiguousSkipped    int                  `json:"ambiguous_skipped"`
	Baseline            []BaselineComparison `json:"baseline,omitempty"`
}
