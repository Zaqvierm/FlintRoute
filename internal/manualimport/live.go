package manualimport

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"router-policy/internal/lifecycle"
)

const (
	LiveObservationSchemaVersion = 1
	maxLiveObservationFileBytes  = 4 << 20
)

// LiveObservation is a read-only snapshot of resources named by an adoption
// plan. It is deliberately not a HandoffManifest: it does not claim ownership
// and cannot authorize a ChangeSet. Missing or unreadable evidence is retained
// as an explicit state so a caller cannot mistake an incomplete capture for a
// proof of safety.
type LiveObservation struct {
	SchemaVersion   int                       `json:"schema_version"`
	GeneratedAt     string                    `json:"generated_at"`
	CandidateSHA256 string                    `json:"candidate_sha256"`
	Resources       []LiveResourceObservation `json:"resources"`
}

type LiveResourceObservation struct {
	Kind           string `json:"kind"`
	Identifier     string `json:"identifier"`
	CurrentOwner   string `json:"current_owner"`
	State          string `json:"state"`
	EvidenceSHA256 string `json:"evidence_sha256,omitempty"`
	ConfigSHA256   string `json:"config_sha256,omitempty"`
	Executable     string `json:"executable,omitempty"`
	PID            int    `json:"pid,omitempty"`
	StartTimeTicks uint64 `json:"start_time_ticks,omitempty"`
	PGID           int    `json:"pgid,omitempty"`
	Error          string `json:"error,omitempty"`
}

// LiveProcessTarget identifies a process resource from the reviewed plan.
// ConfigPath is optional and is hashed, never copied into the observation.
type LiveProcessTarget struct {
	Kind       string
	Identifier string
	PID        int
	ConfigPath string
}

// LiveEvidenceTarget identifies an exact evidence file for a plan resource.
// The path itself is intentionally absent from the resulting observation.
type LiveEvidenceTarget struct {
	Kind       string
	Identifier string
	Path       string
}

type liveProcessInspector interface {
	Inspect(pid int) (lifecycle.ProcessIdentity, error)
}

type LiveObservationOptions struct {
	Plan            AdoptionPlan
	ProcessTargets  []LiveProcessTarget
	EvidenceTargets []LiveEvidenceTarget
	Inspector       liveProcessInspector
	GeneratedAt     time.Time
}

func (o LiveObservation) Validate() error {
	if o.SchemaVersion != LiveObservationSchemaVersion {
		return fmt.Errorf("unsupported live observation schema %d", o.SchemaVersion)
	}
	if _, err := time.Parse(time.RFC3339Nano, o.GeneratedAt); err != nil {
		return fmt.Errorf("invalid live observation generated_at: %w", err)
	}
	if _, ok := normalizeSHA256(o.CandidateSHA256); !ok {
		return errors.New("live observation candidate_sha256 must be a 64-character hex digest")
	}
	seen := make(map[string]struct{}, len(o.Resources))
	for _, resource := range o.Resources {
		if strings.TrimSpace(resource.Kind) == "" || strings.TrimSpace(resource.Identifier) == "" {
			return errors.New("live observation resource kind and identifier are required")
		}
		key := resource.Kind + "\x00" + resource.Identifier
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate live observation resource %q", key)
		}
		seen[key] = struct{}{}
		switch resource.State {
		case "observed", "missing", "error":
		default:
			return fmt.Errorf("invalid live observation state %q", resource.State)
		}
		if resource.EvidenceSHA256 != "" {
			if _, ok := normalizeSHA256(resource.EvidenceSHA256); !ok {
				return fmt.Errorf("resource %s/%s evidence_sha256 is invalid", resource.Kind, resource.Identifier)
			}
		}
		if resource.ConfigSHA256 != "" {
			if _, ok := normalizeSHA256(resource.ConfigSHA256); !ok {
				return fmt.Errorf("resource %s/%s config_sha256 is invalid", resource.Kind, resource.Identifier)
			}
		}
		if resource.State == "observed" && resource.Error != "" {
			return fmt.Errorf("observed resource %s/%s has an error", resource.Kind, resource.Identifier)
		}
	}
	return nil
}

// CaptureLiveObservation reads only the exact resources in the adoption plan.
// It never starts, stops, reloads or mutates a process, service, file or
// network object. The default inspector reads /proc metadata only.
func CaptureLiveObservation(opts LiveObservationOptions) (LiveObservation, error) {
	now := opts.GeneratedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	observation := LiveObservation{
		SchemaVersion:   LiveObservationSchemaVersion,
		GeneratedAt:     now.UTC().Format(time.RFC3339Nano),
		CandidateSHA256: strings.TrimSpace(opts.Plan.CandidateSHA256),
		Resources:       []LiveResourceObservation{},
	}
	if opts.Plan.SchemaVersion != 1 {
		return observation, fmt.Errorf("unsupported adoption plan schema %d", opts.Plan.SchemaVersion)
	}
	if _, ok := normalizeSHA256(observation.CandidateSHA256); !ok {
		return observation, errors.New("adoption plan must contain a candidate hash")
	}
	planResources := make(map[string]AdoptionResource, len(opts.Plan.Resources))
	for _, resource := range opts.Plan.Resources {
		if strings.TrimSpace(resource.Kind) == "" || strings.TrimSpace(resource.Identifier) == "" {
			return observation, errors.New("adoption plan contains an invalid resource")
		}
		key := resource.Kind + "\x00" + resource.Identifier
		if _, exists := planResources[key]; exists {
			return observation, fmt.Errorf("adoption plan contains duplicate resource %q", key)
		}
		planResources[key] = resource
	}
	seen := make(map[string]struct{}, len(opts.ProcessTargets)+len(opts.EvidenceTargets))
	for _, target := range opts.ProcessTargets {
		key := target.Kind + "\x00" + target.Identifier
		resource, ok := planResources[key]
		if !ok || resource.Kind != "process" || target.Kind != "process" {
			return observation, fmt.Errorf("process target %s/%s is not a process in the adoption plan", target.Kind, target.Identifier)
		}
		if target.PID <= 0 {
			return observation, fmt.Errorf("process target %s has invalid PID", target.Identifier)
		}
		if _, exists := seen[key]; exists {
			return observation, fmt.Errorf("duplicate live observation target %q", key)
		}
		seen[key] = struct{}{}
	}
	for _, target := range opts.EvidenceTargets {
		key := target.Kind + "\x00" + target.Identifier
		resource, ok := planResources[key]
		if !ok || resource.Kind != target.Kind {
			return observation, fmt.Errorf("evidence target %s/%s is absent from the adoption plan", target.Kind, target.Identifier)
		}
		if strings.TrimSpace(target.Path) == "" {
			return observation, fmt.Errorf("evidence target %s has no path", target.Identifier)
		}
		if _, exists := seen[key]; exists {
			return observation, fmt.Errorf("duplicate live observation target %q", key)
		}
		seen[key] = struct{}{}
	}

	inspector := opts.Inspector
	if inspector == nil {
		inspector = lifecycle.LinuxProcessInspector{}
	}
	observed := make(map[string]LiveResourceObservation, len(planResources))
	for key, resource := range planResources {
		observed[key] = LiveResourceObservation{
			Kind:         resource.Kind,
			Identifier:   resource.Identifier,
			CurrentOwner: resource.ObservedOwner,
			State:        "missing",
		}
	}
	for _, target := range opts.ProcessTargets {
		key := target.Kind + "\x00" + target.Identifier
		resource := observed[key]
		identity, err := inspector.Inspect(target.PID)
		if err != nil {
			resource.State = "error"
			resource.Error = "process_unavailable"
			observed[key] = resource
			continue
		}
		resource.State = "observed"
		resource.PID = identity.PID
		resource.StartTimeTicks = identity.StartTimeTicks
		resource.PGID = identity.PGID
		resource.Executable = identity.Executable
		resource.EvidenceSHA256 = hashLiveProcess(identity)
		if target.ConfigPath != "" {
			configHash, hashErr := hashLiveFile(target.ConfigPath)
			if hashErr != nil {
				resource.State = "error"
				resource.Error = "config_unavailable"
			} else {
				resource.ConfigSHA256 = configHash
			}
		}
		observed[key] = resource
	}
	for _, target := range opts.EvidenceTargets {
		key := target.Kind + "\x00" + target.Identifier
		resource := observed[key]
		digest, err := hashLiveFile(target.Path)
		if err != nil {
			resource.State = "error"
			resource.Error = "evidence_unavailable"
		} else {
			resource.State = "observed"
			resource.EvidenceSHA256 = digest
		}
		observed[key] = resource
	}
	keys := make([]string, 0, len(observed))
	for key := range observed {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		observation.Resources = append(observation.Resources, observed[key])
	}
	if err := observation.Validate(); err != nil {
		return LiveObservation{}, err
	}
	return observation, nil
}

func hashLiveProcess(identity lifecycle.ProcessIdentity) string {
	h := sha256.New()
	_, _ = io.WriteString(h, fmt.Sprintf("pid=%d\x00start=%d\x00pgid=%d\x00exe=%s\x00", identity.PID, identity.StartTimeTicks, identity.PGID, identity.Executable))
	for _, arg := range identity.CommandLine {
		_, _ = io.WriteString(h, arg)
		_, _ = io.WriteString(h, "\x00")
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hashLiveFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("evidence path is not a regular file")
	}
	if info.Size() < 0 || info.Size() > maxLiveObservationFileBytes {
		return "", errors.New("evidence file exceeds bounded size")
	}
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, copyErr := io.CopyN(h, file, maxLiveObservationFileBytes+1)
	closeErr := file.Close()
	if copyErr != nil && !errors.Is(copyErr, io.EOF) {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
