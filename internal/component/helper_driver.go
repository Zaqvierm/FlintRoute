package component

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"router-policy/internal/helper"
	"router-policy/internal/secureid"
)

// HelperDriver is the production component driver. Read-only inspection and
// health checks use the existing component driver; service lifecycle changes
// go through the typed root helper. Package install/update/uninstall remain
// intentionally unavailable here and must be part of a reviewed installer or
// ChangeSet, never a direct controller-side file mutation.
type HelperDriver struct {
	base       OpenWrtDriver
	socket     string
	stateDir   string
	runtimeDir string
}

func NewHelperDriver(base OpenWrtDriver, socket, stateDir, runtimeDir string) (*HelperDriver, error) {
	if socket == "" || !filepath.IsAbs(socket) || filepath.Base(socket) != "helper.sock" {
		return nil, errors.New("helper socket path is not allowlisted")
	}
	if stateDir == "" || runtimeDir == "" {
		return nil, errors.New("component helper state paths are required")
	}
	return &HelperDriver{base: base, socket: socket, stateDir: stateDir, runtimeDir: runtimeDir}, nil
}

func (d *HelperDriver) Platform(ctx context.Context) (Platform, error) {
	return d.base.Platform(ctx)
}

func (d *HelperDriver) Inspect(ctx context.Context, kind Kind) (Health, bool, string, error) {
	return d.base.Inspect(ctx, kind)
}

func (d *HelperDriver) Preflight(ctx context.Context, release Release, asset Asset) (Preflight, error) {
	return d.base.Preflight(ctx, release, asset)
}

func (d *HelperDriver) Install(context.Context, Release, Asset, string, Record) (Record, error) {
	return Record{}, errors.New("component install requires the reviewed installer path")
}

func (d *HelperDriver) Restart(ctx context.Context, kind Kind) error {
	service, err := helperServiceName(kind)
	if err != nil {
		return err
	}
	binding, err := d.loadBinding()
	if err != nil {
		return err
	}
	health, _, _, healthErr := d.base.Inspect(ctx, kind)
	operation := "start"
	if healthErr == nil && health.ServiceState == "running" {
		operation = "reload"
	}
	requestID, err := secureid.Hex(12)
	if err != nil {
		return fmt.Errorf("generate component request id: %w", err)
	}
	_, err = helper.Call(ctx, d.socket, helper.Request{
		ProtocolVersion:      helper.ProtocolVersion,
		RequestID:            requestID,
		Command:              "service." + operation,
		Generation:           binding.RevisionID,
		RevisionID:           binding.RevisionID,
		TransactionID:        binding.TransactionID,
		RollbackTokenHash:    binding.RollbackTokenHash,
		CandidateHash:        binding.CandidateHash,
		ArtifactManifestHash: binding.ArtifactManifestHash,
		Service:              &helper.ServiceRequest{Name: service, Operation: operation},
	})
	if err != nil {
		return fmt.Errorf("component service %s: %w", operation, err)
	}
	verified, err := d.base.Health(ctx, kind)
	if err != nil || !verified.Ready {
		return fmt.Errorf("component did not recover after %s: %s", operation, verified.Reason)
	}
	return nil
}

func (d *HelperDriver) Rollback(context.Context, Record) (Record, error) {
	return Record{}, errors.New("component rollback requires the reviewed installer path")
}

func (d *HelperDriver) Uninstall(context.Context, Kind, bool) error {
	return errors.New("component uninstall requires the reviewed installer path")
}

func (d *HelperDriver) Health(ctx context.Context, kind Kind) (Health, error) {
	return d.base.Health(ctx, kind)
}

type componentBinding struct {
	TransactionID        string
	RevisionID           string
	CandidateHash        string
	ArtifactManifestHash string
	RollbackTokenHash    string
}

func (d *HelperDriver) loadBinding() (componentBinding, error) {
	raw, err := os.ReadFile(filepath.Join(d.runtimeDir, "active-transaction.env"))
	if err != nil {
		return componentBinding{}, fmt.Errorf("active component binding unavailable: %w", err)
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || values[key] != "" {
			return componentBinding{}, errors.New("active component binding is invalid")
		}
		values[key] = value
	}
	if values["transaction_state"] != "committed" {
		return componentBinding{}, errors.New("component lifecycle is fenced until active revision is committed")
	}
	binding := componentBinding{
		TransactionID: values["transaction_id"], RevisionID: values["revision_id"],
		CandidateHash: values["candidate_hash"], ArtifactManifestHash: values["artifact_manifest_hash"],
	}
	if !safeBindingToken(binding.TransactionID) || !safeBindingToken(binding.RevisionID) ||
		!safeBindingHash(binding.CandidateHash) || !safeBindingHash(binding.ArtifactManifestHash) {
		return componentBinding{}, errors.New("active component binding identity is invalid")
	}
	bindingPath := filepath.Join(d.stateDir, "transactions", binding.RevisionID, binding.TransactionID, "binding.env")
	bindingRaw, err := os.ReadFile(bindingPath)
	if err != nil {
		return componentBinding{}, fmt.Errorf("component rollback binding unavailable: %w", err)
	}
	for _, line := range strings.Split(string(bindingRaw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok && key == "rollback_token_hash" {
			binding.RollbackTokenHash = value
		}
	}
	if binding.TransactionID == "" || binding.RevisionID == "" || binding.CandidateHash == "" || binding.ArtifactManifestHash == "" || binding.RollbackTokenHash == "" {
		return componentBinding{}, errors.New("active component binding is incomplete")
	}
	if !safeBindingHash(binding.RollbackTokenHash) {
		return componentBinding{}, errors.New("active component rollback binding is invalid")
	}
	return binding, nil
}

func safeBindingToken(value string) bool {
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "/\\\r\n\x00 ") {
		return false
	}
	return true
}

func safeBindingHash(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, char := range value[len("sha256:"):] {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func helperServiceName(kind Kind) (string, error) {
	switch kind {
	case KindXray:
		return "router-policy-xray", nil
	case KindZapret:
		return "router-policy-zapret", nil
	default:
		return "", errors.New("component lifecycle is not available through the helper")
	}
}

var _ Driver = (*HelperDriver)(nil)
