package adapter

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"router-policy/internal/helper"
)

// RouteAssignmentRequest is the adapter-side representation of a bounded
// domain-to-existing-route mutation. It deliberately contains no filesystem
// path or shell fragment; the helper resolves those from its fixed config.
type RouteAssignmentRequest struct {
	RequestID            string
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
}

type RouteAssignmentReceipt struct {
	ProtocolVersion int
	RequestID       string
	Operation       string
	Applied         bool
	Verified        bool
	Generation      string
	RevisionID      string
	Domain          string
	RouteTag        string
	RouteType       string
	RouteSetID      string
	AssignmentID    string
	MappingHash     string
}

func (a *OpenWrt) ApplyOwnedRouteAssignment(ctx context.Context, request RouteAssignmentRequest) (RouteAssignmentReceipt, error) {
	return a.executeRouteAssignment(ctx, request, "apply")
}

func (a *OpenWrt) RollbackOwnedRouteAssignment(ctx context.Context, request RouteAssignmentRequest, receipt RouteAssignmentReceipt) error {
	if receipt.RequestID != request.RequestID || receipt.MappingHash != request.MappingHash || receipt.Domain != request.Domain || receipt.RouteTag != request.RouteTag {
		return fmt.Errorf("route assignment rollback receipt does not bind to request")
	}
	result, err := a.executeRouteAssignment(ctx, request, "rollback")
	if err != nil {
		return err
	}
	if result.Operation != "route_assignment.rollback" || result.Generation != request.Generation || result.RevisionID != request.RevisionID || result.Domain != request.Domain || result.RouteTag != request.RouteTag || result.RouteType != request.RouteType || result.RouteSetID != request.RouteSetID || result.AssignmentID != request.AssignmentID || result.MappingHash != request.MappingHash {
		return fmt.Errorf("route assignment rollback response binding mismatch")
	}
	return nil
}

func (a *OpenWrt) ReconcileOwnedRouteAssignments(ctx context.Context) error {
	if a == nil || a.helperSocket == "" {
		return fmt.Errorf("route assignment helper is unavailable")
	}
	values, err := readRouteAssignmentBinding(a.stateDir)
	if err != nil {
		return err
	}
	requestID, err := secureRandomHex(8)
	if err != nil {
		return err
	}
	wire := helper.Request{
		ProtocolVersion:      helper.ProtocolVersion,
		RequestID:            "req_" + requestID,
		Command:              "route_assignment.reconcile",
		Generation:           values["revision_id"],
		RevisionID:           values["revision_id"],
		TransactionID:        "route-assignment",
		CandidateHash:        values["candidate_hash"],
		ArtifactManifestHash: values["artifact_manifest_hash"],
	}
	response, err := helper.Call(ctx, a.helperSocket, wire)
	if err != nil {
		return err
	}
	if response.Operation != "route_assignment.reconcile" || response.Evidence["reconciled"] != "true" || response.Evidence["verified"] != "true" {
		return fmt.Errorf("helper did not semantically confirm route assignment reconcile")
	}
	return nil
}

func readRouteAssignmentBinding(stateDir string) (map[string]string, error) {
	paths := []string{
		// The controller runs as the unprivileged daemon user. The durable
		// last-good directory is intentionally root-owned, so the adapter's
		// runtime binding is the readable, generation-bound source for the
		// route-assignment reconciler after restart.
		"/tmp/router-policy/active-transaction.env",
		filepath.Join(stateDir, "last-good", "active-transaction.env"),
		filepath.Join(stateDir, "last-good", "transaction.env"),
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		values := map[string]string{}
		for _, line := range strings.Split(string(raw), "\n") {
			key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
			if ok {
				values[key] = value
			}
		}
		if values["revision_id"] != "" && values["candidate_hash"] != "" && values["artifact_manifest_hash"] != "" {
			return values, nil
		}
	}
	return nil, fmt.Errorf("route assignment committed binding is unavailable")
}

func (a *OpenWrt) executeRouteAssignment(ctx context.Context, request RouteAssignmentRequest, operation string) (RouteAssignmentReceipt, error) {
	if a == nil || a.helperSocket == "" {
		return RouteAssignmentReceipt{}, fmt.Errorf("route assignment helper is unavailable")
	}
	if strings.TrimSpace(request.RequestID) == "" || request.Generation == "" || request.RevisionID == "" || request.CandidateHash == "" || request.ArtifactManifestHash == "" || request.Domain == "" || request.RouteTag == "" || request.RouteType == "" || request.RouteSetID == "" || request.AssignmentID == "" || request.MappingHash == "" {
		return RouteAssignmentReceipt{}, fmt.Errorf("route assignment request is incomplete")
	}
	randomID := request.RequestID
	if randomID == "" {
		value, err := secureRandomHex(8)
		if err != nil {
			return RouteAssignmentReceipt{}, err
		}
		randomID = "req_" + value
	}
	wire := helper.Request{
		ProtocolVersion:      helper.ProtocolVersion,
		RequestID:            randomID,
		Command:              "route_assignment." + operation,
		Generation:           request.Generation,
		RevisionID:           request.RevisionID,
		TransactionID:        "route-assignment",
		CandidateHash:        request.CandidateHash,
		ArtifactManifestHash: request.ArtifactManifestHash,
		RouteAssignment: &helper.RouteAssignmentRequest{
			Operation: operation, Domain: request.Domain, RouteTag: request.RouteTag, RouteType: request.RouteType,
			RouteSetID: request.RouteSetID, AssignmentID: request.AssignmentID, MappingHash: request.MappingHash,
		},
	}
	response, err := helper.Call(ctx, a.helperSocket, wire)
	if err != nil {
		return RouteAssignmentReceipt{}, err
	}
	if response.RouteAssignment == nil {
		return RouteAssignmentReceipt{}, fmt.Errorf("helper omitted route assignment response")
	}
	r := response.RouteAssignment
	receipt := RouteAssignmentReceipt{
		ProtocolVersion: response.ProtocolVersion, RequestID: response.RequestID, Operation: response.Operation,
		Applied: r.Applied, Verified: r.Verified, Generation: response.Generation, RevisionID: response.RevisionID,
		Domain: r.Domain, RouteTag: r.RouteTag, RouteType: r.RouteType, RouteSetID: r.RouteSetID,
		AssignmentID: r.AssignmentID, MappingHash: r.MappingHash,
	}
	if operation == "apply" && (!receipt.Applied || !receipt.Verified || receipt.Operation != "route_assignment.apply") {
		return receipt, fmt.Errorf("helper did not semantically confirm route assignment apply")
	}
	if operation == "rollback" && receipt.Operation != "route_assignment.rollback" {
		return receipt, fmt.Errorf("helper did not semantically confirm route assignment rollback")
	}
	return receipt, nil
}
