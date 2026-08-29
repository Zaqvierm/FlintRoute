package main

import (
	"context"

	"router-policy/internal/adapter"
	"router-policy/internal/api"
)

// openWrtRouteAssignmentRuntime is the production bridge from the API's
// route-only contract to the typed helper-backed adapter. Keeping this bridge
// at the process boundary avoids importing the command package into api and
// makes the unavailable runtime an explicit safety fence in tests.
type openWrtRouteAssignmentRuntime struct {
	adapter *adapter.OpenWrt
}

func (r openWrtRouteAssignmentRuntime) ApplyRouteAssignment(ctx context.Context, request api.RouteAssignmentRequest) (api.RouteAssignmentReceipt, error) {
	receipt, err := r.adapter.ApplyOwnedRouteAssignment(ctx, adapter.RouteAssignmentRequest{
		RequestID: request.RequestID, Generation: request.Generation, RevisionID: request.RevisionID,
		CandidateHash: request.CandidateHash, ArtifactManifestHash: request.ArtifactManifestHash,
		Domain: request.Domain, RouteTag: request.RouteTag, RouteType: request.RouteType,
		RouteSetID: request.RouteSetID, AssignmentID: request.AssignmentID, MappingHash: request.MappingHash,
	})
	if err != nil {
		return api.RouteAssignmentReceipt{}, err
	}
	return api.RouteAssignmentReceipt{
		ProtocolVersion: receipt.ProtocolVersion, RequestID: receipt.RequestID, Operation: receipt.Operation,
		Applied: receipt.Applied, Verified: receipt.Verified, Generation: receipt.Generation, RevisionID: receipt.RevisionID,
		Domain: receipt.Domain, RouteTag: receipt.RouteTag, RouteType: receipt.RouteType, RouteSetID: receipt.RouteSetID,
		AssignmentID: receipt.AssignmentID, MappingHash: receipt.MappingHash,
	}, nil
}

func (r openWrtRouteAssignmentRuntime) RollbackRouteAssignment(ctx context.Context, request api.RouteAssignmentRequest, receipt api.RouteAssignmentReceipt) error {
	return r.adapter.RollbackOwnedRouteAssignment(ctx, adapter.RouteAssignmentRequest{
		RequestID: request.RequestID, Generation: request.Generation, RevisionID: request.RevisionID,
		CandidateHash: request.CandidateHash, ArtifactManifestHash: request.ArtifactManifestHash,
		Domain: request.Domain, RouteTag: request.RouteTag, RouteType: request.RouteType,
		RouteSetID: request.RouteSetID, AssignmentID: request.AssignmentID, MappingHash: request.MappingHash,
	}, adapter.RouteAssignmentReceipt{
		ProtocolVersion: receipt.ProtocolVersion, RequestID: receipt.RequestID, Operation: receipt.Operation,
		Applied: receipt.Applied, Verified: receipt.Verified, Generation: receipt.Generation, RevisionID: receipt.RevisionID,
		Domain: receipt.Domain, RouteTag: receipt.RouteTag, RouteType: receipt.RouteType, RouteSetID: receipt.RouteSetID,
		AssignmentID: receipt.AssignmentID, MappingHash: receipt.MappingHash,
	})
}

func (r openWrtRouteAssignmentRuntime) ReconcileRouteAssignments(ctx context.Context) error {
	return r.adapter.ReconcileOwnedRouteAssignments(ctx)
}
