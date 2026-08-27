package api

import "context"

// RouteAssignmentRequest is the complete binding a runtime consumer must
// enforce before changing an existing owned domain mapping.  It deliberately
// contains no arbitrary path, shell fragment or topology instruction.
type RouteAssignmentRequest struct {
	ProtocolVersion      int
	RequestID            string
	Generation           string
	RevisionID           string
	CandidateHash        string
	ArtifactManifestHash string
	Domain               string
	RouteTag             string
	RouteType            string
}

// RouteAssignmentReceipt is a semantic acknowledgement, not an exit code.
// Applied and Verified are both required before the controller can persist a
// selected decision or tell the UI that the mapping was applied.
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
	MappingHash     string
}

// RouteAssignmentRuntime is the narrow boundary for an already-existing
// route-only mapping.  A nil implementation is a deliberate safety fence:
// discovery may produce suggestions, but it cannot claim a production route
// assignment. Implementations must mutate only exact owned resources and must
// make rollback idempotent.
type RouteAssignmentRuntime interface {
	ApplyRouteAssignment(context.Context, RouteAssignmentRequest) (RouteAssignmentReceipt, error)
	RollbackRouteAssignment(context.Context, RouteAssignmentRequest, RouteAssignmentReceipt) error
}
