package api

import (
	"time"

	"router-policy/internal/adapter"
)

type ErrorResponse struct {
	RequestID string   `json:"request_id"`
	Error     APIError `json:"error"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Envelope struct {
	RequestID string `json:"request_id"`
	Data      any    `json:"data"`
}

type Event struct {
	ID          int64          `json:"id"`
	StreamEpoch string         `json:"stream_epoch"`
	Time        string         `json:"time"`
	Type        string         `json:"type"`
	Severity    string         `json:"severity"`
	DeviceID    string         `json:"device_id,omitempty"`
	ServiceID   string         `json:"service_id,omitempty"`
	Domain      string         `json:"domain,omitempty"`
	Route       string         `json:"route,omitempty"`
	ReasonCode  string         `json:"reason_code"`
	Details     map[string]any `json:"details"`
}

type ChangeSet struct {
	ID                   string               `json:"id"`
	State                string               `json:"state"`
	Title                string               `json:"title"`
	Description          string               `json:"description"`
	BaseVersion          int64                `json:"base_version"`
	Version              int64                `json:"version"`
	CandidateVersion     int64                `json:"candidate_version,omitempty"`
	CandidateHash        string               `json:"candidate_hash,omitempty"`
	CandidatePath        string               `json:"candidate_path,omitempty"`
	ArtifactManifestHash string               `json:"artifact_manifest_hash,omitempty"`
	ArtifactsReady       bool                 `json:"artifacts_ready"`
	ArtifactBlockReason  string               `json:"artifact_block_reason,omitempty"`
	ArtifactsSimulation  bool                 `json:"artifacts_simulation"`
	RevisionID           string               `json:"revision_id,omitempty"`
	TransactionID        string               `json:"transaction_id,omitempty"`
	AdapterStatus        string               `json:"adapter_status,omitempty"`
	Operations           []ChangeOp           `json:"operations"`
	Validation           []Validation         `json:"validation"`
	Diff                 []ChangeOp           `json:"diff"`
	Steps                []adapter.StepResult `json:"steps,omitempty"`
	ManagementVerified   bool                 `json:"management_verified"`
	DataPlaneVerified    bool                 `json:"data_plane_verified"`
	CreatedAt            string               `json:"created_at"`
	UpdatedAt            string               `json:"updated_at"`
	ExpiresAt            string               `json:"expires_at,omitempty"`
	Author               string               `json:"author"`
}

type ChangeOp struct {
	Type   string `json:"type"`
	Path   string `json:"path"`
	Value  any    `json:"value,omitempty"`
	Before any    `json:"before,omitempty"`
}

type Validation struct {
	Level   string `json:"level"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Session struct {
	ID        string    `json:"id"`
	User      string    `json:"user"`
	Role      string    `json:"role"`
	CSRFToken string    `json:"csrf_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type SetupRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	SetupToken string `json:"setup_token"`
}

type ChangeSetRequest struct {
	Title       string     `json:"title"`
	Description string     `json:"description"`
	BaseVersion int64      `json:"base_version"`
	Operations  []ChangeOp `json:"operations"`
}

type ChangeActionRequest struct {
	Version int64 `json:"version,omitempty"`
}
