package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

var errIdempotencyKeyConflict = errors.New("idempotency_key_conflict")

// normalizeMutationRequestID validates a client-generated operation ID. It is
// an idempotency handle, not an authorization token; caller identity and a
// canonical request fingerprint are checked separately.
func normalizeMutationRequestID(raw string) (string, error) {
	id := strings.TrimSpace(raw)
	if id == "" {
		return "", nil // backward-compatible with older local clients
	}
	if len(id) < 16 || len(id) > 128 {
		return "", errors.New("request_id must contain 16 to 128 ASCII characters")
	}
	for _, char := range id {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.' || char == ':' {
			continue
		}
		return "", errors.New("request_id contains unsupported characters")
	}
	return id, nil
}

func mutationRequestFingerprint(operation, actor string, payload any) (string, error) {
	canonical, err := json.Marshal(struct {
		Operation string `json:"operation"`
		Actor     string `json:"actor"`
		Payload   any    `json:"payload"`
	}{Operation: operation, Actor: strings.TrimSpace(actor), Payload: payload})
	if err != nil {
		return "", errors.New("could not fingerprint mutation request")
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func (s *Server) findIdempotentMutation(requestID, fingerprint, actor string) (ChangeSet, bool, error) {
	if s == nil || requestID == "" || fingerprint == "" {
		return ChangeSet{}, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.findIdempotentMutationLocked(requestID, fingerprint, actor)
}

func (s *Server) findIdempotentMutationLocked(requestID, fingerprint, actor string) (ChangeSet, bool, error) {
	for _, change := range s.changes {
		if change.RequestID != requestID {
			continue
		}
		if change.Author != actor || change.RequestFingerprint != fingerprint {
			return ChangeSet{}, false, errIdempotencyKeyConflict
		}
		return change, true, nil
	}
	return ChangeSet{}, false, nil
}

// findReplayableEquivalentAutoApply also coalesces retries that outlive the UI
// component (for example, a page reload after a lost response). It matches the
// persisted operation itself, not just a toast, and only returns a live
// journal entry or a committed operation still satisfied by current policy;
// failed/rolled-back operations remain retryable.
func (s *Server) findReplayableEquivalentAutoApply(baseVersion int64, title, description, author string, operations []ChangeOp) (ChangeSet, bool) {
	if s == nil {
		return ChangeSet{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, change := range s.changes {
		if !change.AutoApply || change.BaseVersion != baseVersion || change.Title != title ||
			change.Description != description || change.Author != author || !equivalentChangeOperations(change.Operations, operations) {
			continue
		}
		switch change.State {
		case "draft", "validated", "prepared", "applying", "verifying", "awaiting_confirmation", "committing", "rolling_back", "requires_device", "recovery_required":
			return change, true
		case "committed":
			candidate, _, diff, validations := buildCandidate(s.activeConfig, operations)
			if candidate == nil || len(diff) != 0 {
				continue
			}
			valid := true
			for _, validation := range validations {
				if validation.Level == "error" && validation.Code != "candidate_noop" {
					valid = false
					break
				}
			}
			if valid {
				return change, true
			}
		}
	}
	return ChangeSet{}, false
}

func equivalentChangeOperations(left, right []ChangeOp) bool {
	leftJSON, leftErr := canonicalChangeOperations(left)
	rightJSON, rightErr := canonicalChangeOperations(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func canonicalChangeOperations(operations []ChangeOp) ([]byte, error) {
	raw, err := json.Marshal(operations)
	if err != nil {
		return nil, err
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

// requestIDFromBody validates a key and binds retries to the same actor and
// logical payload. Empty keys retain the old behavior for compatibility.
func requestIDFromBody(raw, operation, actor string, payload any) (string, string, error) {
	requestID, err := normalizeMutationRequestID(raw)
	if err != nil || requestID == "" {
		return requestID, "", err
	}
	fingerprint, err := mutationRequestFingerprint(operation, actor, payload)
	if err != nil {
		return "", "", err
	}
	return requestID, fingerprint, nil
}
