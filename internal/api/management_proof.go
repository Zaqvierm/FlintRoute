package api

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"router-policy/internal/adapter"
	"router-policy/internal/managementproof"
	"router-policy/internal/state"
)

type automaticManagementProofContextKey struct{}

func withAutomaticManagementProof(ctx context.Context) context.Context {
	return context.WithValue(ctx, automaticManagementProofContextKey{}, true)
}

func automaticManagementProofRequested(ctx context.Context) bool {
	value, _ := ctx.Value(automaticManagementProofContextKey{}).(bool)
	return value
}

func proofBinding(tx adapter.Transaction) managementproof.Binding {
	return managementproof.Binding{TransactionID: tx.ID, RevisionID: tx.RevisionID}
}

func (s *Server) prepareManagementProof(request *http.Request, action ChangeActionRequest, cs ChangeSet) (ChangeSet, *actionFailure) {
	release, failure := s.acquireMutationLease()
	if failure != nil {
		return cs, failure
	}
	defer release()
	tx, failure := s.loadVerifiedTransaction(cs)
	if failure != nil {
		return cs, failure
	}
	mode := strings.ToLower(strings.TrimSpace(action.ManagementMode))
	if mode == "" {
		mode = managementproof.ModeLAN
	}
	switch mode {
	case managementproof.ModeLAN:
		seconds := tx.RollbackTimeoutSeconds
		if seconds <= 0 {
			seconds = 120
		}
		var refreshFailure *actionFailure
		cs, tx, refreshFailure = s.refreshRollbackWindow(cs, tx, seconds)
		if refreshFailure != nil {
			return cs, refreshFailure
		}
		if _, err := s.managementProofs.IssueLANRequest(request.Context(), proofBinding(tx), request, time.Duration(seconds)*time.Second); err != nil {
			return cs, conflict("management_proof_unavailable", err.Error())
		}
	case managementproof.ModeHeadless:
		proof, err := s.managementProofs.Verify(proofBinding(tx))
		if err != nil {
			return cs, conflict("headless_management_proof_invalid", err.Error())
		}
		if proof.Mode != managementproof.ModeHeadless {
			return cs, conflict("headless_management_proof_invalid", "headless apply requires an SSH-issued proof")
		}
		seconds := tx.RollbackTimeoutSeconds * 3
		if seconds < 600 {
			seconds = 600
		}
		if seconds > 3600 {
			seconds = 3600
		}
		var extendFailure *actionFailure
		cs, _, extendFailure = s.refreshRollbackWindow(cs, tx, seconds)
		if extendFailure != nil {
			return cs, extendFailure
		}
	default:
		return cs, &actionFailure{Status: http.StatusBadRequest, Code: "management_mode_invalid", Message: "management_mode must be lan or headless"}
	}
	return cs, nil
}

func (s *Server) verifyManagementConfirmation(request *http.Request, action ChangeActionRequest, cs ChangeSet) *actionFailure {
	tx, failure := s.loadVerifiedTransaction(cs)
	if failure != nil {
		return failure
	}
	proof, err := s.managementProofs.Verify(proofBinding(tx))
	if err != nil {
		return conflict("management_proof_invalid", err.Error())
	}
	switch proof.Mode {
	case managementproof.ModeLAN:
		if _, err := s.managementProofs.VerifyLANConfirmation(proofBinding(tx), request); err != nil {
			return conflict("management_confirmation_path_mismatch", err.Error())
		}
	case managementproof.ModeHeadless:
		if strings.ToLower(strings.TrimSpace(action.ManagementMode)) != managementproof.ModeHeadless || !requestUsesLoopback(request) {
			return conflict("headless_confirmation_required", "headless confirmation must be explicit and submitted through the router loopback API")
		}
	case managementproof.ModeAutomatic:
		return conflict("automatic_confirmation_forbidden", "automatic proof cannot be confirmed through the management API")
	default:
		return conflict("management_proof_invalid", "management proof mode is invalid")
	}
	return nil
}

func (s *Server) ensureAutomaticManagementProof(ctx context.Context, tx adapter.Transaction) *actionFailure {
	if !s.requireManagementProof || !automaticManagementProofRequested(ctx) {
		return nil
	}
	if proof, err := s.managementProofs.Verify(proofBinding(tx)); err == nil && proof.Mode == managementproof.ModeAutomatic {
		return nil
	}
	ttl := time.Duration(tx.RollbackTimeoutSeconds) * time.Second
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	if _, err := s.managementProofs.IssueAutomatic(ctx, proofBinding(tx), ttl); err != nil {
		return conflict("automatic_management_proof_unavailable", err.Error())
	}
	return nil
}

func (s *Server) refreshRollbackWindow(cs ChangeSet, tx adapter.Transaction, seconds int) (ChangeSet, adapter.Transaction, *actionFailure) {
	if seconds < 1 || seconds > 3600 {
		return cs, tx, conflict("rollback_window_invalid", "rollback window must be between 1 and 3600 seconds")
	}
	now := time.Now().UTC()
	tx.RollbackTimeoutSeconds = seconds
	tx.ExpiresAt = now.Add(time.Duration(seconds) * time.Second)
	if err := adapter.PersistBinding(tx); err != nil {
		return cs, tx, internalFailure(err)
	}
	var record transactionRecord
	if err := s.store.LoadJSON("transactions", tx.ID, &record); err != nil {
		return cs, tx, internalFailure(err)
	}
	record.Transaction = tx
	record.UpdatedAt = now
	cs.ExpiresAt = tx.ExpiresAt.Format(time.RFC3339)
	cs.Version++
	cs.UpdatedAt = now.Format(time.RFC3339)
	if err := s.store.SaveBatch(
		state.Entry{Bucket: "transactions", Key: tx.ID, Value: record},
		state.Entry{Bucket: "changes", Key: cs.ID, Value: cs},
	); err != nil {
		return cs, tx, internalFailure(err)
	}
	s.setChange(cs)
	return cs, tx, nil
}

func requestUsesLoopback(request *http.Request) bool {
	if request == nil {
		return false
	}
	remoteHost, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil || !net.ParseIP(strings.Trim(remoteHost, "[]")).IsLoopback() {
		return false
	}
	local, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok || local == nil {
		return false
	}
	localHost, _, err := net.SplitHostPort(local.String())
	return err == nil && net.ParseIP(strings.Trim(localHost, "[]")).IsLoopback()
}
