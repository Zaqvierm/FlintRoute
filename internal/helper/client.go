package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"time"
)

// Call sends one bounded typed request to the local privileged helper.  It
// deliberately speaks only the JSON protocol; callers cannot smuggle a shell
// command or a path through this client.
func Call(ctx context.Context, socket string, request Request) (Response, error) {
	if socket == "" || !filepath.IsAbs(socket) || filepath.Base(socket) != "helper.sock" {
		return Response{}, errors.New("helper socket path is not allowlisted")
	}
	if err := ValidateRequest(request); err != nil {
		return Response{}, err
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return Response{}, fmt.Errorf("connect helper: %w", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(maxRequestDuration))
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return Response{}, fmt.Errorf("write helper request: %w", err)
	}
	decoder := json.NewDecoder(connection)
	// The privileged side is a closed protocol.  Do not accept a response
	// carrying fields this client does not understand: an apparently valid
	// prefix must not hide an out-of-contract operation or security-relevant
	// state added by a mismatched helper binary.
	decoder.DisallowUnknownFields()
	var response Response
	if err := decoder.Decode(&response); err != nil {
		return Response{}, fmt.Errorf("read helper response: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return response, errors.New("helper response contains trailing JSON")
		}
		return response, fmt.Errorf("read helper response trailing data: %w", err)
	}
	if response.ProtocolVersion != ProtocolVersion || response.RequestID != request.RequestID || response.Command != request.Command || response.Generation != request.Generation || response.RevisionID != request.RevisionID || response.TransactionID != request.TransactionID || response.CandidateHash != request.CandidateHash || response.ArtifactManifestHash != request.ArtifactManifestHash || response.RollbackTokenHash != request.RollbackTokenHash {
		return response, errors.New("helper response binding mismatch")
	}
	if !response.Accepted {
		return response, fmt.Errorf("helper operation rejected: %s", response.ErrorCode)
	}
	return response, nil
}
