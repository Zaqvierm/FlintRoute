package adapter

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"router-policy/internal/helper"
)

func TestApplyOwnedRouteAssignmentUsesTypedHelperBoundary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix helper transport is exercised on Linux")
	}
	socket := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	request := RouteAssignmentRequest{
		RequestID:            "route-assignment-1",
		Generation:           "rev_1_001122334455",
		RevisionID:           "rev_1_001122334455",
		CandidateHash:        "sha256:" + strings.Repeat("a", 64),
		ArtifactManifestHash: "sha256:" + strings.Repeat("b", 64),
		Domain:               "youtube.com",
		RouteTag:             "vless-de",
		RouteType:            "vless",
		RouteSetID:           "0123456789ab",
		AssignmentID:         "abcdef012345",
		MappingHash:          "sha256:" + strings.Repeat("c", 64),
	}
	done := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer connection.Close()
		var wire helper.Request
		if err := json.NewDecoder(connection).Decode(&wire); err != nil {
			done <- err
			return
		}
		if wire.Command != "route_assignment.apply" || wire.TransactionID != "route-assignment" || wire.RouteAssignment == nil || wire.RouteAssignment.Domain != request.Domain || wire.RouteAssignment.RouteTag != request.RouteTag {
			done <- os.ErrInvalid
			return
		}
		response := helper.ResponseFrom(wire, true, "", "")
		response.Operation = "route_assignment.apply"
		response.RouteAssignment = &helper.RouteAssignmentResponse{
			Domain: request.Domain, RouteTag: request.RouteTag, RouteType: request.RouteType,
			RouteSetID: request.RouteSetID, AssignmentID: request.AssignmentID,
			MappingHash: request.MappingHash, Applied: true, Verified: true,
		}
		done <- json.NewEncoder(connection).Encode(response)
	}()

	openWrt := &OpenWrt{helperSocket: socket, configPath: filepath.Join(t.TempDir(), "default.json")}
	receipt, err := openWrt.ApplyOwnedRouteAssignment(context.Background(), request)
	if err != nil {
		t.Fatalf("typed route assignment request failed: %v", err)
	}
	if receipt.Operation != "route_assignment.apply" || !receipt.Applied || !receipt.Verified || receipt.MappingHash != request.MappingHash {
		t.Fatalf("semantic receipt lost route binding: %+v", receipt)
	}
	if err := <-done; err != nil {
		t.Fatalf("helper fixture: %v", err)
	}
}
