package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"router-policy/internal/state"
)

func TestRescueHandlerIsReadOnlyAndFenced(t *testing.T) {
	err := &state.RescueError{Path: "/tmp/router-policy.bbolt", Cause: errors.New("checksum mismatch")}
	if !IsRescueRequired(err) {
		t.Fatal("rescue error was not recognized")
	}
	handler := NewRescueHandler(err, err.Path)
	for _, path := range []string{"/api/v1/health", "/api/v1/recovery", "/api/v1/changes/one/apply"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusServiceUnavailable {
			t.Fatalf("path %s returned %d", path, res.Code)
		}
		body := res.Body.String()
		if !strings.Contains(body, `"mode":"rescue"`) || !strings.Contains(body, `"mutation_enabled":false`) || !strings.Contains(body, `"protected_traffic":"fenced"`) {
			t.Fatalf("path %s was not fenced: %s", path, body)
		}
	}
}
