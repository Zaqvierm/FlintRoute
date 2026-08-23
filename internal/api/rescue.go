package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"router-policy/internal/state"
)

// IsRescueRequired identifies durable-state failures that must not be
// converted into a normal controller startup error.
func IsRescueRequired(err error) bool {
	var rescue *state.RescueError
	return errors.As(err, &rescue)
}

// NewRescueHandler exposes only loopback diagnostics. The caller must bind it
// to a loopback address; this handler deliberately has no mutation routes.
func NewRescueHandler(cause error, databasePath string) http.Handler {
	reason := "persistent state cannot be trusted"
	if cause != nil {
		reason = cause.Error()
	}
	payload := map[string]any{
		"mode":              "rescue",
		"status":            "recovery_required",
		"reason_code":       "persistent_state_unreadable",
		"reason":            reason,
		"database_path":     databasePath,
		"mutation_enabled":  false,
		"schedulers":        "stopped",
		"protected_traffic": "fenced",
	}
	mux := http.NewServeMux()
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(payload)
	}
	mux.HandleFunc("/api/v1/health", handler)
	mux.HandleFunc("/api/v1/recovery", handler)
	mux.HandleFunc("/", handler)
	return mux
}
