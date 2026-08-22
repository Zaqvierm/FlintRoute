package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

const onboardingStateKey = "current"

type onboardingStep struct {
	Status    string    `json:"status"`
	UpdatedAt time.Time `json:"updated_at"`
}

type onboardingState struct {
	Version   int                       `json:"version"`
	Steps     map[string]onboardingStep `json:"steps"`
	Completed bool                      `json:"completed"`
	UpdatedAt time.Time                 `json:"updated_at"`
}

type onboardingActionRequest struct {
	Step   string `json:"step"`
	Action string `json:"action"`
}

func defaultOnboardingState() onboardingState {
	return onboardingState{Version: 1, Steps: map[string]onboardingStep{
		"router":       {Status: "pending"},
		"methods":      {Status: "pending"},
		"sources":      {Status: "pending"},
		"services":     {Status: "pending"},
		"verification": {Status: "pending"},
	}}
}

func (s *Server) loadOnboardingState() onboardingState {
	current := defaultOnboardingState()
	if s.store != nil {
		var persisted onboardingState
		if err := s.store.LoadJSON("onboarding", onboardingStateKey, &persisted); err == nil && persisted.Version == 1 {
			current = persisted
			if current.Steps == nil {
				current.Steps = map[string]onboardingStep{}
			}
		}
	}
	for name := range defaultOnboardingState().Steps {
		if _, ok := current.Steps[name]; !ok {
			current.Steps[name] = onboardingStep{Status: "pending"}
		}
	}
	return current
}

func onboardingStepStatus(value onboardingState, name string) string {
	step, ok := value.Steps[name]
	if !ok || step.Status == "" {
		return "pending"
	}
	return step.Status
}

func onboardingOverviewReady(value map[string]any) bool {
	for _, key := range []string{"internet", "dns"} {
		status := strings.ToLower(strings.TrimSpace(fmt.Sprint(value[key])))
		if status == "" || status == "failed" || status == "error" || status == "unavailable" || status == "not_ready" {
			return false
		}
	}
	return true
}

func (s *Server) onboardingResponse(value onboardingState) map[string]any {
	overview := s.provider.Overview(s.currentConfig())
	routerReady := onboardingOverviewReady(overview)
	steps := map[string]any{}
	for name, step := range value.Steps {
		steps[name] = step
	}
	if routerReady {
		steps["router"] = onboardingStep{Status: "verified", UpdatedAt: time.Now().UTC()}
	} else {
		steps["router"] = onboardingStep{Status: "needs_attention"}
	}
	canComplete := routerReady &&
		onboardingStepStatus(value, "methods") != "pending" &&
		onboardingStepStatus(value, "sources") != "pending" &&
		onboardingStepStatus(value, "services") != "pending"
	return map[string]any{
		"version":      value.Version,
		"steps":        steps,
		"completed":    value.Completed,
		"can_complete": canComplete,
		"router_ready": routerReady,
		"source":       "backend",
		"updated_at":   value.UpdatedAt,
		"completion_note": func() string {
			if canComplete {
				return "Все обязательные шаги подтверждены backend-состоянием."
			}
			return "Остались шаги, которые нужно явно подтвердить или пропустить."
		}(),
	}
}

func (s *Server) handleOnboarding(w http.ResponseWriter, r *http.Request) {
	value := s.loadOnboardingState()
	if r.Method == http.MethodGet {
		writeData(w, r, s.onboardingResponse(value))
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET or POST required")
		return
	}
	var request onboardingActionRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	request.Step = strings.ToLower(strings.TrimSpace(request.Step))
	request.Action = strings.ToLower(strings.TrimSpace(request.Action))
	now := time.Now().UTC()
	switch request.Step {
	case "methods", "sources", "services":
		if request.Action != "skip" && request.Action != "accept" && request.Action != "automatic" {
			writeError(w, r, http.StatusBadRequest, "invalid_onboarding_action", "step can be skipped or explicitly accepted")
			return
		}
		status := "accepted"
		if request.Action == "skip" {
			status = "skipped"
		}
		value.Steps[request.Step] = onboardingStep{Status: status, UpdatedAt: now}
	case "complete":
		if request.Action != "complete" {
			writeError(w, r, http.StatusBadRequest, "invalid_onboarding_action", "complete step requires complete action")
			return
		}
		if response := s.onboardingResponse(value); response["can_complete"] != true {
			writeError(w, r, http.StatusConflict, "onboarding_not_ready", "complete the required steps after backend checks pass")
			return
		}
		value.Steps["verification"] = onboardingStep{Status: "verified", UpdatedAt: now}
		value.Completed = true
	default:
		writeError(w, r, http.StatusBadRequest, "invalid_onboarding_step", "unknown onboarding step")
		return
	}
	value.UpdatedAt = now
	if err := s.store.SaveJSON("onboarding", onboardingStateKey, value); err != nil {
		writeError(w, r, http.StatusInternalServerError, "onboarding_state_failed", "onboarding state could not be saved")
		return
	}
	s.publishEvent(Event{Type: "onboarding.updated", Severity: "info", ReasonCode: "onboarding_state_saved", Details: map[string]any{"step": request.Step, "action": request.Action}})
	writeData(w, r, s.onboardingResponse(value))
}
