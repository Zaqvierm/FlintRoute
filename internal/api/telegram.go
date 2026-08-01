package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"router-policy/internal/telegramnotify"
)

type telegramConfigureRequest struct {
	BotToken   string   `json:"bot_token"`
	ChatID     string   `json:"chat_id"`
	Enabled    bool     `json:"enabled"`
	EventTypes []string `json:"event_types"`
}

func (s *Server) handleTelegramConfigure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "PUT required")
		return
	}
	var request telegramConfigureRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	ctx, cancel := contextWithTimeout(r, 15*time.Second)
	defer cancel()
	status, err := s.telegramNotifier.Configure(ctx, request.BotToken, request.ChatID, request.Enabled, request.EventTypes)
	if err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "telegram_verification_failed", err.Error())
		return
	}
	s.publishEvent(Event{Type: "notifications.telegram_configured", Severity: "info", ReasonCode: "telegram_settings_verified", Details: map[string]any{"enabled": status.Enabled, "event_type_count": len(status.EventTypes)}})
	writeData(w, r, status)
}

func (s *Server) handleTelegramTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	ctx, cancel := contextWithTimeout(r, 20*time.Second)
	defer cancel()
	if err := s.telegramNotifier.SendTest(ctx); err != nil {
		writeError(w, r, http.StatusBadGateway, "telegram_test_failed", err.Error())
		return
	}
	writeData(w, r, map[string]any{"delivered": true, "status": s.telegramNotifier.Status()})
}

func contextWithTimeout(r *http.Request, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), timeout)
}

func notificationForEvent(event Event) (telegramnotify.Notification, bool) {
	typeName := ""
	switch {
	case event.Type == "change.awaiting_confirmation":
		typeName = "apply_succeeded"
	case event.Type == "change.rolled_back" || event.Type == "change.expired" || event.Type == "change.rollback_failed" || event.Type == "change.failed":
		typeName = "rollback"
	case strings.HasPrefix(event.Type, "recovery.") || strings.Contains(event.ReasonCode, "recovery") || strings.Contains(event.ReasonCode, "recovered"):
		typeName = "recovery"
	case event.Type == "route.health" && (event.Severity == "warning" || event.Severity == "error"):
		typeName = "route_loss"
	case event.Type == "discovery.auto_apply_paused":
		typeName = "auto_apply_blocked"
	case strings.HasPrefix(event.Type, "storage.") && (event.Severity == "warning" || event.Severity == "error"):
		typeName = "storage_critical"
	default:
		return telegramnotify.Notification{}, false
	}
	return telegramnotify.Notification{Type: typeName, Text: "FlintRoute: " + typeName + " (" + safeNotificationReason(event.ReasonCode) + ")"}, true
}

func safeNotificationReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 96 {
		return "state_changed"
	}
	for _, character := range reason {
		if !(character == '_' || character == '-' || character == '.' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9') {
			return "state_changed"
		}
	}
	return reason
}
