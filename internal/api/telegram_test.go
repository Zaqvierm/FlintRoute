package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-policy/internal/auth"
	"router-policy/internal/platform"
	"router-policy/internal/telegramnotify"
)

func TestTelegramConfigureAndTestAPIKeepsCredentialsSecret(t *testing.T) {
	token := "12345:" + strings.Repeat("x", 24)
	telegramAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/bot"+token+"/") {
			t.Errorf("unexpected Telegram API path %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer telegramAPI.Close()
	cfg := testAPIConfig(t)
	store, err := auth.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	setupToken, _, err := store.CreateSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetupAdmin("admin", "CorrectHorse123!", setupToken); err != nil {
		t.Fatal(err)
	}
	notifier, err := telegramnotify.New(telegramnotify.Options{SecretFile: filepath.Join(cfg.Storage.StateDir, "telegram.json"), APIBaseURL: telegramAPI.URL, Client: telegramAPI.Client(), MinInterval: time.Millisecond, RetryBase: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServerWithOptions(cfg, Options{Auth: store, Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: newFakeAdapter(), TelegramNotifier: notifier, Development: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()
	client, csrf := login(t, httpServer.URL)

	payload, _ := json.Marshal(map[string]any{"bot_token": token, "chat_id": "-100123", "enabled": true, "event_types": []string{"rollback"}})
	request, _ := http.NewRequest(http.MethodPut, httpServer.URL+"/api/v1/telegram/configure", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || bytes.Contains(raw, []byte(token)) || bytes.Contains(raw, []byte("-100123")) {
		t.Fatalf("configure response leaked credentials or failed: status=%d body=%s", response.StatusCode, raw)
	}

	request, _ = http.NewRequest(http.MethodPost, httpServer.URL+"/api/v1/telegram/test", strings.NewReader("{}"))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || bytes.Contains(raw, []byte(token)) || !bytes.Contains(raw, []byte(`"delivered":true`)) {
		t.Fatalf("test delivery response is invalid: status=%d body=%s", response.StatusCode, raw)
	}
}

func TestNotificationEventMapping(t *testing.T) {
	tests := []struct {
		event Event
		want  string
	}{
		{Event{Type: "change.awaiting_confirmation", ReasonCode: "adapter_verified"}, "apply_succeeded"},
		{Event{Type: "change.rolled_back", ReasonCode: "rollback_complete"}, "rollback"},
		{Event{Type: "route.health", Severity: "error", ReasonCode: "path_lost"}, "route_loss"},
		{Event{Type: "recovery.completed", ReasonCode: "recovered"}, "recovery"},
		{Event{Type: "discovery.auto_apply_paused", ReasonCode: "rollback_limit_reached"}, "auto_apply_blocked"},
		{Event{Type: "storage.backup_failed", Severity: "error", ReasonCode: "backup_failed"}, "storage_critical"},
	}
	for _, test := range tests {
		notification, ok := notificationForEvent(test.event)
		if !ok || notification.Type != test.want {
			t.Fatalf("event %s mapped to %+v, ok=%t", test.event.Type, notification, ok)
		}
	}
}

func TestNotificationTextRejectsUnsafeReason(t *testing.T) {
	notification, ok := notificationForEvent(Event{Type: "change.rolled_back", ReasonCode: "token=12345:" + strings.Repeat("x", 24)})
	if !ok || notification.Text != "FlintRoute: rollback (state_changed)" {
		t.Fatalf("unsafe reason leaked into notification: %+v", notification)
	}
}
