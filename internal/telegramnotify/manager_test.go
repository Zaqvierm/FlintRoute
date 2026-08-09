package telegramnotify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var testToken = "12345:" + strings.Repeat("x", 24)

func TestStatusEncodesMissingEventTypesAsEmptyArray(t *testing.T) {
	manager, err := New(Options{SecretFile: filepath.Join(t.TempDir(), "telegram.json")})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	public, err := json.Marshal(manager.Status())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(public), `"event_types":[]`) {
		t.Fatalf("status must expose an empty array, got %s", public)
	}
}

func TestConfigureVerifiesAndStoresSecretWithoutExposingIt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/bot"+testToken+"/") {
			t.Fatalf("unexpected Telegram path %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":{}}`))
	}))
	defer server.Close()
	secret := filepath.Join(t.TempDir(), "telegram.json")
	manager, err := New(Options{SecretFile: secret, APIBaseURL: server.URL, Client: server.Client(), MinInterval: time.Millisecond, RetryBase: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	status, err := manager.Configure(context.Background(), testToken, "-100123", true, []string{"rollback", "apply_succeeded"})
	if err != nil {
		t.Fatal(err)
	}
	if status.State != StateVerified || !status.Enabled || !status.TokenConfigured || !status.ChatConfigured {
		t.Fatalf("unexpected status: %+v", status)
	}
	info, err := os.Stat(secret)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("secret permissions are too broad: %o", info.Mode().Perm())
	}
	public, _ := json.Marshal(status)
	if strings.Contains(string(public), testToken) || strings.Contains(string(public), "-100123") {
		t.Fatalf("public status leaked Telegram credentials: %s", public)
	}
	if err := manager.SendTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	manager.Close()
	restarted, err := New(Options{SecretFile: secret, APIBaseURL: server.URL, Client: server.Client(), MinInterval: time.Millisecond, RetryBase: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	deadline := time.Now().Add(time.Second)
	for restarted.Status().State != StateVerified && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if status := restarted.Status(); status.State != StateVerified || !status.Enabled {
		t.Fatalf("saved Telegram settings did not survive restart: %+v", status)
	}
}

func TestDeliveryRetriesAreBoundedAndFailureIsSanitized(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/getMe") || strings.HasSuffix(r.URL.Path, "/getChat") {
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		attempts.Add(1)
		http.Error(w, `{"ok":false,"description":"token `+testToken+` rejected"}`, http.StatusTooManyRequests)
	}))
	defer server.Close()
	manager, err := New(Options{SecretFile: filepath.Join(t.TempDir(), "telegram.json"), APIBaseURL: server.URL, Client: server.Client(), MaxRetries: 3, MinInterval: time.Millisecond, RetryBase: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if _, err := manager.Configure(context.Background(), testToken, "123", true, nil); err != nil {
		t.Fatal(err)
	}
	err = manager.SendTest(context.Background())
	if err == nil || strings.Contains(err.Error(), testToken) {
		t.Fatalf("expected sanitized delivery failure, got %v", err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("retry count is not bounded: %d", attempts.Load())
	}
	if status := manager.Status(); status.State != StateFailed || status.ConsecutiveFailures != 3 {
		t.Fatalf("terminal failure state missing: %+v", status)
	}
}

func TestDisablePreservesSettingsAndStopsDelivery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"ok":true}`)) }))
	defer server.Close()
	secret := filepath.Join(t.TempDir(), "telegram.json")
	manager, err := New(Options{SecretFile: secret, APIBaseURL: server.URL, Client: server.Client(), MinInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if _, err := manager.Configure(context.Background(), testToken, "123", true, nil); err != nil {
		t.Fatal(err)
	}
	status, err := manager.Configure(context.Background(), "", "", false, []string{"rollback"})
	if err != nil {
		t.Fatal(err)
	}
	if status.State != StateConfigured || status.Enabled || !status.TokenConfigured || !status.ChatConfigured {
		t.Fatalf("disable discarded configuration: %+v", status)
	}
	if manager.Enqueue(Notification{Type: "rollback", Text: "rollback"}) {
		t.Fatal("disabled notifier accepted a delivery")
	}
}
