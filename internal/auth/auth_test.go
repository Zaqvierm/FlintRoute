package auth

import (
	"errors"
	"testing"
	"time"

	"router-policy/internal/config"
)

func TestSetupTokenCreatesAdminAndIsConsumed(t *testing.T) {
	store := testStore(t)
	token, _, err := store.CreateSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetupAdmin("admin", "CorrectHorse123!", token); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetupAdmin("admin2", "CorrectHorse123!", token); !errors.Is(err, ErrSetupUnavailable) {
		t.Fatalf("expected setup unavailable after admin creation, got %v", err)
	}
	if _, _, err := store.Login("admin", "wrong-password", "127.0.0.1:1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected wrong password failure, got %v", err)
	}
	session, _, err := store.Login("admin", "CorrectHorse123!", "127.0.0.2:1")
	if err != nil {
		t.Fatal(err)
	}
	if session.ID == "" || session.CSRFToken == "" {
		t.Fatalf("expected session id and csrf")
	}
}

func TestWeakPasswordRejected(t *testing.T) {
	store := testStore(t)
	token, _, err := store.CreateSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetupAdmin("admin", "admin123", token); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("expected weak password rejection, got %v", err)
	}
}

func TestLoginWithoutAdminRequiresSetup(t *testing.T) {
	store := testStore(t)
	if _, _, err := store.Login("admin", "CorrectHorse123!", "127.0.0.1:1"); !errors.Is(err, ErrSetupRequired) {
		t.Fatalf("expected setup required, got %v", err)
	}
}

func TestDefaultAdminSessionDoesNotExpire(t *testing.T) {
	store := testStore(t)
	token, _, err := store.CreateSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetupAdmin("admin", "CorrectHorse123!", token); err != nil {
		t.Fatal(err)
	}
	session, _, err := store.Login("admin", "CorrectHorse123!", "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if !session.ExpiresAt.IsZero() {
		t.Fatalf("default session unexpectedly has an expiry: %s", session.ExpiresAt)
	}
	if _, ok := store.Session(session.ID); !ok {
		t.Fatal("default non-expiring session was rejected")
	}
	store.mu.Lock()
	store.cleanupLocked(time.Now().UTC().Add(100 * 365 * 24 * time.Hour))
	store.mu.Unlock()
	if _, ok := store.Session(session.ID); !ok {
		t.Fatal("default non-expiring session was removed by cleanup")
	}
}

func TestLoginRateLimitBoundsRotatingSourcesBeforePasswordWork(t *testing.T) {
	store := testStore(t)
	store.mu.Lock()
	defer store.mu.Unlock()
	for i := 0; i < maxGlobalLoginAttempts; i++ {
		if err := store.checkRateLocked("user-"+string(rune('a'+i)), "192.0.2."+string(rune('1'+i))); err != nil {
			t.Fatalf("attempt %d unexpectedly rate limited: %v", i, err)
		}
	}
	if err := store.checkRateLocked("rotating-user", "198.51.100.9"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected global rate limit after %d attempts, got %v", maxGlobalLoginAttempts, err)
	}
	if len(store.globalLoginAttempts) > maxGlobalLoginAttempts {
		t.Fatalf("global attempt window grew beyond bound: %d", len(store.globalLoginAttempts))
	}
	store.globalLoginAttempts[0] = time.Now().UTC().Add(-2 * globalLoginWindow)
	if err := store.checkRateLocked("new-user", "203.0.113.8"); err != nil {
		t.Fatalf("expired global attempt should be evicted: %v", err)
	}
}

func testStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(&config.Config{Storage: config.Storage{StateDir: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	return store
}
