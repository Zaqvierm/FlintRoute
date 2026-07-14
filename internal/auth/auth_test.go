package auth

import (
	"errors"
	"testing"

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

func testStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(&config.Config{Storage: config.Storage{StateDir: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	return store
}
