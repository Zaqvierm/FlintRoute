package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEventBrokerFailsWhenEntropyIsUnavailable(t *testing.T) {
	original := secureRandomHex
	secureRandomHex = func(int) (string, error) { return "", errors.New("entropy unavailable") }
	defer func() { secureRandomHex = original }()

	_, err := NewEventBroker(8)
	if err == nil || !strings.Contains(err.Error(), "generate event stream epoch") {
		t.Fatalf("expected event broker entropy failure, got %v", err)
	}
}

func TestRequestIDFailsClosedWhenEntropyIsUnavailable(t *testing.T) {
	original := secureRandomHex
	secureRandomHex = func(int) (string, error) { return "", errors.New("entropy unavailable") }
	defer func() { secureRandomHex = original }()

	s := &Server{}
	handler := s.withRequestID(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("request reached protected handler without a request ID")
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", recorder.Code)
	}
}
