package vpnsub

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"router-policy/internal/remotefetch"
)

func TestPortalEnrollmentRecognition(t *testing.T) {
	for _, path := range []string{"/connect/test-enrollment-token", "/api/device-enrollment/test-enrollment-token/happ"} {
		raw := "https://portal.noclip.ink" + path
		endpoint, present, err := portalEnrollmentEndpoint(raw)
		if err != nil || !present || endpoint != "https://portal.noclip.ink/api/device-enrollment/test-enrollment-token/happ" {
			t.Fatalf("endpoint recognition failed: present=%v err=%v", present, err)
		}
		description, err := DescribeSource(raw)
		if err != nil || description.SourceType != "portal_enrollment" || strings.Contains(description.SourceMasked, "test-enrollment-token") {
			t.Fatalf("unsafe or misleading source description: %+v err=%v", description, err)
		}
	}
	for _, raw := range []string{"https://portal.noclip.ink.evil.example/connect/token", "https://other.example/connect/token", "https://portal.noclip.ink/ordinary-subscription"} {
		_, present, err := portalEnrollmentEndpoint(raw)
		if err != nil || present {
			t.Fatal("unrecognized source was treated as enrollment")
		}
	}
	for _, raw := range []string{"https://user:pass@portal.noclip.ink/connect/token", "https://portal.noclip.ink:443/connect/token", "https://portal.noclip.ink/connect/a%2Fb", "http://portal.noclip.ink/connect/token"} {
		_, _, err := portalEnrollmentEndpoint(raw)
		if err == nil {
			t.Fatal("malformed enrollment accepted")
		}
	}
}

func TestPortalHappResponseBoundedAndDoesNotForwardHWID(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		wantOK     bool
	}{
		{"valid", `{"happImportUrl":"happ://crypt4/test-payload","other":"metadata"}`, 200, true},
		{"unsupported-version-recognized", `{"happImportUrl":"happ://crypt5/test-payload"}`, 200, true},
		{"html", `<html>private-enrollment-token</html>`, 200, false},
		{"not-happ", `{"happImportUrl":"https://127.0.0.1/private"}`, 200, false},
		{"missing", `{}`, 200, false},
		{"array", `[]`, 200, false},
		{"oversize", strings.Repeat("x", (64<<10)+1), 200, false},
		{"upstream", `private-enrollment-token`, 403, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-HWID") != "" || r.Header.Get("Accept") != "application/json" {
					t.Error("provider HWID leaked to enrollment or wrong negotiation")
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			_, err := fetchPortalHappSource(remotefetch.WithLoopbackForTests(context.Background()), server.Client(), server.URL)
			if (err == nil) != tc.wantOK {
				t.Fatalf("success=%v want=%v", err == nil, tc.wantOK)
			}
			if err != nil && strings.Contains(err.Error(), "private-enrollment-token") {
				t.Fatal("provider body leaked")
			}
		})
	}
}

func TestPortalRedirectRejectedWithoutContactingTarget(t *testing.T) {
	targetCalls := 0
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls++; w.WriteHeader(200) }))
	defer target.Close()
	portal := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(302)
	}))
	defer portal.Close()
	_, err := fetchPortalHappSource(remotefetch.WithLoopbackForTests(context.Background()), portal.Client(), portal.URL)
	if err == nil || targetCalls != 0 {
		t.Fatal("enrollment redirect followed")
	}
}

func TestPortalSourceCannotBeFetchedAsPlainSubscription(t *testing.T) {
	_, err := NewDefaultSourceResolver().Resolve(context.Background(), "https://portal.noclip.ink/connect/test-token")
	var sourceErr *SourceError
	if !errors.As(err, &sourceErr) || sourceErr.Code != "portal_resolution_required" {
		t.Fatalf("enrollment misclassified as plain subscription: %v", err)
	}
	raw, _ := json.Marshal(SourceResolution{OriginalSource: "https://portal.noclip.ink/connect/test-token", OriginalSourceMasked: "https://portal.noclip.ink/connect/****"})
	if strings.Contains(string(raw), "test-token") {
		t.Fatal("secret serialized")
	}
}
