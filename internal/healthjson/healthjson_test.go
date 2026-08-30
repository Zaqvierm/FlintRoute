package healthjson

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeHealthFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "health.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadFieldSupportsEnvelopeAndBareObject(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{name: "envelope", body: `{"data":{"status":"ok","recovery_status":"not_required"}}`},
		{name: "bare", body: `{"status":"ok","recovery_status":"ok"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeHealthFixture(t, tc.body)
			got, err := ReadField(path, "status")
			if err != nil || got != "ok" {
				t.Fatalf("ReadField() = %q, %v", got, err)
			}
		})
	}
}

func TestReadFieldRejectsUnsafeOrMalformedInput(t *testing.T) {
	path := writeHealthFixture(t, `{"data":{"status":"ok"}} trailing`)
	if _, err := ReadField(path, "status"); err == nil {
		t.Fatal("expected trailing JSON to be rejected")
	}
	if _, err := ReadField(path, "arbitrary"); err == nil {
		t.Fatal("expected non-allowlisted field to be rejected")
	}
	path = writeHealthFixture(t, `{"data":{"status":true}}`)
	if _, err := ReadField(path, "status"); err == nil {
		t.Fatal("expected non-string health field to be rejected")
	}
	path = writeHealthFixture(t, `{"data":{"status":"`+strings.Repeat("x", MaxBytes)+`"}}`)
	if _, err := ReadField(path, "status"); err == nil {
		t.Fatal("expected oversized health response to be rejected")
	}
}
