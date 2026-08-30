//go:build linux

package zapret

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestExecCalibrationRunnerKeepsMachineOutputSeparateFromDiagnostics(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "runner.sh")
	const machineJSON = `{"catalog":{"version":1},"evidence_level":"path_verified","path_verified":false,"attempts":[]}`
	scriptBody := "#!/bin/sh\n" +
		"printf '%s\\n' '" + machineJSON + "'\n" +
		"printf '%s\\n' 'warning: nft emitted a diagnostic' >&2\n"
	if err := os.WriteFile(script, []byte(scriptBody), 0o755); err != nil {
		t.Fatal(err)
	}

	runner := ExecCalibrationRunner{
		QuickScript:     script,
		Config:          "/tmp/router-policy-config.json",
		RouterPolicyBin: "/tmp/router-policy",
		NFQWSBin:        "/tmp/nfqws",
		ZapretInit:      "/tmp/zapret-init",
		RuntimeDir:      "/tmp/router-policy-runtime",
		CatalogOut:      "/tmp/zapret-catalog.json",
		ManagedQueue:    205,
	}
	out, err := runner.Run(context.Background(), CalibrationRequest{Mode: CalibrationModeQuick})
	if err != nil {
		t.Fatalf("runner rejected valid machine output: %v", err)
	}
	want := machineJSON + "\n"
	if string(out) != want {
		t.Fatalf("machine output was polluted by diagnostics: got %q, want %q", out, want)
	}
}

func TestBoundedCalibrationOutputRejectsOverflowWithoutGrowing(t *testing.T) {
	output := new(boundedCalibrationOutput)
	payload := make([]byte, maxCalibrationOutputBytes+1024)
	if n, err := output.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("bounded writer write=(%d,%v), want (%d,nil)", n, err, len(payload))
	}
	if !output.overflow {
		t.Fatal("bounded writer did not record overflow")
	}
	if output.Len() != maxCalibrationOutputBytes {
		t.Fatalf("bounded writer retained %d bytes, want %d", output.Len(), maxCalibrationOutputBytes)
	}
}
