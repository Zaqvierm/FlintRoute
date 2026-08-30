//go:build linux

package zapret

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maxCalibrationOutputBytes = 1 << 20

// boundedCalibrationOutput keeps a noisy helper from turning a bounded
// calibration into an unbounded memory allocation.  We deliberately report
// the full write length to the child: truncating diagnostics must not make a
// successful helper look like a different failure mode.  Run checks
// overflow after Wait and rejects the result instead.
type boundedCalibrationOutput struct {
	bytes.Buffer
	overflow bool
}

func (b *boundedCalibrationOutput) Write(p []byte) (int, error) {
	remaining := maxCalibrationOutputBytes - b.Len()
	if remaining <= 0 {
		b.overflow = true
		return len(p), nil
	}
	if len(p) > remaining {
		_, _ = b.Buffer.Write(p[:remaining])
		b.overflow = true
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

func (r ExecCalibrationRunner) Progress() (int, int) {
	raw := r.latestCalibrationLog()
	return countCompletedCalibrationChecks(raw), 0
}

func (r ExecCalibrationRunner) Live() ([]string, []string) {
	return calibrationLiveSnapshot(r.latestCalibrationLog())
}

func (r ExecCalibrationRunner) latestCalibrationLog() []byte {
	matches, _ := filepath.Glob(filepath.Join(r.RuntimeDir, "zapret-calibration.*", "blockcheck.log"))
	var selected string
	var selectedTime time.Time
	for _, path := range matches {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 4<<20 {
			continue
		}
		if selected == "" || info.ModTime().After(selectedTime) {
			selected, selectedTime = path, info.ModTime()
		}
	}
	if selected == "" {
		return nil
	}
	raw, err := os.ReadFile(selected)
	if err != nil {
		return nil
	}
	return raw
}

func (r ExecCalibrationRunner) Run(ctx context.Context, request CalibrationRequest) ([]byte, error) {
	if request.Mode == CalibrationModeQuick && request.AllowManagedRestart {
		return nil, errors.New("quick Zapret calibration cannot restart the managed service")
	}
	if request.Mode == CalibrationModeQuick && r.QuickScript == "" {
		return nil, errCalibrationQuickEvidenceUnavailable
	}
	if err := r.validatePathsFor(request.Mode); err != nil {
		return nil, err
	}
	script := r.Script
	blockcheck := r.Blockcheck
	if request.Mode == CalibrationModeQuick {
		// The upstream blockcheck is deliberately not used for the default
		// action. It has no contract for curated strategy count or NFQUEUE
		// path evidence, so falling back to it here would make the UI lie.
		script = r.QuickScript
		blockcheck = ""
	}
	args := []string{"--apply", "--mode", string(request.Mode), "--domain", request.Domain, "--bundle-id", request.BundleID, "--network-fingerprint", request.NetworkFingerprint}
	if blockcheck != "" {
		args = append(args, "--blockcheck", blockcheck)
	}
	if request.AllowManagedRestart {
		args = append(args, "--allow-managed-restart")
	}
	command := exec.Command(script, args...)
	command.Env = append(os.Environ(),
		"ROUTER_POLICY_CONFIG="+r.Config,
		"ROUTER_POLICY_BIN="+r.RouterPolicyBin,
		"NFQWS_BIN="+r.NFQWSBin,
		"ZAPRET_INIT="+r.ZapretInit,
		"ROUTER_POLICY_RUNTIME_DIR="+r.RuntimeDir,
		"ZAPRET_CATALOG_OUT="+r.CatalogOut,
	)
	if request.Mode == CalibrationModeQuick {
		if r.ManagedQueue < 1 || r.ManagedQueue > 65535 {
			return nil, errors.New("quick Zapret calibration requires the managed production NFQUEUE")
		}
		command.Env = append(command.Env, "ZAPRET_MANAGED_QUEUE="+strconv.Itoa(r.ManagedQueue))
	}
	if len(request.ResolvedIPv4) > 0 {
		command.Env = append(command.Env, "ZAPRET_CALIBRATION_IPV4="+strings.Join(request.ResolvedIPv4, ","))
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout, stderr boundedCalibrationOutput
	// stdout is a machine-readable protocol.  stderr is diagnostics only and
	// must never be concatenated with the JSON document: nft/curl/OpenWrt can
	// legitimately write warnings while the helper still completes successfully.
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return nil, errors.New("start Zapret calibration failed")
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if stdout.overflow || stderr.overflow {
			return nil, errors.New("Zapret calibration output exceeded limit")
		}
		if err != nil {
			diagnostic := make([]byte, 0, stdout.Len()+stderr.Len())
			diagnostic = append(diagnostic, stdout.Bytes()...)
			diagnostic = append(diagnostic, stderr.Bytes()...)
			return nil, calibrationCommandError(diagnostic)
		}
		return append([]byte(nil), stdout.Bytes()...), nil
	case <-ctx.Done():
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			<-done
		}
		return nil, ctx.Err()
	}
}
