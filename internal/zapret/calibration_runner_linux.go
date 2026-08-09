//go:build linux

package zapret

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func (r ExecCalibrationRunner) Run(ctx context.Context, request CalibrationRequest) ([]byte, error) {
	if err := r.validatePaths(); err != nil {
		return nil, err
	}
	args := []string{"--apply", "--domain", request.Domain, "--bundle-id", request.BundleID, "--network-fingerprint", request.NetworkFingerprint, "--blockcheck", r.Blockcheck}
	if request.AllowManagedRestart {
		args = append(args, "--allow-managed-restart")
	}
	command := exec.Command(r.Script, args...)
	command.Env = append(os.Environ(),
		"ROUTER_POLICY_CONFIG="+r.Config,
		"ROUTER_POLICY_BIN="+r.RouterPolicyBin,
		"NFQWS_BIN="+r.NFQWSBin,
		"ZAPRET_INIT="+r.ZapretInit,
		"ROUTER_POLICY_RUNTIME_DIR="+r.RuntimeDir,
		"ZAPRET_CATALOG_OUT="+r.CatalogOut,
	)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		return nil, errors.New("start Zapret calibration failed")
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if output.Len() > 1<<20 {
			return nil, errors.New("Zapret calibration output exceeded limit")
		}
		if err != nil {
			return nil, calibrationCommandError(output.Bytes())
		}
		return output.Bytes(), nil
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
