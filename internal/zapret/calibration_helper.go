package zapret

import (
	"context"
	"errors"
	"router-policy/internal/config"
	"router-policy/internal/helper"
	"router-policy/internal/secureid"
)

func (r ExecCalibrationRunner) runThroughHelper(ctx context.Context, input CalibrationRequest) ([]byte, error) {
	if input.Mode != CalibrationModeQuick || input.AllowManagedRestart {
		return nil, errors.New("exhaustive calibration requires a separate privileged maintenance runner; quick test cannot restart production")
	}
	bootstrap, err := config.Load(r.Config)
	if err != nil {
		return nil, errors.New("quick test bootstrap unavailable")
	}
	request, err := helper.CalibrationBinding(bootstrap.Storage.StateDir, bootstrap.Storage.RuntimeDir)
	if err != nil {
		return nil, err
	}
	request.RequestID, err = secureid.Hex(12)
	if err != nil {
		return nil, err
	}
	request.Command = "zapret.quick_check"
	request.ZapretQuick = &helper.ZapretQuickRequest{Domain: input.Domain, BundleID: input.BundleID, NetworkFingerprint: input.NetworkFingerprint, ResolvedIPv4: input.ResolvedIPv4}
	response, err := helper.Call(ctx, r.HelperSocket, request)
	if err != nil {
		if response.Evidence["diagnostic"] != "" {
			return nil, calibrationCommandError([]byte(response.Evidence["diagnostic"]))
		}
		return nil, err
	}
	if response.Operation != "quick_check" || response.SemanticState != "completed" || response.Committed || response.Evidence["payload"] == "" {
		return nil, errors.New("quick test helper returned an invalid semantic response")
	}
	return []byte(response.Evidence["payload"]), nil
}
