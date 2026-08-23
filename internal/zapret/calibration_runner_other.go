//go:build !linux

package zapret

import (
	"context"
	"errors"
)

func (r ExecCalibrationRunner) Progress() (int, int) { return 0, 0 }

func (r ExecCalibrationRunner) Live() ([]string, []string) { return nil, nil }

func (r ExecCalibrationRunner) Run(_ context.Context, request CalibrationRequest) ([]byte, error) {
	if request.Mode == CalibrationModeQuick && r.QuickScript == "" {
		return nil, errCalibrationQuickEvidenceUnavailable
	}
	if request.Mode == CalibrationModeQuick && (r.ManagedQueue < 1 || r.ManagedQueue > 65535) {
		return nil, errors.New("quick Zapret calibration requires the managed production NFQUEUE")
	}
	if err := r.validatePathsFor(request.Mode); err != nil {
		return nil, err
	}
	return nil, errors.New("Zapret calibration is supported only on the OpenWrt runtime")
}
