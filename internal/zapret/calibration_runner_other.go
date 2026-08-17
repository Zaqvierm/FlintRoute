//go:build !linux

package zapret

import (
	"context"
	"errors"
)

func (r ExecCalibrationRunner) Progress() (int, int) { return 0, 0 }

func (r ExecCalibrationRunner) Run(context.Context, CalibrationRequest) ([]byte, error) {
	if err := r.validatePaths(); err != nil {
		return nil, err
	}
	return nil, errors.New("Zapret calibration is supported only on the OpenWrt runtime")
}
