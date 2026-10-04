//go:build !linux

package helper

import "context"

func (e AdapterExecutor) executeZapretQuick(_ context.Context, r Request) Response {
	return ResponseFrom(r, false, "zapret_quick_platform_unavailable", "quick dataplane test requires Linux")
}
