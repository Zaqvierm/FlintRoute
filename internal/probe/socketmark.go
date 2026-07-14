package probe

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"router-policy/internal/config"
)

func exerciseDropProbe(ctx context.Context, cfg *config.Config, route config.Route) error {
	if cfg == nil || cfg.Platform.Target == "test" {
		return nil
	}
	if !socketMarkAvailable() {
		return fmt.Errorf("drop_probe_socket_mark_unavailable")
	}
	markText := route.Mark
	if markText == "" {
		markText = cfg.OpenWrt.DropMark
	}
	mark, err := parseSocketMark(markText)
	if err != nil || mark == 0 {
		return fmt.Errorf("drop_probe_mark_invalid")
	}
	var observed uint32
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	setSocketMarkControl(dialer, mark, &observed)
	conn, dialErr := dialer.DialContext(ctx, "udp4", "192.0.2.1:9")
	if conn != nil {
		_, _ = conn.Write([]byte{0})
		_ = conn.Close()
	}
	if observed != mark {
		if dialErr != nil {
			return fmt.Errorf("drop_probe_socket_mark_failed: %w", dialErr)
		}
		return fmt.Errorf("drop_probe_socket_mark_mismatch")
	}
	return nil
}

func installRouteSocketMark(dialer *net.Dialer, cfg *config.Config, route config.Route, observed *uint32) bool {
	if cfg == nil || cfg.Platform.Target == "test" || route.SOCKS5 != "" || !socketMarkAvailable() {
		return false
	}
	value := route.Mark
	if value == "" {
		switch route.Type {
		case "direct", "smart_dns":
			value = cfg.OpenWrt.DirectMark
		case "zapret":
			value = cfg.OpenWrt.ZapretMark
		}
	}
	mark, err := parseSocketMark(value)
	if err != nil || mark == 0 {
		return false
	}
	setSocketMarkControl(dialer, mark, observed)
	return true
}

func parseSocketMark(value string) (uint32, error) {
	value = strings.TrimSpace(value)
	base := 10
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		base = 16
		value = value[2:]
	}
	parsed, err := strconv.ParseUint(value, base, 32)
	return uint32(parsed), err
}

func formatSocketMark(value uint32) string {
	if value == 0 {
		return ""
	}
	return "0x" + strconv.FormatUint(uint64(value), 16)
}
