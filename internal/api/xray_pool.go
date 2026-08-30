package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/vpnsub"
)

type vlessSpeedTestRequest struct {
	LogicalID string `json:"logical_id"`
}

type managedVLESSSpeedMeasurer interface {
	MeasureServer(context.Context, *config.Config, string) (vpnsub.SpeedMeasurement, vpnsub.ServerStatus, error)
}

func (s *Server) handleXrayPool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	cfg := s.currentConfig()
	if cfg == nil || cfg.Storage.StateDir == "" {
		writeError(w, r, http.StatusServiceUnavailable, "vless_pool_unavailable", "VLESS storage is not configured")
		return
	}
	snapshot, err := vpnsub.LoadPool(vpnsub.PoolPath(cfg.Storage.StateDir))
	if errors.Is(err, os.ErrNotExist) {
		writeData(w, r, vpnsub.PoolSnapshot{TariffMbps: vpnsub.LoadTariffMbps(cfg.Storage.StateDir), Sources: []vpnsub.SubscriptionSource{}, Servers: []vpnsub.ServerStatus{}})
		return
	}
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "vless_pool_invalid", "The VLESS pool cannot be read; run server verification again")
		return
	}
	sort.SliceStable(snapshot.Servers, func(i, j int) bool {
		left, right := snapshot.Servers[i], snapshot.Servers[j]
		if left.Selected != right.Selected {
			return left.Selected
		}
		if left.PathVerified != right.PathVerified {
			return left.PathVerified
		}
		if left.Score != right.Score {
			return left.Score > right.Score
		}
		return left.Name < right.Name
	})
	writeData(w, r, snapshot)
}

func (s *Server) handleXrayPoolSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "PUT required")
		return
	}
	release, failure := s.acquireMutationLease()
	if failure != nil {
		writeError(w, r, failure.Status, failure.Code, failure.Message)
		return
	}
	defer release()
	var request vpnsub.PoolSettings
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	cfg := s.currentConfig()
	if cfg == nil || cfg.Storage.StateDir == "" {
		writeError(w, r, http.StatusServiceUnavailable, "vless_pool_unavailable", "VLESS storage is not configured")
		return
	}
	if err := vpnsub.SaveTariffMbps(cfg.Storage.StateDir, request.TariffMbps); err != nil {
		writeError(w, r, http.StatusBadRequest, "vless_tariff_invalid", err.Error())
		return
	}
	path := vpnsub.PoolPath(cfg.Storage.StateDir)
	snapshot, err := vpnsub.LoadPool(path)
	if err == nil {
		snapshot.TariffMbps = request.TariffMbps
		snapshot.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
		snapshot.Servers = vpnsub.RefreshPoolScores(snapshot.Servers, request.TariffMbps)
		if err := vpnsub.StorePool(path, snapshot); err != nil {
			writeError(w, r, http.StatusInternalServerError, "vless_pool_write_failed", "The tariff was saved, but the pool score could not be refreshed")
			return
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		writeError(w, r, http.StatusServiceUnavailable, "vless_pool_invalid", "The tariff was saved, but the existing VLESS pool is invalid")
		return
	}
	s.publishEvent(Event{Type: "xray.pool.settings", Severity: "info", ReasonCode: "vless_tariff_updated", Details: map[string]any{"tariff_mbps": request.TariffMbps}})
	writeData(w, r, vpnsub.PoolSettings{TariffMbps: request.TariffMbps})
}

func (s *Server) handleXrayPoolSpeedTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	release, failure := s.acquireMutationLease()
	if failure != nil {
		writeError(w, r, failure.Status, failure.Code, failure.Message)
		return
	}
	defer release()
	if s.vlessThroughputTester == nil {
		writeError(w, r, http.StatusServiceUnavailable, "vless_speedtest_unavailable", "VLESS speed measurement is unavailable on this runtime")
		return
	}
	var request vlessSpeedTestRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	if request.LogicalID == "" || len(request.LogicalID) > 96 {
		writeError(w, r, http.StatusBadRequest, "vless_server_invalid", "Select a logical VLESS server")
		return
	}
	cfg := s.currentConfig()
	if cfg == nil || cfg.Storage.StateDir == "" {
		writeError(w, r, http.StatusServiceUnavailable, "vless_pool_unavailable", "VLESS storage is not configured")
		return
	}
	if !s.tryLockSubscription() {
		writeError(w, r, http.StatusTooManyRequests, "subscription_operation_busy", "Another subscription operation is still running")
		return
	}
	defer s.subscriptionMu.Unlock()
	if measurer, ok := s.subscriptionPreparer.(managedVLESSSpeedMeasurer); ok {
		measurement, server, err := measurer.MeasureServer(r.Context(), cfg, request.LogicalID)
		if err != nil {
			writeError(w, r, http.StatusBadGateway, "vless_speedtest_failed", err.Error())
			return
		}
		s.publishEvent(Event{Type: "xray.pool.speedtest", Severity: "info", ReasonCode: "vless_speed_measured", Details: map[string]any{"logical_id": request.LogicalID, "bytes_used": measurement.BytesUsed, "duration_ms": measurement.DurationMS}})
		writeData(w, r, map[string]any{"server": server, "measurement": measurement})
		return
	}
	path := vpnsub.PoolPath(cfg.Storage.StateDir)
	snapshot, err := vpnsub.LoadPool(path)
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "vless_pool_invalid", "The VLESS pool cannot be read; run server verification again")
		return
	}
	index := -1
	for current := range snapshot.Servers {
		if snapshot.Servers[current].LogicalID == request.LogicalID {
			index = current
			break
		}
	}
	if index < 0 || !snapshot.Servers[index].PathVerified {
		writeError(w, r, http.StatusPreconditionFailed, "vless_path_unverified", "The selected server does not have a verified VLESS path")
		return
	}
	host, _, splitErr := net.SplitHostPort(snapshot.Servers[index].SOCKS5)
	address, parseErr := netip.ParseAddr(host)
	if splitErr != nil || parseErr != nil || !address.IsLoopback() {
		writeError(w, r, http.StatusPreconditionFailed, "vless_socks_unverified", "The selected server is not bound to a loopback SOCKS endpoint")
		return
	}
	measurement, err := s.vlessThroughputTester.Measure(r.Context(), snapshot.Servers[index].SOCKS5, vpnsub.SpeedTestBytes(snapshot.TariffMbps))
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "vless_speedtest_failed", err.Error())
		return
	}
	snapshot.Servers[index].MeasuredMbps = measurement.MeasuredMbps
	snapshot.Servers[index].SpeedBytes = measurement.BytesUsed
	snapshot.Servers[index].SpeedDuration = measurement.DurationMS
	snapshot.Servers[index].SpeedTestedAt = measurement.TestedAt
	snapshot.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	snapshot.Servers = vpnsub.RefreshPoolScores(snapshot.Servers, snapshot.TariffMbps)
	if err := vpnsub.StorePool(path, snapshot); err != nil {
		writeError(w, r, http.StatusInternalServerError, "vless_pool_write_failed", "The measurement succeeded, but its result could not be stored")
		return
	}
	s.publishEvent(Event{Type: "xray.pool.speedtest", Severity: "info", ReasonCode: "vless_speed_measured", Details: map[string]any{"logical_id": request.LogicalID, "bytes_used": measurement.BytesUsed, "duration_ms": measurement.DurationMS}})
	writeData(w, r, map[string]any{"server": snapshot.Servers[index], "measurement": measurement})
}
