package component

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type TGWSConfigRequest struct {
	Port          int    `json:"port"`
	FakeTLSDomain string `json:"fake_tls_domain,omitempty"`
	LinkHost      string `json:"link_host"`
}

type TGWSStatus struct {
	Installed          bool      `json:"installed"`
	Configured         bool      `json:"configured"`
	Enabled            bool      `json:"enabled"`
	Running            bool      `json:"running"`
	LocalListener      bool      `json:"local_listener"`
	UpstreamReachable  bool      `json:"upstream_reachable"`
	ClientPathVerified bool      `json:"client_path_verified"`
	Port               int       `json:"port,omitempty"`
	FakeTLS            bool      `json:"fake_tls"`
	State              string    `json:"state"`
	Reason             string    `json:"reason,omitempty"`
	CheckedAt          time.Time `json:"checked_at"`
}

type TGWSConfigureResult struct {
	Status      TGWSStatus `json:"status"`
	ConnectLink string     `json:"connect_link"`
	OneTime     bool       `json:"one_time"`
}

type TGWSDriver interface {
	TGWSStatus(context.Context) (TGWSStatus, error)
	ConfigureTGWS(context.Context, TGWSConfigRequest) (TGWSConfigureResult, error)
}

func (m *Manager) TGWSStatus(ctx context.Context) (TGWSStatus, error) {
	if err := m.validate(); err != nil {
		return TGWSStatus{}, err
	}
	driver, ok := m.Driver.(TGWSDriver)
	if !ok {
		return TGWSStatus{}, errors.New("TG WS Proxy configuration is unsupported by this platform")
	}
	return driver.TGWSStatus(ctx)
}

func (m *Manager) ConfigureTGWS(ctx context.Context, request TGWSConfigRequest) (TGWSConfigureResult, error) {
	if err := m.validate(); err != nil {
		return TGWSConfigureResult{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	driver, ok := m.Driver.(TGWSDriver)
	if !ok {
		return TGWSConfigureResult{}, errors.New("TG WS Proxy configuration is unsupported by this platform")
	}
	return driver.ConfigureTGWS(ctx, request)
}

func (d OpenWrtDriver) TGWSStatus(ctx context.Context) (TGWSStatus, error) {
	now := d.now()
	binary := defaultString(d.TGWSBinary, "/usr/bin/tg-ws-proxy")
	service := defaultString(d.TGWSService, "/etc/init.d/tg-ws-proxy")
	configDir := defaultString(d.TGWSConfigDir, "/etc/tg-ws-proxy")
	status := TGWSStatus{State: "not_installed", CheckedAt: now}
	if !regularExecutable(binary) {
		return status, nil
	}
	status.Installed = true
	values, secret, err := loadTGWSConfig(configDir)
	if err != nil {
		status.State = "needs_configuration"
		status.Reason = err.Error()
		return status, nil
	}
	port, err := strconv.Atoi(values["PORT"])
	if err != nil || port < 1024 || port > 65535 || !validTGWSSecret(secret) {
		status.State = "needs_configuration"
		status.Reason = "TG WS Proxy configuration is incomplete"
		return status, nil
	}
	status.Configured = true
	status.Port = port
	status.FakeTLS = values["FAKE_TLS_DOMAIN"] != ""
	status.Running = d.serviceRunning(ctx, service)
	status.Enabled = status.Running
	if !status.Running {
		status.State = "stopped"
		status.Reason = "TG WS Proxy is configured but the service is stopped"
		return status, nil
	}
	status.LocalListener = d.probeTGWSLocal(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(port))) == nil
	status.UpstreamReachable = d.probeTGWSUpstream(ctx, net.JoinHostPort(values["DC_IP_DEFAULT"], "443")) == nil
	switch {
	case !status.LocalListener:
		status.State, status.Reason = "failed", "TG WS Proxy process is running but its listener is unavailable"
	case !status.UpstreamReachable:
		status.State, status.Reason = "degraded", "Telegram DC is unreachable from the router"
	default:
		status.State = "ready_for_client"
		status.Reason = "Router-side checks passed; open the one-time MTProto link in Telegram to verify the client path"
	}
	return status, nil
}

func (d OpenWrtDriver) ConfigureTGWS(ctx context.Context, request TGWSConfigRequest) (TGWSConfigureResult, error) {
	if request.Port == 0 {
		request.Port = 1443
	}
	if request.Port < 1024 || request.Port > 65535 {
		return TGWSConfigureResult{}, errors.New("TG WS Proxy port must be between 1024 and 65535")
	}
	request.LinkHost = strings.TrimSpace(strings.Trim(request.LinkHost, "[]"))
	if !validHost(request.LinkHost) {
		return TGWSConfigureResult{}, errors.New("router address for the Telegram link is invalid")
	}
	request.FakeTLSDomain = strings.TrimSpace(request.FakeTLSDomain)
	if request.FakeTLSDomain != "" && !validDNSName(request.FakeTLSDomain) {
		return TGWSConfigureResult{}, errors.New("Fake TLS domain is invalid")
	}
	binary := defaultString(d.TGWSBinary, "/usr/bin/tg-ws-proxy")
	service := defaultString(d.TGWSService, "/etc/init.d/tg-ws-proxy")
	configDir := defaultString(d.TGWSConfigDir, "/etc/tg-ws-proxy")
	if !regularExecutable(binary) {
		return TGWSConfigureResult{}, errors.New("TG WS Proxy is not installed")
	}
	values, secret, err := loadTGWSConfig(configDir)
	if err != nil {
		return TGWSConfigureResult{}, errors.New("installed TG WS Proxy package has no safe base configuration")
	}
	if !validTGWSSecret(secret) {
		secret, err = randomTGWSSecret()
		if err != nil {
			return TGWSConfigureResult{}, err
		}
	}
	values["HOST"] = "0.0.0.0"
	values["PORT"] = strconv.Itoa(request.Port)
	values["FAKE_TLS_DOMAIN"] = request.FakeTLSDomain
	values["DC_IP_DEFAULT_POOL"] = ""
	values["CFPROXY_DOMAINS"] = ""
	values["CFPROXY_DOMAINS_URL"] = ""
	values["CFPROXY_WORKER_DOMAINS"] = ""
	values["EXTRA_ARGS"] = ""
	linkArgs := []string{"--print-link", "--host", request.LinkHost, "--port", values["PORT"], "--secret", secret}
	if request.FakeTLSDomain != "" {
		linkArgs = append(linkArgs, "--fake-tls-domain", request.FakeTLSDomain)
	}
	linkRaw, err := d.runner().Run(ctx, binary, linkArgs...)
	if err != nil {
		return TGWSConfigureResult{}, errors.New("TG WS Proxy could not generate a client link")
	}
	link := extractTGWSLink(string(linkRaw))
	if link == "" {
		return TGWSConfigureResult{}, errors.New("TG WS Proxy returned an invalid client link")
	}
	configPath := filepath.Join(configDir, "config.conf")
	secretPath := filepath.Join(configDir, "secret.conf")
	oldConfig, _ := os.ReadFile(configPath)
	oldSecret, _ := os.ReadFile(secretPath)
	if err := atomicTGWSFile(configPath, renderTGWSConfig(values)); err != nil {
		return TGWSConfigureResult{}, err
	}
	if err := atomicTGWSFile(secretPath, []byte("SECRET="+secret+"\n")); err != nil {
		_ = atomicTGWSFile(configPath, oldConfig)
		return TGWSConfigureResult{}, err
	}
	rollback := func() {
		_ = atomicTGWSFile(configPath, oldConfig)
		_ = atomicTGWSFile(secretPath, oldSecret)
		_, _ = d.runner().Run(ctx, "uci", "set", "tg-ws-proxy.main.enabled=0")
		_, _ = d.runner().Run(ctx, "uci", "commit", "tg-ws-proxy")
		_, _ = d.runner().Run(ctx, service, "stop")
	}
	for _, args := range [][]string{{"set", "tg-ws-proxy.main.enabled=1"}, {"set", "tg-ws-proxy.main.user=root"}, {"commit", "tg-ws-proxy"}} {
		if _, err := d.runner().Run(ctx, "uci", args...); err != nil {
			rollback()
			return TGWSConfigureResult{}, errors.New("TG WS Proxy service configuration failed")
		}
	}
	if _, err := d.runner().Run(ctx, service, "enable"); err != nil {
		rollback()
		return TGWSConfigureResult{}, errors.New("TG WS Proxy could not be enabled")
	}
	if _, err := d.runner().Run(ctx, service, "restart"); err != nil {
		rollback()
		return TGWSConfigureResult{}, errors.New("TG WS Proxy failed to start")
	}
	var status TGWSStatus
	for attempt := 0; attempt < 10; attempt++ {
		status, _ = d.TGWSStatus(ctx)
		if status.LocalListener {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !status.LocalListener {
		rollback()
		return TGWSConfigureResult{}, errors.New("TG WS Proxy started without a reachable local listener; previous configuration restored")
	}
	return TGWSConfigureResult{Status: status, ConnectLink: link, OneTime: true}, nil
}

func (d OpenWrtDriver) probeTGWSLocal(ctx context.Context, address string) error {
	if d.TGWSLocalProbe != nil {
		return d.TGWSLocalProbe(ctx, address)
	}
	dialer := net.Dialer{Timeout: 2 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err == nil {
		_ = connection.Close()
	}
	return err
}

func (d OpenWrtDriver) probeTGWSUpstream(ctx context.Context, address string) error {
	if d.TGWSUpstreamProbe != nil {
		return d.TGWSUpstreamProbe(ctx, address)
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err == nil {
		_ = connection.Close()
	}
	return err
}

func loadTGWSConfig(dir string) (map[string]string, string, error) {
	allowed := map[string]bool{"HOST": true, "PORT": true, "DC_IP_DEFAULT": true, "DC_IP_DEFAULT_POOL": true, "FAKE_TLS_DOMAIN": true, "CFPROXY_DOMAINS": true, "CFPROXY_DOMAINS_URL": true, "CFPROXY_WORKER_DOMAINS": true, "EXTRA_ARGS": true}
	values := map[string]string{}
	file, err := openRegular(filepath.Join(dir, "config.conf"))
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !allowed[key] {
			continue
		}
		values[key] = strings.Trim(strings.TrimSpace(value), "\"")
	}
	if err := scanner.Err(); err != nil || net.ParseIP(values["DC_IP_DEFAULT"]) == nil {
		return nil, "", errors.New("TG WS Proxy base configuration is invalid")
	}
	secretFile, err := openRegular(filepath.Join(dir, "secret.conf"))
	if err != nil {
		return nil, "", err
	}
	defer secretFile.Close()
	secretScanner := bufio.NewScanner(secretFile)
	secret := ""
	for secretScanner.Scan() {
		if strings.HasPrefix(secretScanner.Text(), "SECRET=") {
			secret = strings.Trim(strings.TrimPrefix(secretScanner.Text(), "SECRET="), "\"")
		}
	}
	return values, secret, secretScanner.Err()
}

func openRegular(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("TG WS Proxy configuration is missing or unsafe")
	}
	return os.Open(path)
}

func renderTGWSConfig(values map[string]string) []byte {
	keys := []string{"HOST", "PORT", "DC_IP_DEFAULT", "DC_IP_DEFAULT_POOL", "FAKE_TLS_DOMAIN", "CFPROXY_DOMAINS", "CFPROXY_DOMAINS_URL", "CFPROXY_WORKER_DOMAINS", "EXTRA_ARGS"}
	var out strings.Builder
	for _, key := range keys {
		value := strings.ReplaceAll(values[key], "\"", "")
		fmt.Fprintf(&out, "%s=\"%s\"\n", key, value)
	}
	return []byte(out.String())
}

func atomicTGWSFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("TG WS Proxy configuration directory is unsafe")
	}
	if target, statErr := os.Lstat(path); statErr == nil && (!target.Mode().IsRegular() || target.Mode()&os.ModeSymlink != 0) {
		return errors.New("TG WS Proxy configuration target is unsafe")
	}
	temporary, err := os.CreateTemp(dir, ".flintroute-tgws-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(data)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}

func regularExecutable(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && (info.Mode()&0o111 != 0 || runtime.GOOS == "windows")
}

func randomTGWSSecret() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("TG WS Proxy secret generation failed")
	}
	return hex.EncodeToString(value), nil
}

func validTGWSSecret(value string) bool {
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

var tgwsLinkPattern = regexp.MustCompile(`tg://proxy\?[^\s]+`)

func extractTGWSLink(value string) string {
	link := tgwsLinkPattern.FindString(value)
	if len(link) > 512 {
		return ""
	}
	return link
}

func validHost(value string) bool {
	return net.ParseIP(value) != nil || validDNSName(value)
}

func validDNSName(value string) bool {
	if len(value) == 0 || len(value) > 253 || strings.ContainsAny(value, " /\\:@\t\r\n") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}
