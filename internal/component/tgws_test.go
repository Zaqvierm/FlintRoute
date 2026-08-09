package component

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type tgwsRunner struct {
	running     bool
	restartFail bool
	calls       []string
}

func (r *tgwsRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if strings.Contains(call, "--print-link") {
		return []byte("tg://proxy?server=router.example&port=1443&secret=dd00112233445566778899aabbccddeeff\n"), nil
	}
	if len(args) > 0 && args[0] == "running" {
		if r.running {
			return nil, nil
		}
		return nil, errors.New("stopped")
	}
	if len(args) > 0 && args[0] == "restart" {
		if r.restartFail {
			return nil, errors.New("failed")
		}
		r.running = true
	}
	if len(args) > 0 && args[0] == "stop" {
		r.running = false
	}
	return nil, nil
}

func TestConfigureTGWSCreatesManagedConfigAndOneTimeLink(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "tgws")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := "HOST=0.0.0.0\nPORT=1443\nDC_IP_DEFAULT=203.0.113.20\nDC_IP_DEFAULT_POOL=\"\"\nFAKE_TLS_DOMAIN=\"\"\nCFPROXY_DOMAINS=\"\"\nCFPROXY_DOMAINS_URL=\"\"\nCFPROXY_WORKER_DOMAINS=\"\"\nEXTRA_ARGS=\"\"\n"
	if err := os.WriteFile(filepath.Join(configDir, "config.conf"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "secret.conf"), []byte("SECRET=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "tg-ws-proxy")
	if err := os.WriteFile(binary, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &tgwsRunner{}
	driver := OpenWrtDriver{
		TGWSBinary: binary, TGWSService: "/etc/init.d/tg-ws-proxy", TGWSConfigDir: configDir, Runner: runner,
		TGWSLocalProbe:    func(context.Context, string) error { return nil },
		TGWSUpstreamProbe: func(context.Context, string) error { return nil },
	}
	result, err := driver.ConfigureTGWS(context.Background(), TGWSConfigRequest{Port: 1443, LinkHost: "router.example"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.OneTime || !strings.HasPrefix(result.ConnectLink, "tg://proxy?") || !result.Status.LocalListener || !result.Status.UpstreamReachable {
		t.Fatalf("unexpected configuration result: %+v", result)
	}
	secret, err := os.ReadFile(filepath.Join(configDir, "secret.conf"))
	if err != nil {
		t.Fatal(err)
	}
	value := strings.TrimSpace(strings.TrimPrefix(string(secret), "SECRET="))
	if !validTGWSSecret(value) {
		t.Fatalf("generated secret is invalid: length=%d", len(value))
	}
}

func TestConfigureTGWSRejectsInvalidAddressAndUnsafeConfig(t *testing.T) {
	driver := OpenWrtDriver{}
	if _, err := driver.ConfigureTGWS(context.Background(), TGWSConfigRequest{Port: 1443, LinkHost: "router;reboot"}); err == nil {
		t.Fatal("unsafe router address was accepted")
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("HOST=0.0.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "config.conf")); err != nil {
		t.Skip("symlink creation unavailable")
	}
	if _, _, err := loadTGWSConfig(root); err == nil {
		t.Fatal("symlink configuration was accepted")
	}
}

func TestConfigureTGWSRestoresFilesWhenServiceStartFails(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "tgws")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	oldConfig := []byte("HOST=0.0.0.0\nPORT=1443\nDC_IP_DEFAULT=203.0.113.20\n")
	oldSecret := []byte("SECRET=00112233445566778899aabbccddeeff\n")
	_ = os.WriteFile(filepath.Join(configDir, "config.conf"), oldConfig, 0o600)
	_ = os.WriteFile(filepath.Join(configDir, "secret.conf"), oldSecret, 0o600)
	binary := filepath.Join(root, "tg-ws-proxy")
	_ = os.WriteFile(binary, []byte("fixture"), 0o700)
	driver := OpenWrtDriver{TGWSBinary: binary, TGWSService: "/etc/init.d/tg-ws-proxy", TGWSConfigDir: configDir, Runner: &tgwsRunner{restartFail: true}}
	if _, err := driver.ConfigureTGWS(context.Background(), TGWSConfigRequest{Port: 1555, LinkHost: "router.example"}); err == nil {
		t.Fatal("failed service start was reported as success")
	}
	gotConfig, _ := os.ReadFile(filepath.Join(configDir, "config.conf"))
	gotSecret, _ := os.ReadFile(filepath.Join(configDir, "secret.conf"))
	if string(gotConfig) != string(oldConfig) || string(gotSecret) != string(oldSecret) {
		t.Fatal("previous TG WS Proxy configuration was not restored")
	}
}
