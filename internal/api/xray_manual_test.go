package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"

	"router-policy/internal/vpnsub"
)

func TestManualVLESSAPIStoresSecretWithoutEchoingCredential(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client, csrf := login(t, ts.URL)
	const uri = "vless://33333333-3333-4333-8333-333333333333@manual.example:443?encryption=none&security=reality&type=tcp&sni=www.example.com&fp=chrome&pbk=public-key&sid=abcd&flow=xtls-rprx-vision#Home%20VPS"
	body, _ := json.Marshal(map[string]string{"uri": uri})
	request, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/xray/manual-servers", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(response.Body)
		t.Fatalf("manual VLESS create status=%d body=%s", response.StatusCode, raw)
	}
	rawResponse, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawResponse), uri) || strings.Contains(string(rawResponse), "33333333-3333-4333-8333-333333333333") || !strings.Contains(string(rawResponse), "manual.example") {
		t.Fatalf("manual VLESS response leaked a secret or omitted safe metadata: %s", rawResponse)
	}
	path := vpnsub.ManualServersPath(srv.cfg.Storage.StateDir)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("manual VLESS store mode=%o", info.Mode().Perm())
	}
}
