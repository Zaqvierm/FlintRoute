package vpnsub

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeArrayOfConfigs(t *testing.T) {
	data := []byte(`[
	  {"outbounds":[{"tag":"a","protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"11111111-1111-4111-8111-111111111111","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"reality"}}]}
	]`)
	s, err := Normalize(data)
	if err != nil {
		t.Fatal(err)
	}
	if s.VLESSCount != 1 || s.OutboundCount != 1 {
		t.Fatalf("bad summary: %+v", s)
	}
}

func TestDuplicateTagsAreRetaggedDeterministically(t *testing.T) {
	data := []byte(`{"outbounds":[
	  {"tag":"dup","protocol":"vless","settings":{"vnext":[{"address":"a","port":443,"users":[{"id":"11111111-1111-4111-8111-111111111111","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"tls"}},
	  {"tag":"dup","protocol":"vless","settings":{"vnext":[{"address":"b","port":443,"users":[{"id":"22222222-2222-4222-8222-222222222222","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"tls"}}
	]}`)
	summary, err := Normalize(data)
	if err != nil {
		t.Fatal(err)
	}
	if summary.SupportedVLESSCount != 2 || summary.UnsupportedVLESSCount != 0 || len(summary.DuplicateTags) != 1 {
		t.Fatalf("duplicate tags were not normalized safely: %+v", summary)
	}
	if summary.Servers[0].Tag == summary.Servers[1].Tag || summary.Servers[0].SourceTag != "dup" || summary.Servers[1].SourceTag != "dup" {
		t.Fatalf("duplicate tags were not replaced with unique internal tags: %+v", summary.Servers)
	}
	second, err := Normalize(data)
	if err != nil {
		t.Fatal(err)
	}
	if second.Servers[0].Tag != summary.Servers[0].Tag || second.Servers[1].Tag != summary.Servers[1].Tag {
		t.Fatalf("internal tags are not deterministic: first=%+v second=%+v", summary.Servers, second.Servers)
	}
}

func TestIdenticalVLESSOutboundsAreDeduplicated(t *testing.T) {
	data := []byte(`[{"outbounds":[
	  {"tag":"first","protocol":"vless","settings":{"vnext":[{"address":"same.example","port":443,"users":[{"id":"11111111-1111-4111-8111-111111111111"}]}]},"streamSettings":{"network":"tcp","security":"tls"}}
	]}, {"outbounds":[
	  {"tag":"second","protocol":"vless","settings":{"vnext":[{"address":"same.example","port":443,"users":[{"id":"11111111-1111-4111-8111-111111111111"}]}]},"streamSettings":{"network":"tcp","security":"tls"}}
	]}]`)
	summary, err := Normalize(data)
	if err != nil {
		t.Fatal(err)
	}
	if summary.VLESSCount != 2 || summary.DeduplicatedVLESSCount != 1 || summary.SupportedVLESSCount != 1 || len(summary.Servers) != 1 {
		t.Fatalf("identical server was not deduplicated: %+v", summary)
	}
}

func TestGenerateXrayConfigFile(t *testing.T) {
	tmp := t.TempDir()
	subscription := filepath.Join(tmp, "subscription.json")
	output := filepath.Join(tmp, "xray.json")
	data := []byte(`[
	  {"outbounds":[{"tag":"vpnsub-frankfurt-1","protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"11111111-1111-4111-8111-111111111111","encryption":"none","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com"}}}]}
	]`)
	if err := os.WriteFile(subscription, data, 0o600); err != nil {
		t.Fatal(err)
	}
	summary, err := GenerateXrayConfigFile(subscription, output, 12000)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Inbounds != 1 || summary.Outbounds != 1 || summary.RoutingRules != 1 {
		t.Fatalf("bad summary: %+v", summary)
	}
	if summary.SecretsPrinted {
		t.Fatal("summary must not report printed secrets")
	}
	rawSummary, _ := json.Marshal(summary)
	if strings.Contains(string(rawSummary), "11111111-1111-4111-8111-111111111111") {
		t.Fatalf("summary leaked subscription secret-ish value: %s", rawSummary)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if summary.SHA256 != "sha256:"+sha256Hex(raw) {
		t.Fatalf("summary hash does not bind exact output bytes: summary=%s file=sha256:%s", summary.SHA256, sha256Hex(raw))
	}
	if !strings.Contains(string(raw), `"port": 12000`) || !strings.Contains(string(raw), `"outboundTag": "vpnsub-frankfurt-1"`) {
		t.Fatalf("generated config missing inbound/routing: %s", raw)
	}
}

func TestUnsupportedOutboundDoesNotBreakSupportedServer(t *testing.T) {
	tmp := t.TempDir()
	subscription := filepath.Join(tmp, "subscription.json")
	output := filepath.Join(tmp, "xray.json")
	data := []byte(`{"outbounds":[
	  {"tag":"good","protocol":"vless","settings":{"vnext":[{"address":"good.example","port":443,"users":[{"id":"11111111-1111-4111-8111-111111111111","encryption":"none"}]}]},"streamSettings":{"network":"grpc","security":"reality","realitySettings":{"serverName":"good.example","publicKey":"PUBLIC","shortId":"SHORT"}}},
	  {"tag":"bad-flow","protocol":"vless","settings":{"vnext":[{"address":"bad.example","port":443,"users":[{"id":"22222222-2222-4222-8222-222222222222","encryption":"none","flow":"unknown-flow"}]}]},"streamSettings":{"network":"tcp","security":"tls"}}
	]}`)
	if err := os.WriteFile(subscription, data, 0o600); err != nil {
		t.Fatal(err)
	}
	summary, err := GenerateXrayConfigFile(subscription, output, 12000)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Outbounds != 1 || len(summary.Servers) != 2 || summary.Servers[0].Status != "SUPPORTED" || summary.Servers[1].Status != "UNSUPPORTED" || summary.Servers[1].Reason != "unsupported_flow" {
		t.Fatalf("mixed subscription classification failed: %+v", summary)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"realitySettings"`) || strings.Contains(string(raw), `"bad-flow"`) {
		t.Fatalf("raw supported Reality fields were not preserved or unsupported server leaked into config: %s", raw)
	}
}

func TestPortExhaustionIsRejectedBeforeWrite(t *testing.T) {
	tmp := t.TempDir()
	subscription := filepath.Join(tmp, "subscription.json")
	output := filepath.Join(tmp, "xray.json")
	data := []byte(`{"outbounds":[
	  {"tag":"one","protocol":"vless","settings":{"vnext":[{"address":"one.example","port":443,"users":[{"id":"11111111-1111-4111-8111-111111111111"}]}]},"streamSettings":{"network":"tcp","security":"tls"}},
	  {"tag":"two","protocol":"vless","settings":{"vnext":[{"address":"two.example","port":443,"users":[{"id":"22222222-2222-4222-8222-222222222222"}]}]},"streamSettings":{"network":"tcp","security":"tls"}}
	]}`)
	if err := os.WriteFile(subscription, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateXrayConfigFile(subscription, output, 65535); err == nil {
		t.Fatal("SOCKS port overflow was accepted")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("output was written despite port exhaustion")
	}
}
