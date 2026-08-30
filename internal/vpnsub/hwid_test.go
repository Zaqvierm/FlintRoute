package vpnsub

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratedHWIDIsDeterministicAndUUIDFormatted(t *testing.T) {
	components := FingerprintComponents{
		DeviceName: " GL-MT6000 ", OSName: "OpenWrt", OSVersion: "24.10.4",
		SoftwareName: "FlintRoute", SoftwareVersion: "1.0.0",
		MachineIdentifier: "machine-123", NetworkIdentifier: "lan-a",
	}
	settings := HWIDSettings{Mode: HWIDModeGenerated, Source: HWIDSourceComposite}
	first, err := DeriveHWID(settings, components)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DeriveHWID(settings, components)
	if err != nil || first != second {
		t.Fatalf("same fingerprint changed HWID: %q/%q err=%v", first, second, err)
	}
	if len(first) != 36 || first[14] != '4' || !strings.Contains(first, "-") {
		t.Fatalf("not RFC4122-compatible UUIDv4 form: %q", first)
	}
	changed := components
	changed.OSVersion = "24.10.5"
	third, err := DeriveHWID(settings, changed)
	if err != nil || first == third {
		t.Fatalf("changed fingerprint did not change HWID: %q/%q err=%v", first, third, err)
	}
}

func TestHWIDSourcesPresetAndDisabled(t *testing.T) {
	components := FingerprintComponents{DeviceName: "router", OSName: "OpenWrt", OSVersion: "24", SoftwareName: "FlintRoute", SoftwareVersion: "1", MachineIdentifier: "machine", NetworkIdentifier: "lan"}
	for _, source := range []HWIDSource{HWIDSourceDevice, HWIDSourceOS, HWIDSourceSoftware, HWIDSourceMachine, HWIDSourceNetwork} {
		value, err := DeriveHWID(HWIDSettings{Mode: HWIDModeGenerated, Source: source}, components)
		if err != nil || value == "" {
			t.Fatalf("source %s failed: %q %v", source, value, err)
		}
	}
	preset := strings.Repeat("3", 8) + "-" + strings.Repeat("3", 4) + "-1233-7333-" + strings.Repeat("3", 12)
	value, err := ResolveHWID(context.Background(), HWIDSettings{Mode: HWIDModePreset, Preset: preset}, nil)
	if err != nil || value != preset {
		t.Fatalf("preset was not preserved: %q err=%v", value, err)
	}
	value, err = ResolveHWID(context.Background(), HWIDSettings{Mode: HWIDModeDisabled}, nil)
	if err != nil || value != "" {
		t.Fatalf("disabled HWID was not empty: %q err=%v", value, err)
	}
}

func TestPresetHWIDSurvivesPersistenceAndDoesNotUseFingerprintProvider(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subscription.secret.hwid.json")
	want := "a330268d-7d9d-4343-8672-f6191f80a25c"
	if err := StoreHWIDSettings(path, HWIDSettings{Mode: HWIDModePreset, Preset: want}); err != nil {
		t.Fatal(err)
	}

	provider := &countingFingerprintProvider{}
	settings, err := LoadHWIDSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := ResolveHWID(context.Background(), settings, provider)
	if err != nil || first != want {
		t.Fatalf("persisted preset changed on first resolve: %q err=%v", first, err)
	}

	provider.components = FingerprintComponents{DeviceName: "a-different-router"}
	settings, err = LoadHWIDSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ResolveHWID(context.Background(), settings, provider)
	if err != nil || second != want {
		t.Fatalf("persisted preset changed after provider change: %q err=%v", second, err)
	}
	if provider.calls != 0 {
		t.Fatalf("preset resolution consulted fingerprint provider %d times", provider.calls)
	}
}

type countingFingerprintProvider struct {
	calls      int
	components FingerprintComponents
}

func (p *countingFingerprintProvider) Components(context.Context) (FingerprintComponents, error) {
	p.calls++
	return p.components, nil
}

func TestHWIDHardwareSourcesAreDeterministic(t *testing.T) {
	components := FingerprintComponents{
		MACAddress: "AA:BB:CC:DD:EE:FF", MachineIdentifier: "machine-1", RouterSerial: "serial-1",
		Hostname: "flint", DeviceModel: "GL-MT6000", SSID: "home", CustomSeed: "zaq-flint2-main",
	}
	for _, source := range []HWIDSource{HWIDSourceMAC, HWIDSourceMachineID, HWIDSourceRouterSerial, HWIDSourceHostname, HWIDSourceDeviceModel, HWIDSourceSSID, HWIDSourceCustomSeed, HWIDSourceComposite} {
		settings := HWIDSettings{Mode: HWIDModeGenerated, Source: source, CustomSeed: components.CustomSeed}
		first, err := DeriveHWID(settings, components)
		if err != nil || first == "" {
			t.Fatalf("source %s failed: %q %v", source, first, err)
		}
		second, err := DeriveHWID(settings, components)
		if err != nil || first != second {
			t.Fatalf("source %s was not deterministic: %q/%q %v", source, first, second, err)
		}
	}
}

func TestHWIDPreviewContainsRequestedRowsAndUnavailableState(t *testing.T) {
	provider := staticFingerprintProvider{components: FingerprintComponents{
		MACAddress: "aa:bb:cc:dd:ee:ff", MachineIdentifier: "machine-1", Hostname: "flint", DeviceModel: "GL-MT6000",
	}}
	rows, err := PreviewHWIDs(context.Background(), HWIDSettings{Mode: HWIDModePreset, Preset: "a330268d-7d9d-4343-8672-f6191f80a25c"}, provider)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 9 || !rows[0].Selected || rows[0].HWID != "a330268d-7d9d-4343-8672-f6191f80a25c" {
		t.Fatalf("unexpected preset preview: %+v", rows)
	}
	seen := map[HWIDSource]HWIDPreview{}
	for _, row := range rows {
		seen[row.Source] = row
	}
	if !seen[HWIDSourceMAC].Available || seen[HWIDSourceMAC].HWID == "" {
		t.Fatalf("MAC preview was not derived: %+v", seen[HWIDSourceMAC])
	}
	if seen[HWIDSourceSSID].Available || seen[HWIDSourceSSID].Reason == "" {
		t.Fatalf("missing SSID was not reported as unavailable: %+v", seen[HWIDSourceSSID])
	}
}

func TestSystemFingerprintProviderReadsStablePaths(t *testing.T) {
	root := t.TempDir()
	machine := filepath.Join(root, "machine-id")
	mac := filepath.Join(root, "mac")
	serial := filepath.Join(root, "serial")
	model := filepath.Join(root, "model")
	ssid := filepath.Join(root, "wireless")
	for path, value := range map[string]string{
		machine: "machine-1\n", mac: "aa:bb:cc:dd:ee:ff\n", serial: "serial-1\x00", model: "GL-MT6000\x00", ssid: "config wifi-iface\n\toption ssid 'home'\n",
	} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	provider := SystemFingerprintProvider{MachineIDPath: machine, MACPath: mac, RouterSerialPath: serial, DeviceModelPath: model, SSIDPath: ssid, Hostname: "flint"}
	components, err := provider.Components(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if components.MACAddress != "aa:bb:cc:dd:ee:ff" || components.RouterSerial != "serial-1" || components.DeviceModel != "GL-MT6000" || components.SSID != "home" {
		t.Fatalf("stable fingerprint paths were not read: %+v", components)
	}
}

func TestHWIDRejectsEmptySelectedFingerprint(t *testing.T) {
	empty := FingerprintComponents{}
	if _, err := DeriveHWID(HWIDSettings{Mode: HWIDModeGenerated, Source: HWIDSourceMachine}, empty); err == nil {
		t.Fatal("empty machine fingerprint was accepted")
	}
	if _, err := DeriveHWID(HWIDSettings{Mode: HWIDModeGenerated, Source: HWIDSourceComposite}, empty); err == nil {
		t.Fatal("empty composite fingerprint was accepted")
	}
}

func TestHWIDSettingsPersistAndRejectUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subscription.secret.hwid.json")
	want := HWIDSettings{Mode: HWIDModePreset, Preset: strings.Repeat("3", 8) + "-" + strings.Repeat("3", 4) + "-1233-7333-" + strings.Repeat("3", 12)}
	if err := StoreHWIDSettings(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadHWIDSettings(path)
	if err != nil || got != NormalizeHWIDSettings(want) {
		t.Fatalf("settings round trip failed: got=%+v err=%v", got, err)
	}
	if err := os.WriteFile(path, []byte(`{"mode":"generated","source":"composite","unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHWIDSettings(path); err == nil {
		t.Fatal("unknown HWID setting field was accepted")
	}
}
