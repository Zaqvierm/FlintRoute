package vpnsub

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

type HWIDMode string

const (
	HWIDModeGenerated HWIDMode = "generated"
	HWIDModePreset    HWIDMode = "preset"
	HWIDModeDisabled  HWIDMode = "disabled"
)

type HWIDSource string

const (
	// The first group is retained for settings written by older FlintRoute
	// versions. The explicit hardware-oriented sources are the public v2
	// choices shown by the UI.
	HWIDSourceComposite    HWIDSource = "composite"
	HWIDSourceDevice       HWIDSource = "device"
	HWIDSourceOS           HWIDSource = "os"
	HWIDSourceSoftware     HWIDSource = "software"
	HWIDSourceMachine      HWIDSource = "machine"
	HWIDSourceNetwork      HWIDSource = "network"
	HWIDSourceMAC          HWIDSource = "mac"
	HWIDSourceMachineID    HWIDSource = "machine_id"
	HWIDSourceRouterSerial HWIDSource = "router_serial"
	HWIDSourceHostname     HWIDSource = "hostname"
	HWIDSourceDeviceModel  HWIDSource = "device_model"
	HWIDSourceSSID         HWIDSource = "ssid"
	HWIDSourceCustomSeed   HWIDSource = "custom_seed"
)

type HWIDSettings struct {
	Mode       HWIDMode   `json:"mode"`
	Source     HWIDSource `json:"source"`
	Preset     string     `json:"preset,omitempty"`
	CustomSeed string     `json:"custom_seed,omitempty"`
}

type FingerprintComponents struct {
	DeviceName        string `json:"device_name,omitempty"`
	OSName            string `json:"os_name,omitempty"`
	OSVersion         string `json:"os_version,omitempty"`
	SoftwareName      string `json:"software_name,omitempty"`
	SoftwareVersion   string `json:"software_version,omitempty"`
	MachineIdentifier string `json:"machine_identifier,omitempty"`
	NetworkIdentifier string `json:"network_identifier,omitempty"`
	MACAddress        string `json:"mac_address,omitempty"`
	RouterSerial      string `json:"router_serial,omitempty"`
	Hostname          string `json:"hostname,omitempty"`
	DeviceModel       string `json:"device_model,omitempty"`
	SSID              string `json:"ssid,omitempty"`
	CustomSeed        string `json:"custom_seed,omitempty"`
}

// HWIDPreview is safe to return to an administrator: it contains the
// selected source value and the deterministic UUID that would be derived from
// it, but never contains a subscription URL or provider credential.
type HWIDPreview struct {
	Source    HWIDSource `json:"source"`
	Label     string     `json:"label"`
	Value     string     `json:"value,omitempty"`
	HWID      string     `json:"hwid,omitempty"`
	Available bool       `json:"available"`
	Selected  bool       `json:"selected"`
	Reason    string     `json:"reason,omitempty"`
}

type FingerprintProvider interface {
	Components(context.Context) (FingerprintComponents, error)
}

type SystemFingerprintProvider struct {
	DeviceName        string
	SoftwareName      string
	SoftwareVersion   string
	MachineIDPath     string
	NetworkIdentifier string
	MACAddress        string
	RouterSerial      string
	Hostname          string
	DeviceModel       string
	SSID              string
	CustomSeed        string
	MACPath           string
	RouterSerialPath  string
	DeviceModelPath   string
	SSIDPath          string
}

func (p SystemFingerprintProvider) Components(_ context.Context) (FingerprintComponents, error) {
	deviceName := strings.TrimSpace(p.DeviceName)
	if deviceName == "" {
		deviceName, _ = os.Hostname()
	}
	hostname := strings.TrimSpace(p.Hostname)
	if hostname == "" {
		hostname = deviceName
	}
	machinePath := p.MachineIDPath
	if machinePath == "" {
		machinePath = "/etc/machine-id"
	}
	machineID := ""
	if raw, err := os.ReadFile(machinePath); err == nil {
		machineID = strings.TrimSpace(string(raw))
	}
	softwareName := strings.TrimSpace(p.SoftwareName)
	if softwareName == "" {
		softwareName = "FlintRoute"
	}
	softwareVersion := strings.TrimSpace(p.SoftwareVersion)
	if softwareVersion == "" {
		softwareVersion = "v1"
	}
	macAddress := strings.TrimSpace(p.MACAddress)
	if macAddress == "" {
		macAddress = readFirstNonEmpty(p.MACPath, "/sys/class/net/br-lan/address", "/sys/class/net/eth0/address", "/sys/class/net/lan/address")
	}
	routerSerial := strings.TrimSpace(p.RouterSerial)
	if routerSerial == "" {
		routerSerial = readFirstNonEmpty(p.RouterSerialPath, "/proc/device-tree/serial-number", "/proc/device-tree/board_serial", "/sys/devices/soc0/serial_number")
	}
	deviceModel := strings.TrimSpace(p.DeviceModel)
	if deviceModel == "" {
		deviceModel = readFirstNonEmpty(p.DeviceModelPath, "/tmp/sysinfo/model", "/proc/device-tree/model")
	}
	ssid := strings.TrimSpace(p.SSID)
	if ssid == "" && strings.TrimSpace(p.SSIDPath) != "" {
		ssid = readFirstSSID(p.SSIDPath)
	}
	return FingerprintComponents{
		DeviceName: deviceName, OSName: runtime.GOOS, OSVersion: runtime.Version(),
		SoftwareName: softwareName, SoftwareVersion: softwareVersion,
		MachineIdentifier: machineID, NetworkIdentifier: strings.TrimSpace(p.NetworkIdentifier),
		MACAddress: macAddress, RouterSerial: routerSerial, Hostname: hostname,
		DeviceModel: deviceModel, SSID: ssid, CustomSeed: strings.TrimSpace(p.CustomSeed),
	}, nil
}

func DefaultHWIDSettings() HWIDSettings {
	return HWIDSettings{Mode: HWIDModeGenerated, Source: HWIDSourceComposite}
}

func (s HWIDSettings) Validate() error {
	mode := s.Mode
	if mode == "" {
		mode = HWIDModeGenerated
	}
	source := s.Source
	if source == "" {
		source = HWIDSourceComposite
	}
	switch mode {
	case HWIDModeGenerated:
		if !validHWIDSource(source) {
			return errors.New("HWID source is unsupported")
		}
		if strings.TrimSpace(s.Preset) != "" {
			return errors.New("preset must be empty for generated HWID")
		}
		if source == HWIDSourceCustomSeed && strings.TrimSpace(s.CustomSeed) == "" {
			return errors.New("custom seed is required for custom-seed HWID")
		}
	case HWIDModePreset:
		if _, err := parseUUID(strings.TrimSpace(s.Preset)); err != nil {
			return errors.New("preset HWID must be a UUID")
		}
		if strings.TrimSpace(s.CustomSeed) != "" {
			return errors.New("custom seed must be empty for preset HWID")
		}
	case HWIDModeDisabled:
		if strings.TrimSpace(s.Preset) != "" || strings.TrimSpace(s.CustomSeed) != "" {
			return errors.New("preset and custom seed must be empty when HWID is disabled")
		}
	default:
		return errors.New("HWID mode is unsupported")
	}
	return nil
}

func NormalizeHWIDSettings(s HWIDSettings) HWIDSettings {
	if s.Mode == "" {
		s.Mode = HWIDModeGenerated
	}
	if s.Source == "" {
		s.Source = HWIDSourceComposite
	}
	s.Preset = strings.ToLower(strings.TrimSpace(s.Preset))
	s.CustomSeed = strings.TrimSpace(s.CustomSeed)
	return s
}

func ResolveHWID(ctx context.Context, settings HWIDSettings, provider FingerprintProvider) (string, error) {
	settings = NormalizeHWIDSettings(settings)
	if err := settings.Validate(); err != nil {
		return "", err
	}
	if settings.Mode == HWIDModeDisabled {
		return "", nil
	}
	if settings.Mode == HWIDModePreset {
		// A preset is an administrator-supplied identifier. Preserve its UUID
		// bytes exactly (apart from the stable lower-case normalization) instead
		// of rewriting version/variant bits as we do for generated IDs.
		return settings.Preset, nil
	}
	if provider == nil {
		return "", errors.New("HWID fingerprint provider is not configured")
	}
	components, err := provider.Components(ctx)
	if err != nil {
		return "", errors.New("HWID fingerprint could not be collected")
	}
	components.CustomSeed = settings.CustomSeed
	value, err := fingerprintValue(settings.Source, components)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", errors.New("selected HWID fingerprint is empty")
	}
	// This is derivation, not encryption. The namespace prevents the same
	// source value from becoming an identifier in another product.
	mac := hmac.New(sha256.New, []byte("flintroute-hwid-v1"))
	_, _ = mac.Write([]byte(value))
	return formatUUIDBytes(mac.Sum(nil)[:16]), nil
}

func DeriveHWID(settings HWIDSettings, components FingerprintComponents) (string, error) {
	return ResolveHWID(context.Background(), settings, staticFingerprintProvider{components: components})
}

func fingerprintValue(source HWIDSource, c FingerprintComponents) (string, error) {
	normalize := func(value string) string {
		return strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(value)), " "))
	}
	fields := map[string]string{
		"device":        normalize(c.DeviceName),
		"os":            normalize(c.OSName) + "\x1f" + normalize(c.OSVersion),
		"software":      normalize(c.SoftwareName) + "\x1f" + normalize(c.SoftwareVersion),
		"machine":       normalize(c.MachineIdentifier),
		"network":       normalize(c.NetworkIdentifier),
		"mac":           normalize(c.MACAddress),
		"machine_id":    normalize(c.MachineIdentifier),
		"router_serial": normalize(c.RouterSerial),
		"hostname":      normalize(firstNonEmptyString(c.Hostname, c.DeviceName)),
		"device_model":  normalize(c.DeviceModel),
		"ssid":          normalize(c.SSID),
		"custom_seed":   normalize(c.CustomSeed),
	}
	if source == HWIDSourceComposite {
		allEmpty := true
		for _, value := range fields {
			if strings.TrimSpace(strings.ReplaceAll(value, "\x1f", "")) != "" {
				allEmpty = false
				break
			}
		}
		if allEmpty {
			return "", errors.New("selected HWID fingerprint is empty")
		}
		ordered := []string{
			"flintroute-hwid-v1",
			"mac=" + fields["mac"],
			"machine_id=" + fields["machine_id"],
			"router_serial=" + fields["router_serial"],
			"hostname=" + fields["hostname"],
			"device_model=" + fields["device_model"],
			"ssid=" + fields["ssid"],
			"device=" + fields["device"],
			"os=" + fields["os"],
			"software=" + fields["software"],
			"machine=" + fields["machine"],
			"network=" + fields["network"],
		}
		return strings.Join(ordered, "\n"), nil
	}
	value, ok := fields[string(source)]
	if !ok {
		return "", errors.New("HWID source is unsupported")
	}
	if strings.Trim(strings.ReplaceAll(value, "\x1f", ""), " \t\r\n") == "" {
		return "", errors.New("selected HWID fingerprint is empty")
	}
	return "flintroute-hwid-v1\n" + string(source) + "=" + value, nil
}

// PreviewHWIDs evaluates every user-selectable source independently. A
// missing optional hardware value is a row-level unavailable result, not a
// failure of the whole settings endpoint.
func PreviewHWIDs(ctx context.Context, settings HWIDSettings, provider FingerprintProvider) ([]HWIDPreview, error) {
	settings = NormalizeHWIDSettings(settings)
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	components := FingerprintComponents{}
	if provider != nil {
		var err error
		components, err = provider.Components(ctx)
		if err != nil {
			// A preset is self-contained and must remain usable even when
			// optional platform fingerprint sources are unavailable.  Keep the
			// selectable rows visible as unavailable instead of turning the whole
			// settings endpoint into a 500.  Generated modes still fail closed:
			// they cannot claim a value without their fingerprint evidence.
			if settings.Mode != HWIDModePreset {
				return nil, errors.New("HWID fingerprint could not be collected")
			}
			components = FingerprintComponents{}
		}
	}
	components.CustomSeed = settings.CustomSeed
	rows := []HWIDPreview{{Source: "preset", Label: "Preset / вручную заданный HWID", Value: settings.Preset, HWID: settings.Preset, Available: settings.Preset != "", Selected: settings.Mode == HWIDModePreset}}
	choices := []struct {
		source HWIDSource
		label  string
		value  string
	}{
		{HWIDSourceMAC, "MAC (base/LAN)", components.MACAddress},
		{HWIDSourceMachineID, "Machine ID", components.MachineIdentifier},
		{HWIDSourceRouterSerial, "Router serial / board serial", components.RouterSerial},
		{HWIDSourceHostname, "Hostname", firstNonEmptyString(components.Hostname, components.DeviceName)},
		{HWIDSourceDeviceModel, "Device model", components.DeviceModel},
		{HWIDSourceSSID, "SSID", components.SSID},
		{HWIDSourceCustomSeed, "Custom seed", settings.CustomSeed},
		{HWIDSourceComposite, "Composite", compositePreviewValue(components)},
	}
	for _, choice := range choices {
		row := HWIDPreview{Source: choice.source, Label: choice.label, Value: choice.value, Selected: settings.Mode == HWIDModeGenerated && settings.Source == choice.source}
		if strings.TrimSpace(choice.value) == "" {
			row.Reason = "Источник не найден на этом роутере"
			rows = append(rows, row)
			continue
		}
		value, err := fingerprintValue(choice.source, components)
		if err != nil {
			row.Reason = err.Error()
			rows = append(rows, row)
			continue
		}
		row.HWID = deriveHWIDValue(value)
		row.Available = row.HWID != ""
		if !row.Available {
			row.Reason = "Не удалось получить детерминированный HWID"
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func deriveHWIDValue(value string) string {
	mac := hmac.New(sha256.New, []byte("flintroute-hwid-v1"))
	_, _ = mac.Write([]byte(value))
	return formatUUIDBytes(mac.Sum(nil)[:16])
}

func compositePreviewValue(c FingerprintComponents) string {
	values := []string{c.MACAddress, c.MachineIdentifier, c.RouterSerial, firstNonEmptyString(c.Hostname, c.DeviceName), c.DeviceModel, c.SSID}
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return "Стабильные доступные поля роутера"
		}
	}
	return ""
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func readFirstNonEmpty(paths ...string) string {
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if raw, err := os.ReadFile(path); err == nil {
			if value := strings.Trim(string(raw), " \t\r\n\x00"); value != "" {
				return value
			}
		}
	}
	return ""
}

func readFirstSSID(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 1<<20 {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "option ssid") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		value := strings.Trim(strings.Join(parts[2:], " "), "'\"")
		if value != "" {
			return value
		}
	}
	return ""
}

type staticFingerprintProvider struct{ components FingerprintComponents }

func (p staticFingerprintProvider) Components(context.Context) (FingerprintComponents, error) {
	return p.components, nil
}

func HWIDSettingsPath(subscriptionSecretPath string) string {
	if subscriptionSecretPath == "" {
		return ""
	}
	return subscriptionSecretPath + ".hwid.json"
}

func LoadHWIDSettings(path string) (HWIDSettings, error) {
	if path == "" {
		return DefaultHWIDSettings(), nil
	}
	if err := validateHWIDSettingsPath(path, false); err != nil {
		return HWIDSettings{}, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return DefaultHWIDSettings(), nil
	}
	if err != nil || len(raw) > 4096 {
		return HWIDSettings{}, errors.New("HWID settings could not be read")
	}
	var settings HWIDSettings
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&settings); err != nil {
		return HWIDSettings{}, errors.New("HWID settings are invalid")
	}
	settings = NormalizeHWIDSettings(settings)
	if err := settings.Validate(); err != nil {
		return HWIDSettings{}, err
	}
	return settings, nil
}

func StoreHWIDSettings(path string, settings HWIDSettings) error {
	if err := validateHWIDSettingsPath(path, true); err != nil {
		return err
	}
	settings = NormalizeHWIDSettings(settings)
	if err := settings.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(raw, '\n'), 0o600)
}

func validateHWIDSettingsPath(path string, createParent bool) error {
	if !filepath.IsAbs(path) {
		return errors.New("HWID settings path must be absolute")
	}
	parent := filepath.Dir(path)
	if createParent {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return err
		}
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !createParent {
			return nil
		}
		return errors.New("HWID settings parent is unavailable")
	}
	if filepath.Clean(resolved) != filepath.Clean(parent) {
		return errors.New("HWID settings parent must not contain symlinks")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("HWID settings target is unavailable")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("HWID settings target must be a regular file")
	}
	if runtimeModeMustBe0600() && info.Mode().Perm() != 0o600 {
		return errors.New("HWID settings must have mode 0600")
	}
	return nil
}

var hwidUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func parseUUID(value string) ([]byte, error) {
	if !hwidUUIDPattern.MatchString(value) {
		return nil, errors.New("invalid UUID")
	}
	compact := strings.ReplaceAll(value, "-", "")
	decoded, err := hex.DecodeString(compact)
	if err != nil || len(decoded) != 16 {
		return nil, errors.New("invalid UUID")
	}
	return decoded, nil
}

func formatUUIDBytes(value []byte) string {
	if len(value) < 16 {
		return ""
	}
	copyValue := append([]byte(nil), value[:16]...)
	copyValue[6] = (copyValue[6] & 0x0f) | 0x40
	copyValue[8] = (copyValue[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s", hex.EncodeToString(copyValue[0:4]), hex.EncodeToString(copyValue[4:6]), hex.EncodeToString(copyValue[6:8]), hex.EncodeToString(copyValue[8:10]), hex.EncodeToString(copyValue[10:16]))
}

func validHWIDSource(source HWIDSource) bool {
	switch source {
	case HWIDSourceComposite, HWIDSourceDevice, HWIDSourceOS, HWIDSourceSoftware, HWIDSourceMachine, HWIDSourceNetwork,
		HWIDSourceMAC, HWIDSourceMachineID, HWIDSourceRouterSerial, HWIDSourceHostname, HWIDSourceDeviceModel, HWIDSourceSSID, HWIDSourceCustomSeed:
		return true
	default:
		return false
	}
}
