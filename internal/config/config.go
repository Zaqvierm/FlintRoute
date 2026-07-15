package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

var sha256ReferencePattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var firewallMarkPattern = regexp.MustCompile(`^0x[0-9a-fA-F]{1,8}$`)
var routeTagPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)
var nftTablePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,31}$`)

type Config struct {
	Version       int                `json:"version"`
	Platform      Platform           `json:"platform"`
	Storage       Storage            `json:"storage"`
	Policy        Policy             `json:"policy"`
	Xray          Xray               `json:"xray"`
	Zapret        Zapret             `json:"zapret"`
	GeoIP         GeoIP              `json:"geoip"`
	OpenWrt       OpenWrt            `json:"openwrt"`
	Routes        []Route            `json:"routes"`
	Services      map[string]Service `json:"services"`
	Overrides     []PolicyOverride   `json:"overrides"`
	Notifications NotificationConfig `json:"notifications"`
	TSPUSources   []TSPUSource       `json:"tspu_sources"`
}

type Platform struct {
	Target                      string `json:"target"`
	RequireConfirmedDiagnostics bool   `json:"require_confirmed_diagnostics"`
	UnsupportedApplyPolicy      string `json:"unsupported_apply_policy"`
}

type Storage struct {
	StateDir                 string `json:"state_dir"`
	RuntimeDir               string `json:"runtime_dir"`
	Database                 string `json:"database"`
	EventRetentionDays       int    `json:"event_retention_days"`
	ChangeSetRetentionDays   int    `json:"changeset_retention_days"`
	TransactionRetentionDays int    `json:"transaction_retention_days"`
	MaxProbeResults          int    `json:"max_probe_results"`
	BackupIntervalHours      int    `json:"backup_interval_hours"`
	CompactIntervalDays      int    `json:"compact_interval_days"`
	MaxStateBackups          int    `json:"max_state_backups"`
	MaxDatabaseBytes         int64  `json:"max_database_bytes"`
	MaxAutoDomains           int    `json:"max_auto_domains"`
	SnapshotIntervalSeconds  int    `json:"snapshot_interval_seconds"`
}

type Policy struct {
	UnknownDomainFirstPath         string `json:"unknown_domain_first_path"`
	UnknownDomainBackgroundCheck   bool   `json:"unknown_domain_background_check"`
	RouteHoldSeconds               int    `json:"route_hold_seconds"`
	FailAfterConsecutiveErrors     int    `json:"fail_after_consecutive_errors"`
	RecoverAfterConsecutiveSuccess int    `json:"recover_after_consecutive_successes"`
	HealthCheckIntervalSeconds     int    `json:"health_check_interval_seconds"`
	DomainDecisionTTLSeconds       int    `json:"domain_decision_ttl_seconds"`
	SubscriptionUpdateIntervalSecs int    `json:"subscription_update_interval_seconds"`
	TSPUListUpdateIntervalSeconds  int    `json:"tspu_list_update_interval_seconds"`
	TSPUStalePolicy                string `json:"tspu_stale_policy"`
	MaxSubscriptionBytes           int64  `json:"max_subscription_bytes"`
	MaxTSPUListBytes               int64  `json:"max_tspu_list_bytes"`
	MaxProbeSeconds                int    `json:"max_probe_seconds"`
	ParallelServerChecks           int    `json:"parallel_server_checks"`
	GeoLockedUnknownCountryIsSafe  bool   `json:"geo_locked_unknown_country_is_safe"`
	GeoLockedAllowDirect           bool   `json:"geo_locked_allow_direct"`
	GeoLockedAllowZapret           bool   `json:"geo_locked_allow_zapret"`
	DirectOnlyAllowForeignProxy    bool   `json:"direct_only_allow_foreign_proxy"`
}

type Xray struct {
	Binary                 string `json:"binary"`
	InitScript             string `json:"init_script,omitempty"`
	ActivationMode         string `json:"activation_mode,omitempty"`
	ConfigDir              string `json:"config_dir"`
	ActiveConfig           string `json:"active_config"`
	LastGoodConfig         string `json:"last_good_config"`
	GeneratedDir           string `json:"generated_dir"`
	ProbeSocksBasePort     int    `json:"probe_socks_base_port"`
	ProbeDNSResolver       string `json:"probe_dns_resolver"`
	DNSProxyBasePort       int    `json:"dns_proxy_base_port"`
	TransparentPort        int    `json:"transparent_port"`
	SubscriptionSecretFile string `json:"subscription_secret_file"`
	OutboundBundleSHA256   string `json:"outbound_bundle_sha256,omitempty"`
}

type Zapret struct {
	Binary         string `json:"binary"`
	InitScript     string `json:"init_script"`
	ActiveConfig   string `json:"active_config"`
	ActivationMode string `json:"activation_mode"`
	Strategy       string `json:"strategy"`
	QueueNum       int    `json:"queue_num"`
}

type GeoIP struct {
	Mode             string          `json:"mode"`
	Database         string          `json:"database"`
	SourceURL        string          `json:"source_url,omitempty"`
	MaxDatabaseBytes int64           `json:"max_database_bytes,omitempty"`
	MaxAgeHours      int             `json:"max_age_hours,omitempty"`
	FailCountry      string          `json:"fail_country"`
	Endpoints        []GeoIPEndpoint `json:"endpoints,omitempty"`
}

type GeoIPEndpoint struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	URL      string `json:"url"`
}

type OpenWrt struct {
	Adapter                string `json:"adapter"`
	NFTTable               string `json:"nft_table"`
	NFTFamily              string `json:"nft_family"`
	FirewallInclude        string `json:"firewall_include"`
	DNSMasqInclude         string `json:"dnsmasq_include"`
	WANRouteTable          int    `json:"wan_route_table"`
	ZapretRouteTable       int    `json:"zapret_route_table"`
	XrayRouteTable         int    `json:"xray_route_table"`
	DirectMark             string `json:"direct_mark"`
	ZapretMark             string `json:"zapret_mark"`
	XrayMark               string `json:"xray_mark"`
	XrayTProxyMark         string `json:"xray_tproxy_mark"`
	XrayBypassMark         string `json:"xray_bypass_mark"`
	DropMark               string `json:"drop_mark"`
	FlowOffloadingPolicy   string `json:"flow_offloading_policy"`
	ProbeTimeoutSeconds    int    `json:"probe_timeout_seconds"`
	RollbackTimeoutSeconds int    `json:"rollback_timeout_seconds"`
}

type Route struct {
	Type                string `json:"type"`
	Tag                 string `json:"tag"`
	Priority            int    `json:"priority"`
	Disabled            bool   `json:"disabled,omitempty"`
	Status              string `json:"status,omitempty"`
	DNSServer           string `json:"dns_server"`
	ConnectToResolvedIP bool   `json:"connect_to_resolved_ip"`
	SOCKS5              string `json:"socks5"`
	HTTPProxy           string `json:"http_proxy"`
	DNSMode             string `json:"dns_mode"`
	ExternalIPProbe     bool   `json:"external_ip_probe"`
	RequiresAdapter     bool   `json:"requires_adapter"`
	AdapterMode         string `json:"adapter_mode"`
	Mark                string `json:"mark"`
	ForbidProxy         bool   `json:"forbid_proxy"`
}

type Service struct {
	Category           string       `json:"category"`
	Domains            []string     `json:"domains"`
	AllowedPaths       []string     `json:"allowed_paths"`
	ForbiddenPaths     []string     `json:"forbidden_paths"`
	RequireNonRUEgress bool         `json:"require_non_ru_egress"`
	ProbeURLs          []ProbeCheck `json:"probe_urls"`
}

type PolicyOverride struct {
	ID        string `json:"id"`
	Scope     string `json:"scope"`
	DeviceMAC string `json:"device_mac,omitempty"`
	Domain    string `json:"domain,omitempty"`
	Service   string `json:"service,omitempty"`
	Category  string `json:"category,omitempty"`
	RouteType string `json:"route_type,omitempty"`
	RouteTag  string `json:"route_tag,omitempty"`
}

type ProbeCheck struct {
	Name                 string   `json:"name"`
	URL                  string   `json:"url"`
	Required             bool     `json:"required"`
	ExpectedCodes        []int    `json:"expected_codes"`
	BodyMode             string   `json:"body_mode"`
	SuccessMarkers       []string `json:"success_markers"`
	RegionalBlockMarkers []string `json:"regional_block_markers"`
	BlockMarkers         []string `json:"block_markers"`
}

func (p *ProbeCheck) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*p = ProbeCheck{
			Name:          "default",
			URL:           s,
			Required:      true,
			ExpectedCodes: []int{200},
			BodyMode:      "required",
		}
		return nil
	}
	type alias ProbeCheck
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*p = ProbeCheck(a)
	return nil
}

type NotificationConfig struct {
	TelegramSecretFile     string `json:"telegram_secret_file"`
	HTTPSWebhookSecretFile string `json:"https_webhook_secret_file"`
	DedupeSeconds          int    `json:"dedupe_seconds"`
}

type TSPUSource struct {
	Name         string  `json:"name"`
	Type         string  `json:"type"`
	URL          string  `json:"url"`
	MinEntries   int     `json:"min_entries"`
	MaxDropRatio float64 `json:"max_drop_ratio"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) Validate() error {
	if c.Version < 2 {
		return fmt.Errorf("config version must be >=2")
	}
	if c.Platform.Target == "glinet-flint2" {
		persistentStorage := c.Storage.StateDir == "/etc/router-policy/state" && c.Storage.RuntimeDir == "/tmp/router-policy" && c.Storage.Database == "/etc/router-policy/state/router-policy.bbolt"
		legacyStorage := c.Storage.StateDir == "/var/lib/router-policy" && c.Storage.RuntimeDir == "/tmp/router-policy" && c.Storage.Database == "/var/lib/router-policy/router-policy.bbolt" && legacyFlint2StateAlias()
		if !persistentStorage && !legacyStorage {
			return fmt.Errorf("Flint 2 storage must use persistent /etc/router-policy/state and volatile /tmp/router-policy runtime")
		}
		persistentData := c.Xray.LastGoodConfig == "/etc/router-policy/state/last-good/xray.json" && c.GeoIP.Database == "/etc/router-policy/state/geoip/user-country.mmdb"
		legacyData := c.Xray.LastGoodConfig == "/var/lib/router-policy/last-good/xray.json" && c.GeoIP.Database == "/var/lib/router-policy/geoip/user-country.mmdb" && legacyStorage
		if !persistentData && !legacyData {
			return fmt.Errorf("Flint 2 durable data paths must stay under /etc/router-policy/state")
		}
	}
	if len(c.Routes) == 0 {
		return fmt.Errorf("routes are empty")
	}
	seenRoutes := map[string]bool{}
	routesByTag := map[string]Route{}
	enabledDrop := false
	hasVLESS := false
	hasZapret := false
	enabledVLESSCount := 0
	hasTransparentRoute := false
	transparentSOCKSPorts := map[int]string{}
	for _, r := range c.Routes {
		if !routeTagPattern.MatchString(r.Tag) || !validRouteType(r.Type) {
			return fmt.Errorf("route with empty tag/type")
		}
		if seenRoutes[r.Tag] {
			return fmt.Errorf("duplicate route tag: %s", r.Tag)
		}
		if !r.Disabled && r.Status == "NOT_CONFIGURED" {
			return fmt.Errorf("route %s is NOT_CONFIGURED but not disabled", r.Tag)
		}
		switch r.Status {
		case "", "NOT_CONFIGURED", "CONFIGURED", "ACTIVE", "DEGRADED", "SELECTED", "STANDBY", "QUARANTINED", "UNSUPPORTED":
		default:
			return fmt.Errorf("route %s has invalid status", r.Tag)
		}
		if r.Enabled() && r.Type == "drop" {
			enabledDrop = true
		}
		if !r.Disabled && r.Type == "smart_dns" && (r.DNSServer == "" || strings.Contains(r.DNSServer, "PLACEHOLDER")) {
			return fmt.Errorf("smart_dns route %s has no real dns_server", r.Tag)
		}
		if r.Enabled() && r.Type == "smart_dns" {
			host, portText, err := net.SplitHostPort(r.DNSServer)
			port, portErr := strconv.Atoi(portText)
			ip := net.ParseIP(host)
			if err != nil || portErr != nil || port < 1 || port > 65535 || ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || !r.ConnectToResolvedIP {
				return fmt.Errorf("smart_dns route %s requires a public resolver endpoint and connect_to_resolved_ip", r.Tag)
			}
		}
		if r.Enabled() && r.Type == "vless" {
			hasVLESS = true
			enabledVLESSCount++
			if !strings.HasPrefix(r.SOCKS5, "127.0.0.1:") {
				return fmt.Errorf("vless route %s must use a loopback SOCKS endpoint", r.Tag)
			}
		}
		if r.Enabled() && r.Type == "zapret" {
			hasZapret = true
		}
		if r.Enabled() && (r.Type == "vless" || r.Type == "tg_ws_proxy") {
			hasTransparentRoute = true
			if r.DNSMode != "socks_remote" || r.DNSServer == "" || r.DNSServer != c.Xray.ProbeDNSResolver {
				return fmt.Errorf("transparent route %s must use the configured SOCKS DNS resolver", r.Tag)
			}
			host, portText, err := net.SplitHostPort(r.SOCKS5)
			port, portErr := strconv.Atoi(portText)
			if err != nil || portErr != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || port < 1 || port > 65535 {
				return fmt.Errorf("transparent route %s must use a valid loopback SOCKS endpoint", r.Tag)
			}
			if previous := transparentSOCKSPorts[port]; previous != "" {
				return fmt.Errorf("transparent routes %s and %s reuse SOCKS port %d", previous, r.Tag, port)
			}
			transparentSOCKSPorts[port] = r.Tag
		}
		seenRoutes[r.Tag] = true
		routesByTag[r.Tag] = r
	}
	if !enabledDrop {
		return fmt.Errorf("an enabled drop route is required for fail-closed policy")
	}
	if c.OpenWrt.NFTFamily != "" && c.OpenWrt.NFTFamily != "inet" {
		return fmt.Errorf("openwrt.nft_family must be inet")
	}
	if c.OpenWrt.NFTTable != "" && !nftTablePattern.MatchString(c.OpenWrt.NFTTable) {
		return fmt.Errorf("openwrt.nft_table is invalid")
	}
	switch c.OpenWrt.FlowOffloadingPolicy {
	case "", "preserve", "disable":
	default:
		return fmt.Errorf("openwrt.flow_offloading_policy must be preserve or disable")
	}
	markTables := map[uint64]int{}
	for _, route := range c.Routes {
		if !route.Enabled() {
			continue
		}
		mark := route.Mark
		if mark == "" {
			mark = c.markForRouteType(route.Type)
		}
		value, err := parseFirewallMark(mark)
		if err != nil {
			return fmt.Errorf("route %s mark: %w", route.Tag, err)
		}
		table := c.tableForRouteType(route.Type)
		if route.Type != "drop" && table < 1 {
			return fmt.Errorf("route %s has no route table", route.Tag)
		}
		if previous, ok := markTables[value]; ok && previous != table {
			return fmt.Errorf("route %s mark maps to conflicting route tables", route.Tag)
		}
		markTables[value] = table
	}
	if hasVLESS && !sha256ReferencePattern.MatchString(c.Xray.OutboundBundleSHA256) {
		return fmt.Errorf("enabled vless routes require a bound Xray outbound bundle")
	}
	switch c.Xray.ActivationMode {
	case "", "candidate_only", "managed":
	default:
		return fmt.Errorf("xray.activation_mode must be candidate_only or managed")
	}
	if c.Xray.ActivationMode == "managed" && c.Xray.InitScript != "/etc/init.d/router-policy-xray" {
		return fmt.Errorf("managed xray requires the project-owned init script")
	}
	if hasZapret {
		if c.Zapret.ActivationMode != "managed" {
			return fmt.Errorf("enabled zapret route requires managed zapret activation")
		}
		if c.Zapret.Binary != "/usr/bin/nfqws" || c.Zapret.InitScript != "/etc/init.d/router-policy-zapret" || c.Zapret.ActiveConfig != "/etc/router-policy/zapret/nfqws.conf" {
			return fmt.Errorf("managed zapret paths must use project-owned fixed locations")
		}
		if c.Zapret.QueueNum < 1 || c.Zapret.QueueNum > 65535 {
			return fmt.Errorf("zapret.queue_num must be in 1..65535")
		}
		if c.Zapret.Strategy != "tls-fake-ttl3-v1" {
			return fmt.Errorf("unsupported zapret strategy")
		}
	}
	if !hasVLESS && c.Xray.OutboundBundleSHA256 != "" {
		return fmt.Errorf("Xray outbound bundle is set without enabled vless routes")
	}
	if hasTransparentRoute {
		if c.Xray.TransparentPort < 1024 || c.Xray.TransparentPort > 65535 {
			return fmt.Errorf("enabled transparent routes require xray.transparent_port in 1024..65535")
		}
		if route := transparentSOCKSPorts[c.Xray.TransparentPort]; route != "" {
			return fmt.Errorf("xray.transparent_port collides with route %s SOCKS endpoint", route)
		}
		resolverHost, resolverPort, err := net.SplitHostPort(c.Xray.ProbeDNSResolver)
		resolverIP := net.ParseIP(resolverHost)
		port, portErr := strconv.Atoi(resolverPort)
		if err != nil || portErr != nil || port != 53 || resolverIP == nil || resolverIP.IsUnspecified() || resolverIP.IsLoopback() || resolverIP.IsPrivate() || resolverIP.IsLinkLocalUnicast() || resolverIP.IsMulticast() {
			return fmt.Errorf("enabled transparent routes require a public xray.probe_dns_resolver on port 53")
		}
		marks := map[string]string{
			"openwrt.direct_mark":      c.OpenWrt.DirectMark,
			"openwrt.zapret_mark":      c.OpenWrt.ZapretMark,
			"openwrt.xray_mark":        c.OpenWrt.XrayMark,
			"openwrt.xray_tproxy_mark": c.OpenWrt.XrayTProxyMark,
			"openwrt.xray_bypass_mark": c.OpenWrt.XrayBypassMark,
			"openwrt.drop_mark":        c.OpenWrt.DropMark,
		}
		seenMarks := map[uint64]string{}
		for name, mark := range marks {
			value, err := parseFirewallMark(mark)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			if previous := seenMarks[value]; previous != "" {
				return fmt.Errorf("%s collides with %s", name, previous)
			}
			seenMarks[value] = name
		}
	}
	if enabledVLESSCount > 0 {
		basePort := c.Xray.DNSProxyBasePort
		if basePort == 0 {
			basePort = 14000
		}
		if basePort < 1024 || basePort > 65535 || enabledVLESSCount-1 > 65535-basePort {
			return fmt.Errorf("enabled vless routes exhaust xray DNS proxy ports")
		}
		for port := basePort; port < basePort+enabledVLESSCount; port++ {
			if port == c.Xray.TransparentPort || transparentSOCKSPorts[port] != "" {
				return fmt.Errorf("xray DNS proxy port %d collides with another listener", port)
			}
		}
	}
	seenGeoIPProviders := map[string]bool{}
	if c.GeoIP.SourceURL != "" {
		parsed, err := url.Parse(c.GeoIP.SourceURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return fmt.Errorf("GeoIP source must be HTTPS without credentials or fragment")
		}
		if c.GeoIP.Database == "" || c.GeoIP.MaxDatabaseBytes <= 0 || c.GeoIP.MaxDatabaseBytes > 16<<20 || c.GeoIP.MaxAgeHours <= 0 {
			return fmt.Errorf("GeoIP source requires database, bounded size and max age")
		}
	}
	for _, endpoint := range c.GeoIP.Endpoints {
		if endpoint.Name == "" || len(endpoint.Name) > 64 || endpoint.URL == "" || seenGeoIPProviders[endpoint.Provider] {
			return fmt.Errorf("invalid or duplicate GeoIP endpoint")
		}
		switch endpoint.Provider {
		case "country_is", "ipwho_is":
		default:
			return fmt.Errorf("unsupported GeoIP endpoint provider: %s", endpoint.Provider)
		}
		parsed, err := url.Parse(endpoint.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return fmt.Errorf("GeoIP endpoint %s must be HTTPS without credentials or fragment", endpoint.Name)
		}
		seenGeoIPProviders[endpoint.Provider] = true
	}
	seenDomains := map[string]string{}
	for name, svc := range c.Services {
		if !validServiceCategory(svc.Category) {
			return fmt.Errorf("service %s has empty category", name)
		}
		if len(svc.Domains) == 0 {
			return fmt.Errorf("service %s has no domains", name)
		}
		if len(svc.AllowedPaths) == 0 {
			return fmt.Errorf("service %s has no allowed_paths", name)
		}
		seenPaths := map[string]bool{}
		for _, path := range svc.AllowedPaths {
			if !validRouteType(path) || seenPaths[path] {
				return fmt.Errorf("service %s has invalid or duplicate allowed path", name)
			}
			seenPaths[path] = true
		}
		for _, path := range svc.ForbiddenPaths {
			if !validRouteType(path) {
				return fmt.Errorf("service %s has invalid forbidden path", name)
			}
		}
		if svc.Category == "DIRECT_ONLY" && (len(svc.AllowedPaths) != 1 || svc.AllowedPaths[0] != "direct") {
			return fmt.Errorf("DIRECT_ONLY service %s must allow only direct", name)
		}
		if svc.Category == "GEO_LOCKED" {
			if !svc.RequireNonRUEgress {
				return fmt.Errorf("GEO_LOCKED service %s must require non-RU egress", name)
			}
			if containsString(svc.AllowedPaths, "direct") && !c.Policy.GeoLockedAllowDirect || containsString(svc.AllowedPaths, "zapret") && !c.Policy.GeoLockedAllowZapret {
				return fmt.Errorf("GEO_LOCKED service %s allows a route forbidden by policy", name)
			}
		}
		for i, domain := range svc.Domains {
			normalized, err := normalizeDomain(domain)
			if err != nil {
				return fmt.Errorf("service %s has invalid domain %q", name, domain)
			}
			if owner := seenDomains[normalized]; owner != "" && owner != name {
				return fmt.Errorf("domain %s belongs to both %s and %s", normalized, owner, name)
			}
			seenDomains[normalized] = name
			svc.Domains[i] = normalized
		}
		for _, p := range svc.ProbeURLs {
			if p.Name == "" || p.URL == "" {
				return fmt.Errorf("service %s has invalid probe", name)
			}
			if _, err := url.ParseRequestURI(p.URL); err != nil {
				return fmt.Errorf("service %s probe %s invalid url: %w", name, p.Name, err)
			}
			if len(p.ExpectedCodes) == 0 {
				return fmt.Errorf("service %s probe %s has no expected_codes", name, p.Name)
			}
			switch p.BodyMode {
			case "required", "optional", "empty", "ignored":
			default:
				return fmt.Errorf("service %s probe %s invalid body_mode: %s", name, p.Name, p.BodyMode)
			}
		}
		c.Services[name] = svc
	}
	if err := c.validateOverrides(routesByTag); err != nil {
		return err
	}
	seenTSPUSources := map[string]bool{}
	for _, source := range c.TSPUSources {
		if source.Name == "" || len(source.Name) > 64 || seenTSPUSources[source.Name] || source.Type != "domains" || source.MinEntries < 1 || source.MaxDropRatio < 0 || source.MaxDropRatio > 1 {
			return fmt.Errorf("invalid or duplicate TSPU source: %s", source.Name)
		}
		parsed, err := url.Parse(source.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return fmt.Errorf("TSPU source %s must use HTTPS without credentials or fragment", source.Name)
		}
		seenTSPUSources[source.Name] = true
	}
	if c.Policy.DomainDecisionTTLSeconds < 0 {
		return fmt.Errorf("domain_decision_ttl_seconds cannot be negative")
	}
	if c.Storage.MaxAutoDomains < 0 || c.Storage.MaxAutoDomains > 100000 {
		return fmt.Errorf("max_auto_domains must be between 0 and 100000")
	}
	switch c.Policy.TSPUStalePolicy {
	case "", "fail_open", "zapret_first", "fail_closed":
	default:
		return fmt.Errorf("invalid tspu_stale_policy")
	}
	return nil
}

func legacyFlint2StateAlias() bool {
	resolved, err := filepath.EvalSymlinks("/var/lib/router-policy")
	return err == nil && filepath.Clean(resolved) == "/etc/router-policy/state"
}

func (c *Config) validateOverrides(routesByTag map[string]Route) error {
	seenIDs := map[string]bool{}
	seenSelectors := map[string]bool{}
	for index, override := range c.Overrides {
		if !routeTagPattern.MatchString(override.ID) || seenIDs[override.ID] {
			return fmt.Errorf("invalid or duplicate policy override id")
		}
		seenIDs[override.ID] = true
		if override.Domain != "" {
			normalized, err := normalizeDomain(override.Domain)
			if err != nil {
				return fmt.Errorf("override %s has invalid domain", override.ID)
			}
			override.Domain = normalized
		}
		if override.DeviceMAC != "" {
			hardware, err := net.ParseMAC(override.DeviceMAC)
			if err != nil || len(hardware) != 6 {
				return fmt.Errorf("override %s has invalid device MAC", override.ID)
			}
			override.DeviceMAC = strings.ToLower(hardware.String())
		}
		selector, err := validateOverrideSelector(override, c.Services)
		if err != nil {
			return fmt.Errorf("override %s: %w", override.ID, err)
		}
		if seenSelectors[selector] {
			return fmt.Errorf("duplicate policy override selector: %s", selector)
		}
		seenSelectors[selector] = true

		targetType := override.RouteType
		if override.RouteTag != "" {
			route, ok := routesByTag[override.RouteTag]
			if !ok || !route.Enabled() {
				return fmt.Errorf("override %s targets an unavailable route", override.ID)
			}
			if targetType != "" && targetType != route.Type {
				return fmt.Errorf("override %s route tag/type mismatch", override.ID)
			}
			targetType = route.Type
		}
		if !validRouteType(targetType) {
			return fmt.Errorf("override %s has invalid route action", override.ID)
		}
		if override.RouteTag == "" {
			available := false
			for _, route := range routesByTag {
				if route.Enabled() && route.Type == targetType {
					available = true
					break
				}
			}
			if !available {
				return fmt.Errorf("override %s targets an unavailable route type", override.ID)
			}
		}
		if err := c.validateOverrideSafety(override, targetType); err != nil {
			return err
		}
		c.Overrides[index] = override
	}
	return nil
}

func validateOverrideSelector(override PolicyOverride, services map[string]Service) (string, error) {
	switch override.Scope {
	case "exact_domain":
		if override.Domain == "" || override.DeviceMAC != "" || override.Service != "" || override.Category != "" {
			return "", fmt.Errorf("exact_domain requires only domain")
		}
		return override.Scope + ":" + override.Domain, nil
	case "device_domain":
		if override.DeviceMAC == "" || override.Domain == "" || override.Service != "" || override.Category != "" {
			return "", fmt.Errorf("device_domain requires device_mac and domain")
		}
		return override.Scope + ":" + override.DeviceMAC + ":" + override.Domain, nil
	case "device_service":
		if override.DeviceMAC == "" || override.Service == "" || override.Domain != "" || override.Category != "" {
			return "", fmt.Errorf("device_service requires device_mac and service")
		}
		if _, ok := services[override.Service]; !ok {
			return "", fmt.Errorf("unknown service")
		}
		return override.Scope + ":" + override.DeviceMAC + ":" + override.Service, nil
	case "service":
		if override.Service == "" || override.DeviceMAC != "" || override.Domain != "" || override.Category != "" {
			return "", fmt.Errorf("service scope requires only service")
		}
		if _, ok := services[override.Service]; !ok {
			return "", fmt.Errorf("unknown service")
		}
		return override.Scope + ":" + override.Service, nil
	case "category":
		if !validServiceCategory(override.Category) || override.DeviceMAC != "" || override.Domain != "" || override.Service != "" {
			return "", fmt.Errorf("category scope requires only a valid category")
		}
		return override.Scope + ":" + override.Category, nil
	default:
		return "", fmt.Errorf("invalid scope")
	}
}

func (c *Config) validateOverrideSafety(override PolicyOverride, targetType string) error {
	var affected []Service
	switch override.Scope {
	case "exact_domain", "device_domain":
		if name := c.ServiceForDomain(override.Domain); name != "" {
			affected = append(affected, c.Services[name])
		}
	case "device_service", "service":
		affected = append(affected, c.Services[override.Service])
	case "category":
		for _, service := range c.Services {
			if service.Category == override.Category {
				affected = append(affected, service)
			}
		}
	}
	for _, service := range affected {
		if service.Category == "DIRECT_ONLY" && targetType != "direct" {
			return fmt.Errorf("override %s violates DIRECT_ONLY", override.ID)
		}
		if service.Category == "BLOCKED" && targetType != "drop" {
			return fmt.Errorf("override %s violates BLOCKED", override.ID)
		}
		if service.Category == "GEO_LOCKED" && (targetType == "direct" && !c.Policy.GeoLockedAllowDirect || targetType == "zapret" && !c.Policy.GeoLockedAllowZapret) {
			return fmt.Errorf("override %s violates GEO_LOCKED", override.ID)
		}
	}
	return nil
}

func validRouteType(routeType string) bool {
	switch routeType {
	case "direct", "zapret", "smart_dns", "tg_ws_proxy", "vless", "drop":
		return true
	default:
		return false
	}
}

func validServiceCategory(category string) bool {
	switch category {
	case "GEO_LOCKED", "TSPU_RESTRICTED", "TELEGRAM", "DIRECT_ONLY", "DIRECT_PREFERRED", "BLOCKED":
		return true
	default:
		return false
	}
}

func normalizeDomain(domain string) (string, error) {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", err
	}
	ascii = strings.ToLower(strings.TrimSuffix(ascii, "."))
	if ascii == "" || len(ascii) > 253 || net.ParseIP(ascii) != nil || strings.Contains(ascii, "*") {
		return "", fmt.Errorf("invalid domain")
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("domain has no suffix")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid domain label")
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return "", fmt.Errorf("invalid domain character")
			}
		}
	}
	return ascii, nil
}

func (c *Config) markForRouteType(routeType string) string {
	switch routeType {
	case "direct", "smart_dns":
		return c.OpenWrt.DirectMark
	case "zapret":
		return c.OpenWrt.ZapretMark
	case "vless", "tg_ws_proxy":
		return c.OpenWrt.XrayMark
	case "drop":
		return c.OpenWrt.DropMark
	default:
		return ""
	}
}

func (c *Config) tableForRouteType(routeType string) int {
	switch routeType {
	case "direct", "smart_dns":
		return c.OpenWrt.WANRouteTable
	case "zapret":
		return c.OpenWrt.ZapretRouteTable
	case "vless", "tg_ws_proxy":
		return c.OpenWrt.XrayRouteTable
	default:
		return 0
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func parseFirewallMark(value string) (uint64, error) {
	if !firewallMarkPattern.MatchString(value) {
		return 0, fmt.Errorf("firewall mark must be 0x followed by 1..8 hex digits")
	}
	parsed, err := strconv.ParseUint(value[2:], 16, 32)
	if err != nil || parsed == 0 {
		return 0, fmt.Errorf("firewall mark must be a non-zero 32-bit value")
	}
	return parsed, nil
}

func (c *Config) RouteByTag(tag string) (Route, bool) {
	for _, r := range c.Routes {
		if r.Tag == tag {
			return r, true
		}
	}
	return Route{}, false
}

func (c *Config) RoutesByType(routeType string) []Route {
	var out []Route
	for _, r := range c.Routes {
		if r.Type == routeType && r.Enabled() {
			out = append(out, r)
		}
	}
	return out
}

func (r Route) Enabled() bool {
	if r.Disabled || r.Status == "NOT_CONFIGURED" {
		return false
	}
	if r.Type == "smart_dns" && (r.DNSServer == "" || strings.Contains(r.DNSServer, "PLACEHOLDER")) {
		return false
	}
	return true
}

func (c *Config) ServiceForDomain(domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	for name, svc := range c.Services {
		for _, d := range svc.Domains {
			d = strings.TrimSuffix(strings.ToLower(d), ".")
			if domain == d || strings.HasSuffix(domain, "."+d) {
				return name
			}
		}
	}
	return ""
}

func PathAllowed(svc Service, route Route, policy Policy) bool {
	if svc.Category == "GEO_LOCKED" {
		if route.Type == "direct" && !policy.GeoLockedAllowDirect {
			return false
		}
		if route.Type == "zapret" && !policy.GeoLockedAllowZapret {
			return false
		}
	}
	if svc.Category == "DIRECT_ONLY" && route.Type != "direct" {
		return false
	}
	for _, f := range svc.ForbiddenPaths {
		if f == route.Type {
			return false
		}
	}
	for _, a := range svc.AllowedPaths {
		if a == route.Type {
			return true
		}
	}
	return false
}
