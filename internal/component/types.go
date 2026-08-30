package component

import "time"

type Kind string

const (
	KindXray   Kind = "xray"
	KindZapret Kind = "zapret"
	KindTGWS   Kind = "tg_ws_proxy"
)

func (k Kind) Valid() bool {
	switch k {
	case KindXray, KindZapret, KindTGWS:
		return true
	default:
		return false
	}
}

type Action string

const (
	ActionInstall      Action = "install"
	ActionCheck        Action = "check"
	ActionCheckUpdates Action = "check_updates"
	ActionUpdate       Action = "update"
	ActionRestart      Action = "restart"
	ActionRollback     Action = "rollback"
	ActionUninstall    Action = "uninstall"
)

func (a Action) Valid() bool {
	switch a {
	case ActionInstall, ActionCheck, ActionCheckUpdates, ActionUpdate, ActionRestart, ActionRollback, ActionUninstall:
		return true
	default:
		return false
	}
}

type Asset struct {
	Architecture string `json:"architecture"`
	PackageType  string `json:"package_type"`
	URL          string `json:"url"`
	SHA256       string `json:"sha256"`
	// BinarySHA256 pins the extracted executable when the asset is an archive.
	// SHA256 remains the checksum of the downloaded asset itself.
	BinarySHA256 string `json:"binary_sha256,omitempty"`
	Size         int64  `json:"size"`
	Member       string `json:"member,omitempty"`
}

type Release struct {
	Kind            Kind    `json:"kind"`
	Version         string  `json:"version"`
	Source          string  `json:"source"`
	ReleaseAPI      string  `json:"release_api"`
	MinimumFreeByte int64   `json:"minimum_free_bytes"`
	Assets          []Asset `json:"assets"`
}

type Platform struct {
	GOARCH               string   `json:"goarch"`
	Machine              string   `json:"machine"`
	PackageManager       string   `json:"package_manager"`
	PackageArchitectures []string `json:"package_architectures,omitempty"`
}

type Preflight struct {
	Ready          bool     `json:"ready"`
	Architecture   string   `json:"architecture"`
	PackageManager string   `json:"package_manager"`
	FreeBytes      int64    `json:"free_bytes"`
	RequiredBytes  int64    `json:"required_bytes"`
	Capabilities   []string `json:"capabilities,omitempty"`
	Missing        []string `json:"missing,omitempty"`
	Reason         string   `json:"reason,omitempty"`
}

type Health struct {
	State          string    `json:"state"`
	ServiceState   string    `json:"service_state"`
	Ready          bool      `json:"ready"`
	Reason         string    `json:"reason,omitempty"`
	LastSuccessful time.Time `json:"last_successful,omitempty"`
	Details        []string  `json:"details,omitempty"`
}

type Record struct {
	Kind            Kind      `json:"kind"`
	Installed       bool      `json:"installed"`
	Version         string    `json:"version,omitempty"`
	Source          string    `json:"source,omitempty"`
	Checksum        string    `json:"checksum,omitempty"`
	BinaryChecksum  string    `json:"binary_checksum,omitempty"`
	Architecture    string    `json:"architecture,omitempty"`
	PackageType     string    `json:"package_type,omitempty"`
	InstalledAt     time.Time `json:"installed_at,omitempty"`
	LastCheckedAt   time.Time `json:"last_checked_at,omitempty"`
	RollbackVersion string    `json:"rollback_version,omitempty"`
	RollbackPath    string    `json:"rollback_path,omitempty"`
}

type Status struct {
	Kind      Kind `json:"kind"`
	Installed bool `json:"installed"`
	// Detected means that a compatible executable/package was found on the
	// platform. It is intentionally independent from Managed: a binary found
	// outside FlintRoute must never be presented as a FlintRoute-owned service.
	Detected            bool   `json:"detected"`
	Managed             bool   `json:"managed"`
	Ownership           string `json:"ownership"` // flintroute, foreign, absent
	Version             string `json:"version,omitempty"`
	LatestSupported     string `json:"latest_supported_version"`
	LatestUpstream      string `json:"latest_upstream_version,omitempty"`
	UpdateAvailable     bool   `json:"update_available"`
	UpdateBlockedReason string `json:"update_blocked_reason,omitempty"`
	Architecture        string `json:"architecture,omitempty"`
	Source              string `json:"source"`
	// PinnedAssetURL is the immutable release artifact used for the installed
	// component. Source remains the human-facing upstream repository; setup
	// flows must use this URL when they need a version-bound source.
	PinnedAssetURL       string     `json:"pinned_asset_url,omitempty"`
	Checksum             string     `json:"checksum,omitempty"`
	BinaryChecksum       string     `json:"binary_sha256,omitempty"`
	ServiceState         string     `json:"service_state"`
	HealthState          string     `json:"health_state"`
	HealthReady          bool       `json:"health_ready"`
	HealthReason         string     `json:"health_reason,omitempty"`
	LastSuccessfulCheck  time.Time  `json:"last_successful_check,omitempty"`
	LastCheckedAt        time.Time  `json:"last_checked_at,omitempty"`
	RollbackVersion      string     `json:"rollback_version,omitempty"`
	NextActions          []string   `json:"next_actions,omitempty"`
	RequiresConfirmation bool       `json:"requires_confirmation,omitempty"`
	Preflight            *Preflight `json:"preflight,omitempty"`
}

type Request struct {
	Kind              Kind   `json:"kind"`
	Action            Action `json:"action"`
	PreserveConfig    bool   `json:"preserve_config,omitempty"`
	ConfirmDisruption bool   `json:"confirm_disruption,omitempty"`
}

type Result struct {
	Status   Status   `json:"status"`
	Action   Action   `json:"action"`
	Changed  bool     `json:"changed"`
	Rollback bool     `json:"rollback_performed"`
	Stages   []string `json:"stages"`
}
