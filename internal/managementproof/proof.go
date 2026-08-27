package managementproof

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	SchemaVersion = 1
	ModeLAN       = "lan"
	ModeHeadless  = "headless"
	ModeAutomatic = "automatic"

	defaultBootIDPath = "/proc/sys/kernel/random/boot_id"
	maxProofTTL       = time.Hour
)

var (
	transactionPattern = regexp.MustCompile(`^tx_[a-f0-9]{16}$`)
	revisionPattern    = regexp.MustCompile(`^rev_[0-9]+_[a-f0-9]{12}$`)
	interfacePattern   = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
)

type Binding struct {
	TransactionID string
	RevisionID    string
}

type Observation struct {
	Mode               string
	ClientIP           netip.Addr
	LocalIP            netip.Addr
	Interface          string
	Subnet             netip.Prefix
	ControlPlaneURL    string
	AdminHTTPURL       string
	AdminHTTPAvailable bool
}

type Proof struct {
	SchemaVersion      int    `json:"schema_version"`
	Mode               string `json:"mode"`
	TransactionID      string `json:"transaction_id"`
	RevisionID         string `json:"revision_id"`
	BootID             string `json:"boot_id"`
	IssuedAt           string `json:"issued_at"`
	ExpiresAt          string `json:"expires_at"`
	ClientIP           string `json:"client_ip"`
	LocalIP            string `json:"local_ip"`
	Interface          string `json:"interface"`
	Subnet             string `json:"subnet"`
	ControlPlaneURL    string `json:"control_plane_url"`
	AdminHTTPURL       string `json:"admin_http_url,omitempty"`
	AdminHTTPAvailable bool   `json:"admin_http_available"`
	Signature          string `json:"signature"`
}

type Resolver interface {
	Resolve(localIP, clientIP netip.Addr) (string, netip.Prefix, error)
}

type AutomaticInterface struct {
	Name     string
	Up       bool
	Loopback bool
	Prefixes []netip.Prefix
}

type AutomaticNeighbor struct {
	Interface string
	IP        netip.Addr
	Reachable bool
}

type AutomaticTopology struct {
	Interfaces             []AutomaticInterface
	DefaultRouteInterfaces []string
	Neighbors              []AutomaticNeighbor
}

type AutomaticTopologySource interface {
	Snapshot(context.Context) (AutomaticTopology, error)
}

type systemAutomaticTopologySource struct{}

type SystemResolver struct{}

func (SystemResolver) Resolve(localIP, clientIP netip.Addr) (string, netip.Prefix, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", netip.Prefix{}, err
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, raw := range addrs {
			prefix, err := netip.ParsePrefix(raw.String())
			if err != nil || prefix.Addr().Unmap() != localIP.Unmap() {
				continue
			}
			prefix = netip.PrefixFrom(localIP.Unmap(), prefix.Bits()).Masked()
			if !prefix.Contains(clientIP.Unmap()) {
				return "", netip.Prefix{}, fmt.Errorf("management client is outside the local interface subnet")
			}
			return iface.Name, prefix, nil
		}
	}
	return "", netip.Prefix{}, fmt.Errorf("local management interface was not found")
}

type Options struct {
	KeyPath         string
	BootIDPath      string
	Now             func() time.Time
	Resolver        Resolver
	AdminProbe      func(context.Context, string) bool
	AutomaticSource AutomaticTopologySource
}

type Manager struct {
	stateDir        string
	runtimeDir      string
	keyPath         string
	bootIDPath      string
	now             func() time.Time
	resolver        Resolver
	adminProbe      func(context.Context, string) bool
	automaticSource AutomaticTopologySource
}

func New(stateDir, runtimeDir string, opts Options) (*Manager, error) {
	stateDir = filepath.Clean(stateDir)
	runtimeDir = filepath.Clean(runtimeDir)
	if stateDir == "." || runtimeDir == "." {
		return nil, fmt.Errorf("state and runtime directories are required")
	}
	keyPath := opts.KeyPath
	if keyPath == "" {
		keyPath = filepath.Join(stateDir, "management-proof.key")
	}
	bootIDPath := opts.BootIDPath
	if bootIDPath == "" {
		bootIDPath = defaultBootIDPath
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	resolver := opts.Resolver
	if resolver == nil {
		resolver = SystemResolver{}
	}
	adminProbe := opts.AdminProbe
	if adminProbe == nil {
		adminProbe = probeAdminHTTP
	}
	automaticSource := opts.AutomaticSource
	if automaticSource == nil {
		automaticSource = systemAutomaticTopologySource{}
	}
	manager := &Manager{stateDir: stateDir, runtimeDir: runtimeDir, keyPath: filepath.Clean(keyPath), bootIDPath: filepath.Clean(bootIDPath), now: now, resolver: resolver, adminProbe: adminProbe, automaticSource: automaticSource}
	if _, err := manager.loadOrCreateKey(); err != nil {
		return nil, err
	}
	return manager, nil
}

func (m *Manager) ProofPath(binding Binding) (string, error) {
	if err := validateBinding(binding); err != nil {
		return "", err
	}
	return filepath.Join(m.runtimeDir, "management-proofs", binding.RevisionID+"-"+binding.TransactionID+".json"), nil
}

func (m *Manager) Issue(ctx context.Context, binding Binding, observation Observation, ttl time.Duration) (Proof, error) {
	if err := validateBinding(binding); err != nil {
		return Proof{}, err
	}
	if err := validateObservation(observation); err != nil {
		return Proof{}, err
	}
	if ttl <= 0 || ttl > maxProofTTL {
		return Proof{}, fmt.Errorf("management proof TTL must be between 1 second and 1 hour")
	}
	key, err := m.loadOrCreateKey()
	if err != nil {
		return Proof{}, err
	}
	bootID, err := readBootID(m.bootIDPath)
	if err != nil {
		return Proof{}, err
	}
	now := m.now().UTC()
	proof := Proof{
		SchemaVersion:      SchemaVersion,
		Mode:               observation.Mode,
		TransactionID:      binding.TransactionID,
		RevisionID:         binding.RevisionID,
		BootID:             bootID,
		IssuedAt:           now.Format(time.RFC3339Nano),
		ExpiresAt:          now.Add(ttl).Format(time.RFC3339Nano),
		ClientIP:           observation.ClientIP.Unmap().String(),
		LocalIP:            observation.LocalIP.Unmap().String(),
		Interface:          observation.Interface,
		Subnet:             observation.Subnet.Masked().String(),
		ControlPlaneURL:    observation.ControlPlaneURL,
		AdminHTTPURL:       observation.AdminHTTPURL,
		AdminHTTPAvailable: observation.AdminHTTPAvailable,
	}
	proof.Signature, err = signProof(key, proof)
	if err != nil {
		return Proof{}, err
	}
	path, _ := m.ProofPath(binding)
	if err := writeJSONAtomic(path, proof, 0o600); err != nil {
		return Proof{}, err
	}
	return proof, nil
}

func (m *Manager) IssueLANRequest(ctx context.Context, binding Binding, request *http.Request, ttl time.Duration) (Proof, error) {
	observation, err := m.ObserveLANRequest(ctx, request)
	if err != nil {
		return Proof{}, err
	}
	return m.Issue(ctx, binding, observation, ttl)
}

func (m *Manager) ObserveLANRequest(ctx context.Context, request *http.Request) (Observation, error) {
	if request == nil {
		return Observation{}, fmt.Errorf("management request is required")
	}
	clientIP, _, err := splitAddress(request.RemoteAddr)
	if err != nil {
		return Observation{}, fmt.Errorf("parse management client: %w", err)
	}
	localAddr, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok || localAddr == nil {
		return Observation{}, fmt.Errorf("local management listener address is unavailable")
	}
	localIP, localPort, err := splitAddress(localAddr.String())
	if err != nil {
		return Observation{}, fmt.Errorf("parse management listener: %w", err)
	}
	if localIP.IsUnspecified() {
		hostIP, hostPort, hostErr := splitAddress(request.Host)
		if hostErr != nil || hostIP.IsUnspecified() || hostIP.IsLoopback() {
			return Observation{}, fmt.Errorf("wildcard listener requires a literal LAN address in the HTTP Host header")
		}
		localIP = hostIP
		if hostPort != "" {
			localPort = hostPort
		}
	}
	if clientIP.IsLoopback() || localIP.IsLoopback() || localIP.IsUnspecified() {
		return Observation{}, fmt.Errorf("LAN proof requires a non-loopback client and listener")
	}
	interfaceName, subnet, err := m.resolver.Resolve(localIP, clientIP)
	if err != nil {
		return Observation{}, err
	}
	controlURL := "http://" + net.JoinHostPort(localIP.String(), localPort) + "/api/v1/health"
	adminURL := "http://" + net.JoinHostPort(localIP.String(), "80") + "/"
	return Observation{
		Mode: ModeLAN, ClientIP: clientIP, LocalIP: localIP, Interface: interfaceName, Subnet: subnet,
		ControlPlaneURL: controlURL, AdminHTTPURL: adminURL, AdminHTTPAvailable: m.adminProbe(ctx, adminURL),
	}, nil
}

func (m *Manager) IssueHeadlessSSH(ctx context.Context, binding Binding, sshConnection string, ttl time.Duration) (Proof, error) {
	fields := strings.Fields(sshConnection)
	if len(fields) != 4 {
		return Proof{}, fmt.Errorf("SSH_CONNECTION must contain client IP, client port, server IP and server port")
	}
	clientIP, err := netip.ParseAddr(fields[0])
	if err != nil {
		return Proof{}, fmt.Errorf("parse SSH client IP: %w", err)
	}
	localIP, err := netip.ParseAddr(fields[2])
	if err != nil {
		return Proof{}, fmt.Errorf("parse SSH server IP: %w", err)
	}
	if clientIP.IsLoopback() || localIP.IsLoopback() || localIP.IsUnspecified() {
		return Proof{}, fmt.Errorf("headless proof requires a non-loopback SSH path")
	}
	interfaceName, subnet, err := m.resolver.Resolve(localIP, clientIP)
	if err != nil {
		return Proof{}, err
	}
	adminURL := "http://" + net.JoinHostPort(localIP.String(), "80") + "/"
	return m.Issue(ctx, binding, Observation{
		Mode: ModeHeadless, ClientIP: clientIP, LocalIP: localIP, Interface: interfaceName, Subnet: subnet,
		ControlPlaneURL: "http://127.0.0.1:8787/api/v1/health", AdminHTTPURL: adminURL, AdminHTTPAvailable: m.adminProbe(ctx, adminURL),
	}, ttl)
}

func (m *Manager) IssueAutomatic(ctx context.Context, binding Binding, ttl time.Duration) (Proof, error) {
	topology, err := m.automaticSource.Snapshot(ctx)
	if err != nil {
		return Proof{}, err
	}
	observation, err := selectAutomaticObservation(topology)
	if err != nil {
		return Proof{}, err
	}
	adminURL := "http://" + net.JoinHostPort(observation.LocalIP.String(), "80") + "/"
	observation.Mode = ModeAutomatic
	observation.ControlPlaneURL = "http://" + net.JoinHostPort(observation.LocalIP.String(), "8787") + "/api/v1/health"
	observation.AdminHTTPURL = adminURL
	observation.AdminHTTPAvailable = m.adminProbe(ctx, adminURL)
	return m.Issue(ctx, binding, observation, ttl)
}

func selectAutomaticObservation(topology AutomaticTopology) (Observation, error) {
	defaultInterfaces := make(map[string]bool, len(topology.DefaultRouteInterfaces))
	for _, name := range topology.DefaultRouteInterfaces {
		defaultInterfaces[name] = true
	}
	interfaces := append([]AutomaticInterface(nil), topology.Interfaces...)
	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i].Name < interfaces[j].Name })
	for _, iface := range interfaces {
		if !iface.Up || iface.Loopback || defaultInterfaces[iface.Name] || !interfacePattern.MatchString(iface.Name) {
			continue
		}
		prefixes := append([]netip.Prefix(nil), iface.Prefixes...)
		sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].String() < prefixes[j].String() })
		for _, rawPrefix := range prefixes {
			localIP := rawPrefix.Addr().Unmap()
			if !usableManagementAddress(localIP) {
				continue
			}
			prefix := netip.PrefixFrom(localIP, rawPrefix.Bits()).Masked()
			for _, neighbor := range topology.Neighbors {
				clientIP := neighbor.IP.Unmap()
				if neighbor.Interface != iface.Name || !neighbor.Reachable || clientIP == localIP || !usableManagementAddress(clientIP) || !prefix.Contains(clientIP) {
					continue
				}
				return Observation{ClientIP: clientIP, LocalIP: localIP, Interface: iface.Name, Subnet: prefix}, nil
			}
		}
	}
	return Observation{}, fmt.Errorf("no active management interface with a reachable client is available for automatic proof")
}

func usableManagementAddress(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast()
}

func (systemAutomaticTopologySource) Snapshot(ctx context.Context) (AutomaticTopology, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return AutomaticTopology{}, err
	}
	topology := AutomaticTopology{}
	for _, iface := range interfaces {
		item := AutomaticInterface{Name: iface.Name, Up: iface.Flags&net.FlagUp != 0, Loopback: iface.Flags&net.FlagLoopback != 0}
		addrs, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		for _, raw := range addrs {
			if prefix, parseErr := netip.ParsePrefix(raw.String()); parseErr == nil {
				item.Prefixes = append(item.Prefixes, prefix)
			}
		}
		topology.Interfaces = append(topology.Interfaces, item)
	}
	for _, familyArgs := range [][]string{{"-j", "route", "show", "default"}, {"-j", "-6", "route", "show", "default"}} {
		raw, runErr := exec.CommandContext(ctx, "/sbin/ip", familyArgs...).Output()
		if runErr != nil {
			return AutomaticTopology{}, fmt.Errorf("read default routes: %w", runErr)
		}
		var routes []struct {
			Dev string `json:"dev"`
		}
		if err := json.Unmarshal(raw, &routes); err != nil {
			return AutomaticTopology{}, fmt.Errorf("parse default routes: %w", err)
		}
		for _, route := range routes {
			if interfacePattern.MatchString(route.Dev) {
				topology.DefaultRouteInterfaces = append(topology.DefaultRouteInterfaces, route.Dev)
			}
		}
	}
	raw, err := exec.CommandContext(ctx, "/sbin/ip", "-j", "neigh", "show").Output()
	if err != nil {
		return AutomaticTopology{}, fmt.Errorf("read neighbors: %w", err)
	}
	var neighbors []struct {
		Dst   string   `json:"dst"`
		Dev   string   `json:"dev"`
		State []string `json:"state"`
	}
	if err := json.Unmarshal(raw, &neighbors); err != nil {
		return AutomaticTopology{}, fmt.Errorf("parse neighbors: %w", err)
	}
	for _, neighbor := range neighbors {
		ip, parseErr := netip.ParseAddr(neighbor.Dst)
		if parseErr != nil || !interfacePattern.MatchString(neighbor.Dev) {
			continue
		}
		reachable := len(neighbor.State) > 0
		for _, state := range neighbor.State {
			if state == "FAILED" || state == "INCOMPLETE" || state == "NONE" {
				reachable = false
			}
		}
		topology.Neighbors = append(topology.Neighbors, AutomaticNeighbor{Interface: neighbor.Dev, IP: ip, Reachable: reachable})
	}
	return topology, nil
}

func (m *Manager) Verify(binding Binding) (Proof, error) {
	path, err := m.ProofPath(binding)
	if err != nil {
		return Proof{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Proof{}, fmt.Errorf("management proof is missing")
		}
		return Proof{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return Proof{}, fmt.Errorf("management proof is not a regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Proof{}, err
	}
	if len(raw) > 16*1024 {
		return Proof{}, fmt.Errorf("management proof exceeds size limit")
	}
	var proof Proof
	if err := json.Unmarshal(raw, &proof); err != nil {
		return Proof{}, fmt.Errorf("management proof is invalid JSON: %w", err)
	}
	if proof.SchemaVersion != SchemaVersion || proof.TransactionID != binding.TransactionID || proof.RevisionID != binding.RevisionID {
		return Proof{}, fmt.Errorf("management proof binding does not match the transaction")
	}
	key, err := m.readKey()
	if err != nil {
		return Proof{}, err
	}
	expected, err := signProof(key, proof)
	if err != nil {
		return Proof{}, err
	}
	provided, err := hex.DecodeString(proof.Signature)
	if err != nil || !hmac.Equal(provided, mustDecodeHex(expected)) {
		return Proof{}, fmt.Errorf("management proof signature is invalid")
	}
	bootID, err := readBootID(m.bootIDPath)
	if err != nil {
		return Proof{}, err
	}
	if proof.BootID != bootID {
		return Proof{}, fmt.Errorf("management proof belongs to another boot")
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, proof.IssuedAt)
	if err != nil {
		return Proof{}, fmt.Errorf("management proof issued_at is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, proof.ExpiresAt)
	if err != nil {
		return Proof{}, fmt.Errorf("management proof expires_at is invalid")
	}
	now := m.now().UTC()
	if expiresAt.Sub(issuedAt) <= 0 || expiresAt.Sub(issuedAt) > maxProofTTL || now.Before(issuedAt.Add(-5*time.Second)) {
		return Proof{}, fmt.Errorf("management proof time bounds are invalid")
	}
	if !now.Before(expiresAt) {
		return Proof{}, fmt.Errorf("management proof has expired")
	}
	if _, err := observationFromProof(proof); err != nil {
		return Proof{}, err
	}
	return proof, nil
}

func (m *Manager) VerifyLANConfirmation(binding Binding, request *http.Request) (Proof, error) {
	proof, err := m.Verify(binding)
	if err != nil {
		return Proof{}, err
	}
	if proof.Mode != ModeLAN {
		return Proof{}, fmt.Errorf("management proof is not a LAN proof")
	}
	current, err := m.ObserveLANRequest(request.Context(), request)
	if err != nil {
		return Proof{}, err
	}
	if current.Interface != proof.Interface || current.Subnet.Masked().String() != proof.Subnet || current.LocalIP.String() != proof.LocalIP {
		return Proof{}, fmt.Errorf("confirmation arrived through another management interface or subnet")
	}
	prefix, _ := netip.ParsePrefix(proof.Subnet)
	if !prefix.Contains(current.ClientIP) {
		return Proof{}, fmt.Errorf("confirmation client is outside the proved management subnet")
	}
	return proof, nil
}

func (m *Manager) ProbeAdminHTTP(ctx context.Context, proof Proof) bool {
	if !proof.AdminHTTPAvailable {
		return true
	}
	observation, err := observationFromProof(proof)
	if err != nil || observation.AdminHTTPURL == "" {
		return false
	}
	return m.adminProbe(ctx, observation.AdminHTTPURL)
}

func (m *Manager) Remove(binding Binding) error {
	path, err := m.ProofPath(binding)
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func observationFromProof(proof Proof) (Observation, error) {
	clientIP, err := netip.ParseAddr(proof.ClientIP)
	if err != nil {
		return Observation{}, fmt.Errorf("management proof client IP is invalid")
	}
	localIP, err := netip.ParseAddr(proof.LocalIP)
	if err != nil {
		return Observation{}, fmt.Errorf("management proof local IP is invalid")
	}
	subnet, err := netip.ParsePrefix(proof.Subnet)
	if err != nil {
		return Observation{}, fmt.Errorf("management proof subnet is invalid")
	}
	observation := Observation{Mode: proof.Mode, ClientIP: clientIP, LocalIP: localIP, Interface: proof.Interface, Subnet: subnet, ControlPlaneURL: proof.ControlPlaneURL, AdminHTTPURL: proof.AdminHTTPURL, AdminHTTPAvailable: proof.AdminHTTPAvailable}
	if err := validateObservation(observation); err != nil {
		return Observation{}, fmt.Errorf("management proof observation is invalid: %w", err)
	}
	return observation, nil
}

func validateBinding(binding Binding) error {
	if !transactionPattern.MatchString(binding.TransactionID) || !revisionPattern.MatchString(binding.RevisionID) {
		return fmt.Errorf("management proof transaction or revision failed validation")
	}
	return nil
}

func validateObservation(observation Observation) error {
	if observation.Mode != ModeLAN && observation.Mode != ModeHeadless && observation.Mode != ModeAutomatic {
		return fmt.Errorf("unsupported management proof mode")
	}
	if !observation.ClientIP.IsValid() || !observation.LocalIP.IsValid() || observation.ClientIP.IsUnspecified() || observation.LocalIP.IsUnspecified() {
		return fmt.Errorf("management proof IP addresses are required")
	}
	if !interfacePattern.MatchString(observation.Interface) || !observation.Subnet.IsValid() || !observation.Subnet.Contains(observation.ClientIP) || !observation.Subnet.Contains(observation.LocalIP) {
		return fmt.Errorf("management interface and subnet do not contain the observed path")
	}
	if err := validateManagementURL(observation.ControlPlaneURL, observation.LocalIP, true); err != nil {
		return err
	}
	if observation.AdminHTTPURL != "" {
		if err := validateManagementURL(observation.AdminHTTPURL, observation.LocalIP, false); err != nil {
			return err
		}
	}
	return nil
}

func validateManagementURL(raw string, localIP netip.Addr, allowLoopback bool) error {
	request, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil || request.URL.Scheme != "http" || request.URL.User != nil || request.URL.Hostname() == "" {
		return fmt.Errorf("management proof URL is invalid")
	}
	hostIP, err := netip.ParseAddr(request.URL.Hostname())
	if err != nil {
		return fmt.Errorf("management proof URL must use a literal IP")
	}
	if hostIP.Unmap() != localIP.Unmap() && !(allowLoopback && hostIP.IsLoopback()) {
		return fmt.Errorf("management proof URL is not bound to the observed local address")
	}
	return nil
}

func signProof(key []byte, proof Proof) (string, error) {
	proof.Signature = ""
	raw, err := json.Marshal(proof)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func mustDecodeHex(value string) []byte {
	raw, _ := hex.DecodeString(value)
	return raw
}

func readBootID(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read boot ID: %w", err)
	}
	bootID := strings.TrimSpace(string(raw))
	if len(bootID) < 8 || len(bootID) > 128 || strings.ContainsAny(bootID, "\r\n\t ") {
		return "", fmt.Errorf("boot ID is invalid")
	}
	return bootID, nil
}

func (m *Manager) loadOrCreateKey() ([]byte, error) {
	key, err := m.readKey()
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate management proof key: %w", err)
	}
	if err := writeKeyExclusive(m.keyPath, key); err != nil {
		if errors.Is(err, os.ErrExist) {
			for attempt := 0; attempt < 10; attempt++ {
				if existing, readErr := m.readKey(); readErr == nil {
					return existing, nil
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		return nil, err
	}
	return key, nil
}

func writeKeyExclusive(path string, key []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(key); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func (m *Manager) readKey() ([]byte, error) {
	info, err := os.Lstat(m.keyPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("management proof key is not a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("management proof key permissions must be 0600")
	}
	key, err := os.ReadFile(m.keyPath)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("management proof key length is invalid")
	}
	return key, nil
}

func writeJSONAtomic(path string, value any, mode os.FileMode) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writeFileAtomic(path, raw, mode)
}

func writeFileAtomic(path string, raw []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return fmt.Errorf("refusing non-regular management proof target")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func splitAddress(raw string) (netip.Addr, string, error) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return netip.Addr{}, "", err
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}, "", err
	}
	if port == "" {
		return netip.Addr{}, "", fmt.Errorf("port is missing")
	}
	return ip.Unmap(), port, nil
}

func probeAdminHTTP(ctx context.Context, rawURL string) bool {
	probeCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false
	}
	client := &http.Client{
		Timeout:       time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	_ = response.Body.Close()
	return true
}
