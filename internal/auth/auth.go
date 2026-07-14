package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"router-policy/internal/config"
)

const (
	RoleAdministrator = "administrator"
	RoleDiagnostician = "diagnostician"
	RoleViewer        = "viewer"
)

const (
	defaultSessionTTL         = 12 * time.Hour
	maxSessionsTotal          = 64
	maxSessionsPerUser        = 8
	maxLoginFailures          = 12
	setupTokenTTL             = 30 * time.Minute
	setupTokenMaxUses         = 1
	minPasswordLen            = 12
	argonMemoryKB      uint32 = 16 * 1024
	argonTime          uint32 = 1
	argonThreads       uint8  = 1
	argonKeyLen               = 32
	maxArgonMemoryKB   uint32 = 64 * 1024
	maxArgonTime       uint32 = 4
	maxArgonThreads    uint8  = 2
	maxArgonKeyLen            = 64
)

var ErrSetupRequired = errors.New("setup required")
var ErrSetupUnavailable = errors.New("setup unavailable")
var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrRateLimited = errors.New("rate limited")
var ErrWeakPassword = errors.New("weak password")
var ErrRoleDenied = errors.New("role denied")

var argonSlots = make(chan struct{}, 2)

type Store struct {
	mu          sync.Mutex
	usersPath   string
	setupPath   string
	sessions    map[string]Session
	failures    map[string]loginFailure
	dummyHash   string
	sessionTTL  time.Duration
	maxSessions int
	perUserMax  int
}

type User struct {
	Username           string    `json:"username"`
	Role               string    `json:"role"`
	PasswordHash       string    `json:"password_hash"`
	MustChangePassword bool      `json:"must_change_password"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type Session struct {
	ID        string    `json:"-"`
	User      string    `json:"user"`
	Role      string    `json:"role"`
	CSRFToken string    `json:"csrf_token"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"-"`
}

type PublicSession struct {
	User               string    `json:"user"`
	Role               string    `json:"role"`
	CSRFToken          string    `json:"csrf_token"`
	ExpiresAt          time.Time `json:"expires_at"`
	MustChangePassword bool      `json:"must_change_password"`
}

type SetupToken struct {
	TokenHash string    `json:"token_hash"`
	ExpiresAt time.Time `json:"expires_at"`
	UsesLeft  int       `json:"uses_left"`
	CreatedAt time.Time `json:"created_at"`
}

type loginFailure struct {
	Count     int
	NextTry   time.Time
	UpdatedAt time.Time
}

type LoginAudit struct {
	Username string
	Remote   string
	Success  bool
	Reason   string
}

func Open(cfg *config.Config) (*Store, error) {
	dir := filepath.Join(cfg.Storage.StateDir, "auth")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	dummy, err := hashPassword("router-policy-dummy-password")
	if err != nil {
		return nil, err
	}
	return &Store{
		usersPath:   filepath.Join(dir, "users.json"),
		setupPath:   filepath.Join(dir, "setup-token.json"),
		sessions:    map[string]Session{},
		failures:    map[string]loginFailure{},
		dummyHash:   dummy,
		sessionTTL:  defaultSessionTTL,
		maxSessions: maxSessionsTotal,
		perUserMax:  maxSessionsPerUser,
	}, nil
}

func (s *Store) HasUsers() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	users, err := s.loadUsersLocked()
	return err == nil && len(users) > 0
}

func (s *Store) CreateSetupToken() (string, SetupToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	users, err := s.loadUsersLocked()
	if err != nil {
		return "", SetupToken{}, err
	}
	if len(users) > 0 {
		return "", SetupToken{}, ErrSetupUnavailable
	}
	token := randomHex(32)
	st := SetupToken{
		TokenHash: hashToken(token),
		ExpiresAt: time.Now().UTC().Add(setupTokenTTL),
		UsesLeft:  setupTokenMaxUses,
		CreatedAt: time.Now().UTC(),
	}
	if err := writeJSON0600(s.setupPath, st); err != nil {
		return "", SetupToken{}, err
	}
	return token, st, nil
}

func (s *Store) SetupAdmin(username, password, token string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	users, err := s.loadUsersLocked()
	if err != nil {
		return User{}, err
	}
	if len(users) > 0 {
		return User{}, ErrSetupUnavailable
	}
	st, err := s.loadSetupTokenLocked()
	if err != nil {
		return User{}, ErrSetupRequired
	}
	if time.Now().UTC().After(st.ExpiresAt) || st.UsesLeft <= 0 {
		return User{}, ErrSetupRequired
	}
	if subtle.ConstantTimeCompare([]byte(hashToken(token)), []byte(st.TokenHash)) != 1 {
		return User{}, ErrInvalidCredentials
	}
	if err := validateUsername(username); err != nil {
		return User{}, err
	}
	if err := validatePassword(password); err != nil {
		return User{}, err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return User{}, err
	}
	now := time.Now().UTC()
	user := User{Username: username, Role: RoleAdministrator, PasswordHash: hash, CreatedAt: now, UpdatedAt: now}
	users[user.Username] = user
	if err := s.saveUsersLocked(users); err != nil {
		return User{}, err
	}
	_ = os.Remove(s.setupPath)
	return user, nil
}

func (s *Store) Login(username, password, remote string) (Session, LoginAudit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(time.Now().UTC())
	audit := LoginAudit{Username: username, Remote: remote}
	if err := s.checkRateLocked(username, remote); err != nil {
		audit.Reason = "rate_limited"
		return Session{}, audit, err
	}
	users, err := s.loadUsersLocked()
	if err != nil {
		audit.Reason = "store_error"
		return Session{}, audit, err
	}
	if len(users) == 0 {
		_, _ = verifyPassword(password, s.dummyHash)
		audit.Reason = "setup_required"
		return Session{}, audit, ErrSetupRequired
	}
	user, ok := users[username]
	hash := s.dummyHash
	if ok {
		hash = user.PasswordHash
	}
	valid, _ := verifyPassword(password, hash)
	if !ok || !valid {
		s.recordFailureLocked(username, remote)
		audit.Reason = "bad_credentials"
		return Session{}, audit, ErrInvalidCredentials
	}
	s.clearFailureLocked(username, remote)
	s.enforceUserSessionLimitLocked(username)
	if len(s.sessions) >= s.maxSessions {
		s.dropOldestSessionLocked()
	}
	session := Session{ID: randomHex(32), User: user.Username, Role: user.Role, CSRFToken: randomHex(32), ExpiresAt: time.Now().UTC().Add(s.sessionTTL)}
	s.sessions[session.ID] = session
	audit.Success = true
	audit.Reason = "login_success"
	return session, audit, nil
}

func (s *Store) Public(session Session) PublicSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	users, _ := s.loadUsersLocked()
	user := users[session.User]
	return PublicSession{
		User:               session.User,
		Role:               session.Role,
		CSRFToken:          session.CSRFToken,
		ExpiresAt:          session.ExpiresAt,
		MustChangePassword: user.MustChangePassword,
	}
}

func (s *Store) Session(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	s.cleanupLocked(now)
	session, ok := s.sessions[id]
	if !ok || session.Revoked || now.After(session.ExpiresAt) {
		return Session{}, false
	}
	return session, true
}

func (s *Store) Logout(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

func (s *Store) RevokeUser(username string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for id, session := range s.sessions {
		if session.User == username {
			delete(s.sessions, id)
			count++
		}
	}
	return count
}

func RoleAllows(actual, required string) bool {
	return roleRank(actual) >= roleRank(required)
}

func roleRank(role string) int {
	switch role {
	case RoleAdministrator:
		return 3
	case RoleDiagnostician:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

func RemoteKey(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func (s *Store) checkRateLocked(username, remote string) error {
	f := s.failures[username+"|"+RemoteKey(remote)]
	if f.Count >= maxLoginFailures {
		return ErrRateLimited
	}
	if !f.NextTry.IsZero() && time.Now().UTC().Before(f.NextTry) {
		return ErrRateLimited
	}
	return nil
}

func (s *Store) recordFailureLocked(username, remote string) {
	key := username + "|" + RemoteKey(remote)
	f := s.failures[key]
	f.Count++
	delay := time.Duration(1<<min(f.Count, 5)) * time.Second
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	f.NextTry = time.Now().UTC().Add(delay)
	f.UpdatedAt = time.Now().UTC()
	s.failures[key] = f
}

func (s *Store) clearFailureLocked(username, remote string) {
	delete(s.failures, username+"|"+RemoteKey(remote))
}

func (s *Store) cleanupLocked(now time.Time) {
	for id, session := range s.sessions {
		if session.Revoked || now.After(session.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
	for key, failure := range s.failures {
		if now.Sub(failure.UpdatedAt) > time.Hour {
			delete(s.failures, key)
		}
	}
}

func (s *Store) enforceUserSessionLimitLocked(username string) {
	var ids []string
	for id, session := range s.sessions {
		if session.User == username {
			ids = append(ids, id)
		}
	}
	for len(ids) >= s.perUserMax {
		oldest := ids[0]
		for _, id := range ids[1:] {
			if s.sessions[id].ExpiresAt.Before(s.sessions[oldest].ExpiresAt) {
				oldest = id
			}
		}
		delete(s.sessions, oldest)
		ids = ids[:0]
		for id, session := range s.sessions {
			if session.User == username {
				ids = append(ids, id)
			}
		}
	}
}

func (s *Store) dropOldestSessionLocked() {
	var oldest string
	for id, session := range s.sessions {
		if oldest == "" || session.ExpiresAt.Before(s.sessions[oldest].ExpiresAt) {
			oldest = id
		}
	}
	if oldest != "" {
		delete(s.sessions, oldest)
	}
}

func (s *Store) loadUsersLocked() (map[string]User, error) {
	users := map[string]User{}
	b, err := os.ReadFile(s.usersPath)
	if errors.Is(err, os.ErrNotExist) {
		return users, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &users); err != nil {
		return nil, err
	}
	return users, nil
}

func (s *Store) saveUsersLocked(users map[string]User) error {
	return writeJSON0600(s.usersPath, users)
}

func (s *Store) loadSetupTokenLocked() (SetupToken, error) {
	var st SetupToken
	b, err := os.ReadFile(s.setupPath)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, err
	}
	return st, nil
}

func validateUsername(username string) error {
	if username == "" || len(username) > 64 {
		return fmt.Errorf("invalid username")
	}
	for _, r := range username {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return fmt.Errorf("invalid username")
		}
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < minPasswordLen {
		return ErrWeakPassword
	}
	low := strings.ToLower(password)
	weak := []string{"password", "123456", "qwerty", "admin", "router", "letmein", "changeme"}
	for _, item := range weak {
		if low == item || strings.Contains(low, item) {
			return ErrWeakPassword
		}
	}
	return nil
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	release := acquireArgonSlot()
	defer release()
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKB, argonThreads, argonKeyLen)
	return fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemoryKB, argonTime, argonThreads, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func verifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" || parts[1] != "v=19" {
		return false, fmt.Errorf("unsupported password hash")
	}
	var memory uint32
	var iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return false, err
	}
	if memory == 0 || memory > maxArgonMemoryKB || iterations == 0 || iterations > maxArgonTime || threads == 0 || threads > maxArgonThreads {
		return false, fmt.Errorf("password hash parameters exceed configured limits")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, err
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	if len(expected) == 0 || len(expected) > maxArgonKeyLen {
		return false, fmt.Errorf("password hash key length exceeds configured limits")
	}
	release := acquireArgonSlot()
	defer release()
	key := argon2.IDKey([]byte(password), salt, iterations, memory, threads, uint32(len(expected)))
	return subtle.ConstantTimeCompare(key, expected) == 1, nil
}

func hashToken(token string) string {
	sum := argon2.IDKey([]byte(token), []byte("router-policy-setup-token"), 1, 4*1024, 1, 32)
	return base64.RawStdEncoding.EncodeToString(sum)
}

func writeJSON0600(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp." + randomHex(6)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Chmod(path, 0o600)
	return syncDir(filepath.Dir(path))
}

func acquireArgonSlot() func() {
	argonSlots <- struct{}{}
	return func() { <-argonSlots }
}

func syncDir(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
