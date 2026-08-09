package telegramnotify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	StateNotConfigured = "not_configured"
	StateConfigured    = "configured"
	StateVerified      = "verified"
	StateDegraded      = "degraded"
	StateFailed        = "failed"
)

var SupportedEventTypes = []string{
	"apply_succeeded",
	"rollback",
	"route_loss",
	"recovery",
	"auto_apply_blocked",
	"storage_critical",
}

type SecretConfig struct {
	SchemaVersion int      `json:"schema_version"`
	BotToken      string   `json:"bot_token"`
	ChatID        string   `json:"chat_id"`
	Enabled       bool     `json:"enabled"`
	EventTypes    []string `json:"event_types"`
}

type Status struct {
	State               string    `json:"state"`
	Enabled             bool      `json:"enabled"`
	TokenConfigured     bool      `json:"token_configured"`
	ChatConfigured      bool      `json:"chat_configured"`
	EventTypes          []string  `json:"event_types"`
	QueueDepth          int       `json:"queue_depth"`
	QueueCapacity       int       `json:"queue_capacity"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	LastErrorCode       string    `json:"last_error_code,omitempty"`
	LastVerifiedAt      time.Time `json:"last_verified_at,omitempty"`
	LastDeliveryAt      time.Time `json:"last_delivery_at,omitempty"`
	Dropped             uint64    `json:"dropped"`
}

type Notification struct {
	Type string
	Text string
}

type Options struct {
	SecretFile  string
	Client      *http.Client
	APIBaseURL  string
	QueueSize   int
	MaxRetries  int
	RetryBase   time.Duration
	MinInterval time.Duration
	DedupeFor   time.Duration
	Now         func() time.Time
}

type Manager struct {
	secretFile  string
	client      *http.Client
	apiBaseURL  string
	maxRetries  int
	retryBase   time.Duration
	minInterval time.Duration
	dedupeFor   time.Duration
	now         func() time.Time

	mu                  sync.Mutex
	config              SecretConfig
	state               string
	consecutiveFailures int
	lastErrorCode       string
	lastVerifiedAt      time.Time
	lastDeliveryAt      time.Time
	lastAttemptAt       time.Time
	dedupe              map[string]time.Time
	dropped             uint64
	queue               chan Notification
	stop                chan struct{}
	done                chan struct{}
	closeOnce           sync.Once
}

func New(options Options) (*Manager, error) {
	if !filepath.IsAbs(options.SecretFile) && !strings.HasPrefix(filepath.ToSlash(options.SecretFile), "/") {
		return nil, errors.New("telegram secret file must be absolute")
	}
	if options.Client == nil {
		options.Client = &http.Client{Timeout: 5 * time.Second}
	}
	if options.APIBaseURL == "" {
		options.APIBaseURL = "https://api.telegram.org"
	}
	if options.QueueSize <= 0 {
		options.QueueSize = 64
	}
	if options.MaxRetries <= 0 {
		options.MaxRetries = 3
	}
	if options.RetryBase <= 0 {
		options.RetryBase = 250 * time.Millisecond
	}
	if options.MinInterval <= 0 {
		options.MinInterval = time.Second
	}
	if options.DedupeFor <= 0 {
		options.DedupeFor = time.Hour
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}
	m := &Manager{
		secretFile: options.SecretFile, client: options.Client,
		apiBaseURL: strings.TrimRight(options.APIBaseURL, "/"), maxRetries: options.MaxRetries,
		retryBase: options.RetryBase, minInterval: options.MinInterval, dedupeFor: options.DedupeFor,
		now: options.Now, state: StateNotConfigured, dedupe: map[string]time.Time{},
		queue: make(chan Notification, options.QueueSize), stop: make(chan struct{}), done: make(chan struct{}),
	}
	loaded, err := loadSecret(options.SecretFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		m.state = StateFailed
		m.lastErrorCode = "secret_read_failed"
	} else if err == nil {
		m.config = loaded
		m.state = StateConfigured
	}
	go m.run()
	if err == nil && loaded.Enabled {
		go m.reverifyLoaded()
	}
	return m, nil
}

func (m *Manager) Close() {
	m.closeOnce.Do(func() {
		close(m.stop)
		<-m.done
	})
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Status{
		State: m.state, Enabled: m.config.Enabled,
		TokenConfigured: m.config.BotToken != "", ChatConfigured: m.config.ChatID != "",
		EventTypes: append([]string{}, m.config.EventTypes...), QueueDepth: len(m.queue), QueueCapacity: cap(m.queue),
		ConsecutiveFailures: m.consecutiveFailures, LastErrorCode: m.lastErrorCode,
		LastVerifiedAt: m.lastVerifiedAt, LastDeliveryAt: m.lastDeliveryAt, Dropped: m.dropped,
	}
}

func (m *Manager) Configure(ctx context.Context, token, chatID string, enabled bool, eventTypes []string) (Status, error) {
	m.mu.Lock()
	current := m.config
	m.mu.Unlock()
	if strings.TrimSpace(token) == "" {
		token = current.BotToken
	}
	if strings.TrimSpace(chatID) == "" {
		chatID = current.ChatID
	}
	eventTypes, err := normalizeEventTypes(eventTypes)
	if err != nil {
		return m.Status(), err
	}
	next := SecretConfig{SchemaVersion: 1, BotToken: strings.TrimSpace(token), ChatID: strings.TrimSpace(chatID), Enabled: enabled, EventTypes: eventTypes}
	if next.BotToken == "" || next.ChatID == "" {
		return m.Status(), errors.New("bot token and chat ID are required")
	}
	if err := validateTokenShape(next.BotToken); err != nil {
		return m.Status(), err
	}
	if enabled {
		if err := m.verify(ctx, next); err != nil {
			m.recordFailure("verification_failed")
			return m.Status(), err
		}
	}
	if err := storeSecret(m.secretFile, next); err != nil {
		m.recordFailure("secret_write_failed")
		return m.Status(), errors.New("telegram settings could not be stored")
	}
	m.mu.Lock()
	m.config = next
	m.consecutiveFailures = 0
	m.lastErrorCode = ""
	if enabled {
		m.state = StateVerified
		m.lastVerifiedAt = m.now()
	} else {
		m.state = StateConfigured
	}
	m.mu.Unlock()
	return m.Status(), nil
}

func (m *Manager) SendTest(ctx context.Context) error {
	m.mu.Lock()
	cfg := m.config
	m.mu.Unlock()
	if !cfg.Enabled || cfg.BotToken == "" || cfg.ChatID == "" {
		return errors.New("telegram notifications are not enabled")
	}
	if err := m.sendWithRetry(ctx, cfg, "FlintRoute: test notification delivered."); err != nil {
		m.recordTerminalFailure("test_delivery_failed")
		return err
	}
	m.recordSuccess()
	return nil
}

func (m *Manager) Enqueue(notification Notification) bool {
	if !supportedType(notification.Type) || strings.TrimSpace(notification.Text) == "" {
		return false
	}
	m.mu.Lock()
	if !m.config.Enabled || !contains(m.config.EventTypes, notification.Type) {
		m.mu.Unlock()
		return false
	}
	key := notification.Type + "\x00" + notification.Text
	now := m.now()
	if seen := m.dedupe[key]; !seen.IsZero() && now.Sub(seen) < m.dedupeFor {
		m.mu.Unlock()
		return false
	}
	m.dedupe[key] = now
	for existing, at := range m.dedupe {
		if now.Sub(at) >= m.dedupeFor {
			delete(m.dedupe, existing)
		}
	}
	m.mu.Unlock()
	select {
	case m.queue <- notification:
		return true
	default:
		m.mu.Lock()
		m.dropped++
		m.state = StateDegraded
		m.lastErrorCode = "queue_full"
		m.mu.Unlock()
		return false
	}
}

func (m *Manager) run() {
	defer close(m.done)
	for {
		select {
		case <-m.stop:
			return
		case notification := <-m.queue:
			m.mu.Lock()
			cfg := m.config
			m.mu.Unlock()
			if !cfg.Enabled || !contains(cfg.EventTypes, notification.Type) {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			err := m.sendWithRetry(ctx, cfg, notification.Text)
			cancel()
			if err != nil {
				m.recordTerminalFailure("delivery_failed")
			} else {
				m.recordSuccess()
			}
		}
	}
}

func (m *Manager) reverifyLoaded() {
	m.mu.Lock()
	cfg := m.config
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if err := m.verify(ctx, cfg); err != nil {
		m.recordFailure("startup_verification_failed")
		return
	}
	m.recordVerified()
}

func (m *Manager) verify(ctx context.Context, cfg SecretConfig) error {
	if err := m.call(ctx, cfg.BotToken, "getMe", nil); err != nil {
		return errors.New("Telegram bot token verification failed")
	}
	if err := m.call(ctx, cfg.BotToken, "getChat", map[string]string{"chat_id": cfg.ChatID}); err != nil {
		return errors.New("Telegram chat access verification failed")
	}
	return nil
}

func (m *Manager) sendWithRetry(ctx context.Context, cfg SecretConfig, text string) error {
	if !cfg.Enabled || cfg.BotToken == "" || cfg.ChatID == "" {
		return errors.New("Telegram delivery is not configured")
	}
	var err error
	for attempt := 0; attempt < m.maxRetries; attempt++ {
		if wait := m.rateDelay(); wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return errors.New("Telegram delivery timed out")
			case <-timer.C:
			}
		}
		err = m.call(ctx, cfg.BotToken, "sendMessage", map[string]string{"chat_id": cfg.ChatID, "text": text, "disable_web_page_preview": "true"})
		if err == nil {
			return nil
		}
		if attempt+1 < m.maxRetries {
			delay := m.retryBase << attempt
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return errors.New("Telegram delivery timed out")
			case <-timer.C:
			}
		}
	}
	return err
}

func (m *Manager) rateDelay() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	wait := m.minInterval - now.Sub(m.lastAttemptAt)
	if m.lastAttemptAt.IsZero() || wait < 0 {
		wait = 0
	}
	m.lastAttemptAt = now.Add(wait)
	return wait
}

func (m *Manager) call(ctx context.Context, token, method string, fields map[string]string) error {
	values := make(map[string]string, len(fields))
	for key, value := range fields {
		values[key] = value
	}
	body, err := json.Marshal(values)
	if err != nil {
		return errors.New("Telegram request encoding failed")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, m.apiBaseURL+"/bot"+token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return errors.New("Telegram request creation failed")
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := m.client.Do(request)
	if err != nil {
		return errors.New("Telegram API request failed")
	}
	defer response.Body.Close()
	limited, err := io.ReadAll(io.LimitReader(response.Body, 32<<10))
	if err != nil {
		return errors.New("Telegram API response failed")
	}
	var envelope struct {
		OK bool `json:"ok"`
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || json.Unmarshal(limited, &envelope) != nil || !envelope.OK {
		return fmt.Errorf("Telegram API rejected %s", method)
	}
	return nil
}

func (m *Manager) recordFailure(code string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.consecutiveFailures++
	m.lastErrorCode = code
	if m.consecutiveFailures >= m.maxRetries {
		m.state = StateFailed
	} else {
		m.state = StateDegraded
	}
}

func (m *Manager) recordTerminalFailure(code string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.consecutiveFailures = m.maxRetries
	m.lastErrorCode = code
	m.state = StateFailed
}

func (m *Manager) recordVerified() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = StateVerified
	m.consecutiveFailures = 0
	m.lastErrorCode = ""
	m.lastVerifiedAt = m.now()
}

func (m *Manager) recordSuccess() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = StateVerified
	m.consecutiveFailures = 0
	m.lastErrorCode = ""
	m.lastDeliveryAt = m.now()
}

func validateTokenShape(token string) error {
	parts := strings.Split(token, ":")
	if len(parts) != 2 || len(parts[0]) < 5 || len(parts[1]) < 20 {
		return errors.New("invalid Telegram bot token format")
	}
	if _, err := strconv.ParseInt(parts[0], 10, 64); err != nil {
		return errors.New("invalid Telegram bot token format")
	}
	return nil
}

func normalizeEventTypes(values []string) ([]string, error) {
	if len(values) == 0 {
		values = append([]string(nil), SupportedEventTypes...)
	}
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if !supportedType(value) {
			return nil, errors.New("unsupported Telegram notification type")
		}
		seen[value] = true
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func supportedType(value string) bool { return contains(SupportedEventTypes, value) }
func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func loadSecret(path string) (SecretConfig, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return SecretConfig{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 64<<10 || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return SecretConfig{}, errors.New("telegram secret file is unsafe")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return SecretConfig{}, err
	}
	var cfg SecretConfig
	if err := json.Unmarshal(raw, &cfg); err != nil || cfg.SchemaVersion != 1 || validateTokenShape(cfg.BotToken) != nil || strings.TrimSpace(cfg.ChatID) == "" {
		return SecretConfig{}, errors.New("telegram secret file is invalid")
	}
	cfg.EventTypes, err = normalizeEventTypes(cfg.EventTypes)
	return cfg, err
}

func storeSecret(path string, cfg SecretConfig) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("telegram secret target is unsafe")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(parent, ".telegram-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	ok := false
	defer func() {
		_ = temporary.Close()
		if !ok {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(append(raw, '\n')); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	ok = true
	return nil
}
