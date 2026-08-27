package vpnsub

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/url"
	"os"
	"strings"
	"unicode/utf8"
)

// SourceType describes the syntax of a user-provided subscription source.
// It is deliberately separate from the protocol used to fetch the resolved
// source: a Happ URI is not itself an HTTP endpoint.
type SourceType string

const (
	SourceTypeHTTP  SourceType = "http"
	SourceTypeHTTPS SourceType = "https"
	SourceTypeHapp  SourceType = "happ"
)

// SourceInfo is the safe, parsed description of an original source. Payload
// is retained only in memory and is never included in diagnostics or JSON.
type SourceInfo struct {
	Canonical     string
	Type          SourceType
	CryptoVersion string
	Payload       string
	// WrappedSource is set when a HTTPS provider portal carries a Happ source
	// in a dedicated query parameter (for example /add-key?subkey=...). The
	// wrapper remains Canonical/OriginalSource; only the nested source is sent
	// through the selected decoder.
	WrappedSource string
}

type SourceDescription struct {
	SourceMasked  string `json:"source_masked"`
	SourceType    string `json:"source_type"`
	CryptoVersion string `json:"crypto_version,omitempty"`
}

func DescribeSource(raw string) (SourceDescription, error) {
	info, err := DetectSource(raw)
	if err != nil {
		return SourceDescription{}, err
	}
	return SourceDescription{SourceMasked: maskSource(info), SourceType: string(info.Type), CryptoVersion: info.CryptoVersion}, nil
}

// SourceResolution keeps the original input distinct from the runtime fetch
// target. ResolvedSource is intentionally not JSON-visible: it can contain a
// provider token.
type SourceResolution struct {
	OriginalSource       string     `json:"-"`
	OriginalSourceMasked string     `json:"original_source_masked,omitempty"`
	ResolvedSource       string     `json:"-"`
	ResolvedSourceMasked string     `json:"resolved_source_masked,omitempty"`
	SourceType           SourceType `json:"source_type"`
	CryptoVersion        string     `json:"crypto_version,omitempty"`
	RequiresHWID         bool       `json:"requires_hwid"`
}

// SourceDecoder handles one explicitly identified Happ crypto version.
// Match is not a content probe: the URI prefix chooses the decoder.
type SourceDecoder interface {
	Version() string
	Decode(payload string) (string, error)
}

// SourceResolver converts an original source into a canonical HTTPS URL.
// Decoders are keyed by the version extracted from the URI prefix.
type SourceResolver struct {
	decoders map[string]SourceDecoder
}

func NewSourceResolver(decoders ...SourceDecoder) *SourceResolver {
	result := &SourceResolver{decoders: make(map[string]SourceDecoder, len(decoders))}
	for _, decoder := range decoders {
		if decoder == nil || strings.TrimSpace(decoder.Version()) == "" {
			continue
		}
		result.decoders[strings.ToLower(strings.TrimSpace(decoder.Version()))] = decoder
	}
	return result
}

// NewDefaultSourceResolver wires the versions known by the source grammar.
// The protocol crypt4 key lives in the dedicated adapter. A deployment may
// override it with FLINTROUTE_HAPP_CRYPT4_KEY_FILE; an invalid explicit
// override intentionally results in decoder_unavailable.
func NewDefaultSourceResolver() *SourceResolver {
	crypt4 := embeddedCrypt4Key()
	if path := strings.TrimSpace(os.Getenv("FLINTROUTE_HAPP_CRYPT4_KEY_FILE")); path != "" {
		crypt4, _ = loadRSAPrivateKey(path)
	}
	if crypt4 == nil && strings.TrimSpace(os.Getenv("FLINTROUTE_HAPP_CRYPT4_KEY_FILE")) == "" {
		crypt4, _ = loadRSAPrivateKey("/etc/router-policy/secrets/happ-crypt4-private-key.pem")
	}
	return NewSourceResolver(
		NewCrypt4Decoder(crypt4),
		unsupportedSourceDecoder{version: "crypt"},
		unsupportedSourceDecoder{version: "crypt2"},
		unsupportedSourceDecoder{version: "crypt3"},
		unsupportedSourceDecoder{version: "crypt5"},
	)
}

// NormalizeSource accepts the URI escaping produced by browsers/forms, while
// leaving the ciphertext bytes untouched. Only the scheme separator is
// canonicalized here; payload decoding belongs to the selected decoder.
func NormalizeSource(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", &SourceError{Code: "source_empty", Message: "subscription source is empty or contains control characters"}
	}
	if len(value) > 4096 {
		return "", &SourceError{Code: "source_too_large", Message: "subscription source is too long"}
	}
	// Some clients escape the separator once or twice. Do not unescape the
	// whole value: %2B, %2F and %3D in the ciphertext must remain payload data.
	for strings.HasPrefix(strings.ToLower(value), "happ\\:\\/\\/") {
		value = "happ://" + value[len("happ\\:\\/\\/"):]
	}
	if strings.HasPrefix(strings.ToLower(value), "happ\\://") {
		value = "happ://" + value[len("happ\\://"):]
	}
	if strings.HasPrefix(strings.ToLower(value), "happ%3a%2f%2f") {
		value = "happ://" + value[len("happ%3a%2f%2f"):]
	}
	if strings.HasPrefix(strings.ToLower(value), "happ:\\/\\/") {
		value = "happ://" + value[len("happ:\\/\\/"):]
	}
	if strings.HasPrefix(strings.ToLower(value), "happ://") {
		prefixEnd := strings.IndexByte(value, '/')
		if prefixEnd < 0 {
			return "", &SourceError{Code: "malformed_source", Message: "Happ source payload is missing"}
		}
		// Canonicalize only the URI scheme and version spelling.
		return "happ://" + value[len("happ://"):], nil
	}
	return value, nil
}

func DetectSource(raw string) (SourceInfo, error) {
	canonical, err := NormalizeSource(raw)
	if err != nil {
		return SourceInfo{}, err
	}
	lower := strings.ToLower(canonical)
	if strings.HasPrefix(lower, "happ://") {
		rest := canonical[len("happ://"):]
		slash := strings.IndexByte(rest, '/')
		if slash <= 0 || slash == len(rest)-1 {
			return SourceInfo{}, &SourceError{Code: "malformed_payload", Message: "Happ source prefix or payload is malformed"}
		}
		version := strings.ToLower(rest[:slash])
		if !isHappCryptoVersion(version) {
			return SourceInfo{}, &SourceError{Code: "unsupported_crypto_version", Message: "Happ crypto version is not supported"}
		}
		return SourceInfo{Canonical: canonical, Type: SourceTypeHapp, CryptoVersion: version, Payload: rest[slash+1:]}, nil
	}
	parsed, err := url.Parse(canonical)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return SourceInfo{}, &SourceError{Code: "malformed_source", Message: "subscription source is malformed"}
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	switch parsed.Scheme {
	case "http":
		return SourceInfo{Canonical: parsed.String(), Type: SourceTypeHTTP}, nil
	case "https":
		canonicalURL := parsed.String()
		nested, present, err := wrappedHappSource(parsed)
		if err != nil {
			return SourceInfo{}, err
		}
		if present {
			nestedInfo, err := detectHappSource(nested)
			if err != nil {
				return SourceInfo{}, err
			}
			nestedInfo.Canonical = canonicalURL
			nestedInfo.WrappedSource = nested
			return nestedInfo, nil
		}
		return SourceInfo{Canonical: canonicalURL, Type: SourceTypeHTTPS}, nil
	default:
		return SourceInfo{}, &SourceError{Code: "unsupported_source_scheme", Message: "subscription source scheme is not supported"}
	}
}

func detectHappSource(canonical string) (SourceInfo, error) {
	value, err := NormalizeSource(canonical)
	if err != nil {
		return SourceInfo{}, err
	}
	rest := value[len("happ://"):]
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 || slash == len(rest)-1 {
		return SourceInfo{}, &SourceError{Code: "malformed_payload", Message: "Happ source prefix or payload is malformed"}
	}
	version := strings.ToLower(rest[:slash])
	if !isHappCryptoVersion(version) {
		return SourceInfo{}, &SourceError{Code: "unsupported_crypto_version", Message: "Happ crypto version is not supported"}
	}
	return SourceInfo{Canonical: value, Type: SourceTypeHapp, CryptoVersion: version, Payload: rest[slash+1:]}, nil
}

// wrappedHappSource extracts only the explicitly named subkey parameter. It
// uses PathUnescape rather than QueryUnescape so a literal '+' in a base64
// payload is not silently changed into a space. The payload itself is decoded
// later by the version-specific decoder.
func wrappedHappSource(parsed *url.URL) (string, bool, error) {
	if parsed == nil || parsed.RawQuery == "" {
		return "", false, nil
	}
	for _, pair := range strings.Split(parsed.RawQuery, "&") {
		keyRaw, valueRaw, hasValue := strings.Cut(pair, "=")
		key, err := url.QueryUnescape(keyRaw)
		if err != nil || key != "subkey" {
			continue
		}
		if !hasValue || valueRaw == "" {
			return "", true, &SourceError{Code: "malformed_payload", Message: "subscription portal subkey is empty"}
		}
		nested, err := url.PathUnescape(valueRaw)
		if err != nil {
			return "", true, &SourceError{Code: "malformed_payload", Message: "subscription portal subkey is URL-encoded incorrectly"}
		}
		canonical, err := NormalizeSource(nested)
		if err != nil {
			return "", true, err
		}
		if !strings.HasPrefix(strings.ToLower(canonical), "happ://") {
			return "", true, &SourceError{Code: "malformed_payload", Message: "subscription portal subkey is not a Happ source"}
		}
		return canonical, true, nil
	}
	return "", false, nil
}

func (r *SourceResolver) Resolve(_ context.Context, raw string) (SourceResolution, error) {
	info, err := DetectSource(raw)
	if err != nil {
		return SourceResolution{}, err
	}
	result := SourceResolution{
		OriginalSource: info.Canonical, OriginalSourceMasked: maskSource(info),
		SourceType: info.Type, CryptoVersion: info.CryptoVersion,
		RequiresHWID: info.Type == SourceTypeHapp,
	}
	if info.Type == SourceTypeHTTP {
		return SourceResolution{}, &SourceError{Code: "insecure_source", Message: "subscription endpoint must use HTTPS"}
	}
	if info.Type == SourceTypeHTTPS {
		if _, err := validateSubscriptionURL(info.Canonical); err != nil {
			return SourceResolution{}, &SourceError{Code: "invalid_subscription_url", Message: "subscription endpoint is not a valid HTTPS URL"}
		}
		result.ResolvedSource = info.Canonical
		result.ResolvedSourceMasked = maskURL(info.Canonical)
		return result, nil
	}
	nested := info
	if info.WrappedSource != "" {
		nested, err = detectHappSource(info.WrappedSource)
		if err != nil {
			return SourceResolution{}, err
		}
		result.SourceType = nested.Type
		result.CryptoVersion = nested.CryptoVersion
		result.RequiresHWID = nested.Type == SourceTypeHapp
	}
	if r == nil {
		return SourceResolution{}, &SourceError{Code: "decoder_unavailable", Message: "Happ crypto decoder is not available"}
	}
	decoder, ok := r.decoders[nested.CryptoVersion]
	if !ok || decoder == nil {
		return SourceResolution{}, &SourceError{Code: "decoder_unavailable", Message: "Happ crypto decoder is not available"}
	}
	resolved, err := decoder.Decode(nested.Payload)
	if err != nil {
		return SourceResolution{}, err
	}
	if _, err := validateSubscriptionURL(resolved); err != nil {
		return SourceResolution{}, &SourceError{Code: "plaintext_not_url", Message: "decrypted subscription value is not a valid HTTPS URL"}
	}
	result.ResolvedSource = resolved
	result.ResolvedSourceMasked = maskURL(resolved)
	return result, nil
}

type SourceError struct {
	Code    string
	Message string
}

func isHappCryptoVersion(version string) bool {
	if version == "crypt" {
		return true
	}
	if !strings.HasPrefix(version, "crypt") || len(version) == len("crypt") {
		return false
	}
	for _, char := range version[len("crypt"):] {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func (e *SourceError) Error() string {
	if e == nil {
		return "subscription source error"
	}
	return e.Message
}

type unsupportedSourceDecoder struct{ version string }

func (d unsupportedSourceDecoder) Version() string { return d.version }
func (d unsupportedSourceDecoder) Decode(string) (string, error) {
	return "", &SourceError{Code: "decoder_unavailable", Message: "Happ crypto decoder is not implemented for this version"}
}

type Crypt4Decoder struct{ key *rsa.PrivateKey }

func NewCrypt4Decoder(key *rsa.PrivateKey) SourceDecoder { return &Crypt4Decoder{key: key} }

func NewCrypt4DecoderFromPEM(raw []byte) (SourceDecoder, error) {
	key, err := parseRSAPrivateKey(raw)
	if err != nil {
		return nil, err
	}
	return NewCrypt4Decoder(key), nil
}

func (d *Crypt4Decoder) Version() string { return "crypt4" }

func (d *Crypt4Decoder) Decode(payload string) (string, error) {
	if d == nil || d.key == nil || d.key.Size() != 512 {
		return "", &SourceError{Code: "decoder_unavailable", Message: "crypt4 decoder key is not provisioned"}
	}
	decodedPayload, err := url.PathUnescape(payload)
	if err != nil {
		return "", &SourceError{Code: "malformed_payload", Message: "crypt4 payload URL decoding failed"}
	}
	ciphertext, err := decodeFlexibleBase64(decodedPayload)
	if err != nil {
		return "", &SourceError{Code: "base64_decode_failure", Message: "crypt4 payload is not valid base64"}
	}
	if len(ciphertext) == 0 || len(ciphertext)%d.key.Size() != 0 {
		return "", &SourceError{Code: "ciphertext_alignment", Message: "crypt4 ciphertext is not aligned to RSA-4096 blocks"}
	}
	plaintext := make([]byte, 0, len(ciphertext)/d.key.Size()*190)
	for offset := 0; offset < len(ciphertext); offset += d.key.Size() {
		block, err := rsa.DecryptPKCS1v15(rand.Reader, d.key, ciphertext[offset:offset+d.key.Size()])
		if err != nil {
			return "", &SourceError{Code: "decrypt_failure", Message: "crypt4 RSA decryption failed"}
		}
		plaintext = append(plaintext, block...)
	}
	if !utf8.Valid(plaintext) {
		return "", &SourceError{Code: "decrypt_failure", Message: "crypt4 plaintext is not valid UTF-8"}
	}
	return string(plaintext), nil
}

func decodeFlexibleBase64(value string) ([]byte, error) {
	value = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, value)
	value = strings.NewReplacer("-", "+", "_", "/").Replace(value)
	if rem := len(value) % 4; rem == 1 {
		return nil, errors.New("invalid base64 length")
	} else if rem != 0 {
		value += strings.Repeat("=", 4-rem)
	}
	return base64.StdEncoding.DecodeString(value)
}

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseRSAPrivateKey(raw)
}

func parseRSAPrivateKey(raw []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("crypt4 key is not PEM encoded")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("crypt4 key is not an RSA private key")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("crypt4 key is not an RSA private key")
	}
	return key, nil
}

func maskSource(info SourceInfo) string {
	if info.WrappedSource != "" {
		return maskURL(info.Canonical)
	}
	if info.Type == SourceTypeHapp {
		return "happ://" + info.CryptoVersion + "/" + maskToken(info.Payload)
	}
	return maskURL(info.Canonical)
}

func maskURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "<masked>"
	}
	result := parsed.Scheme + "://" + parsed.Host
	if parsed.EscapedPath() != "" {
		result += "/" + maskToken(strings.Trim(parsed.EscapedPath(), "/"))
	}
	if parsed.RawQuery != "" {
		result += "?" + maskToken(parsed.RawQuery)
	}
	return result
}

func maskToken(value string) string {
	if len(value) <= 8 {
		return "redacted"
	}
	return value[:4] + "-redacted-" + value[len(value)-4:]
}
