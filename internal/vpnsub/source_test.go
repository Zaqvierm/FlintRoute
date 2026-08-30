package vpnsub

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeAndDetectHappForms(t *testing.T) {
	for _, raw := range []string{
		"happ://crypt4/payload",
		"happ\\://crypt4/payload",
		"happ:\\/\\/crypt4/payload",
		"happ%3A%2F%2Fcrypt4/payload",
	} {
		info, err := DetectSource(raw)
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		if info.Type != SourceTypeHapp || info.CryptoVersion != "crypt4" || info.Payload != "payload" {
			t.Fatalf("%q: unexpected info %+v", raw, info)
		}
	}
	encoded := "happ://crypt4/a%2Bb%2Fc%3D"
	info, err := DetectSource(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if info.Payload != "a%2Bb%2Fc%3D" {
		t.Fatalf("payload was changed during source normalization: %q", info.Payload)
	}
}

func TestReadSubscriptionSourceFilesKeepsOriginalHappAndDeduplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sources")
	if err := os.WriteFile(path, []byte("[\"happ%3A%2F%2Fcrypt4/a%2Bb%2Fc%3D\",\"happ://crypt5/payload\",\"happ://crypt5/payload\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	values, err := ReadSubscriptionSourceFiles(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 || values[0] != "happ://crypt4/a%2Bb%2Fc%3D" || values[1] != "happ://crypt5/payload" {
		t.Fatalf("unexpected normalized sources: %#v", values)
	}
}

func TestReadSubscriptionSourceFilesRejectsPlainHTTP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sources")
	if err := os.WriteFile(path, []byte("http://provider.example/list\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadSubscriptionSourceFiles(path)
	var sourceErr *SourceError
	if !errors.As(err, &sourceErr) || sourceErr.Code != "insecure_source" {
		t.Fatalf("plain HTTP source error=%v, want insecure_source", err)
	}
}

func TestDetectSourceSeparatesKnownUnsupportedCrypto(t *testing.T) {
	info, err := DetectSource("happ://crypt5/payload")
	if err != nil || info.CryptoVersion != "crypt5" {
		t.Fatalf("crypt5 was not recognized: info=%+v err=%v", info, err)
	}
	_, err = NewDefaultSourceResolver().Resolve(context.Background(), "happ://crypt5/payload")
	var sourceErr *SourceError
	if !errors.As(err, &sourceErr) || sourceErr.Code != "decoder_unavailable" {
		t.Fatalf("crypt5 did not produce explicit unsupported decoder status: %v", err)
	}
	_, err = NewSourceResolver(NewCrypt4Decoder(nil)).Resolve(context.Background(), "happ://crypt5/payload")
	if !errors.As(err, &sourceErr) || sourceErr.Code != "decoder_unavailable" {
		t.Fatalf("crypt5 was incorrectly offered to crypt4: %v", err)
	}
	info, err = DetectSource("happ://crypt6/payload")
	if err != nil || info.CryptoVersion != "crypt6" {
		t.Fatalf("future Happ version was not recognized: info=%+v err=%v", info, err)
	}
	_, err = NewDefaultSourceResolver().Resolve(context.Background(), "happ://crypt6/payload")
	if !errors.As(err, &sourceErr) || sourceErr.Code != "decoder_unavailable" {
		t.Fatalf("future Happ version did not produce explicit unsupported decoder status: %v", err)
	}
}

func TestResolveCanonicalizesHTTPScheme(t *testing.T) {
	resolution, err := NewSourceResolver().Resolve(context.Background(), "HTTPS://provider.example/list")
	if err != nil {
		t.Fatal(err)
	}
	if resolution.ResolvedSource != "https://provider.example/list" {
		t.Fatalf("scheme was not canonicalized: %q", resolution.ResolvedSource)
	}
}

func TestResolveHappSourceFromPortalSubkeyKeepsWrapperAndLiteralPlus(t *testing.T) {
	key := mustCrypt4TestKey(t)
	plaintext := "https://provider.example/subscription/portal-token"
	payload := encryptCrypt4(t, key, []byte(plaintext), base64.StdEncoding)
	// Query escaping is intentionally mixed: the wrapper is a normal HTTPS
	// URL, while the nested Happ payload contains both raw '+' and %2B forms.
	encoded := url.QueryEscape("happ://crypt4/" + payload)
	encoded = strings.Replace(encoded, "%2B", "+", 1)
	wrapped := "https://portal.example/add-key?subkey=" + encoded
	resolution, err := NewSourceResolver(NewCrypt4Decoder(key)).Resolve(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("portal Happ source did not resolve: %v", err)
	}
	if resolution.OriginalSource != wrapped {
		t.Fatalf("wrapper was not retained as original source: %q", resolution.OriginalSource)
	}
	if resolution.ResolvedSource != plaintext || resolution.SourceType != SourceTypeHapp || resolution.CryptoVersion != "crypt4" || !resolution.RequiresHWID {
		t.Fatalf("unexpected portal resolution: %+v", resolution)
	}
	if strings.Contains(resolution.OriginalSourceMasked, payload) || !strings.Contains(resolution.OriginalSourceMasked, "redacted") {
		t.Fatalf("portal source was not safely masked: %q", resolution.OriginalSourceMasked)
	}
}

func TestResolvePortalSubkeyWithRawHappPrefix(t *testing.T) {
	key := mustCrypt4TestKey(t)
	plaintext := "https://provider.example/subscription/raw-wrapper"
	payload := encryptCrypt4(t, key, []byte(plaintext), base64.StdEncoding)
	// This mirrors the portal form used by Happ clients: the scheme and
	// ciphertext separators stay raw while '+' is percent-encoded.
	payload = strings.ReplaceAll(payload, "+", "%2B")
	wrapped := "https://portal.example/add-key?subkey=happ://crypt4/" + payload
	resolution, err := NewSourceResolver(NewCrypt4Decoder(key)).Resolve(context.Background(), wrapped)
	if err != nil || resolution.ResolvedSource != plaintext {
		t.Fatalf("raw portal Happ source did not resolve: resolution=%+v err=%v", resolution, err)
	}
}

func TestPortalSubkeyRejectsNonHappValue(t *testing.T) {
	_, err := DetectSource("https://portal.example/add-key?subkey=https%3A%2F%2Fprovider.example%2Flist")
	var sourceErr *SourceError
	if !errors.As(err, &sourceErr) || sourceErr.Code != "malformed_payload" {
		t.Fatalf("non-Happ portal subkey error=%v, want malformed_payload", err)
	}
}

func TestCrypt4SingleBlock(t *testing.T) {
	key := mustCrypt4TestKey(t)
	plaintext := "https://provider.example/subscription/token"
	payload := encryptCrypt4(t, key, []byte(plaintext), base64.StdEncoding)
	resolution, err := NewSourceResolver(NewCrypt4Decoder(key)).Resolve(context.Background(), "happ://crypt4/"+payload)
	if err != nil || resolution.ResolvedSource != plaintext {
		t.Fatalf("single block crypt4 decode failed: resolution=%+v err=%v", resolution, err)
	}
	if resolution.ResolvedSourceMasked == plaintext || !strings.Contains(resolution.ResolvedSourceMasked, "redacted") {
		t.Fatalf("resolved source was not masked: %q", resolution.ResolvedSourceMasked)
	}
}

func TestDefaultResolverHasProvenCrypt4Key(t *testing.T) {
	key := embeddedCrypt4Key()
	if key == nil {
		t.Fatal("embedded crypt4 key is not parseable")
	}
	plaintext := "https://provider.example/subscription/default-key"
	payload := encryptCrypt4(t, key, []byte(plaintext), base64.StdEncoding)
	resolution, err := NewDefaultSourceResolver().Resolve(context.Background(), "happ://crypt4/"+payload)
	if err != nil || resolution.ResolvedSource != plaintext {
		t.Fatalf("default crypt4 resolver failed: resolution=%+v err=%v", resolution, err)
	}
}

func TestCrypt4MultipleBlocksAndEncodedPayload(t *testing.T) {
	key := mustCrypt4TestKey(t)
	plaintext := "https://provider.example/subscription/" + strings.Repeat("x", 900)
	encoded := encryptCrypt4(t, key, []byte(plaintext), base64.RawURLEncoding)
	encoded = url.QueryEscape(encoded)
	resolution, err := NewSourceResolver(NewCrypt4Decoder(key)).Resolve(context.Background(), "happ://crypt4/"+encoded)
	if err != nil || resolution.ResolvedSource != plaintext {
		t.Fatalf("multi-block URL-safe crypt4 decode failed: resolution=%+v err=%v", resolution, err)
	}
}

func TestCrypt4MissingPaddingAndFailures(t *testing.T) {
	key := mustCrypt4TestKey(t)
	plaintext := []byte("https://provider.example/subscription/token")
	standard := encryptCrypt4(t, key, plaintext, base64.StdEncoding)
	standard = strings.TrimRight(standard, "=")
	if _, err := NewSourceResolver(NewCrypt4Decoder(key)).Resolve(context.Background(), "happ://crypt4/"+standard); err != nil {
		t.Fatalf("missing padding was rejected: %v", err)
	}
	for _, test := range []struct {
		name    string
		payload string
		want    string
	}{
		{"malformed payload escape", "%%%", "malformed_payload"},
		{"misaligned ciphertext", base64.RawStdEncoding.EncodeToString([]byte("short")), "ciphertext_alignment"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewSourceResolver(NewCrypt4Decoder(key)).Resolve(context.Background(), "happ://crypt4/"+test.payload)
			var sourceErr *SourceError
			if !errors.As(err, &sourceErr) || sourceErr.Code != test.want {
				t.Fatalf("error=%v, want %s", err, test.want)
			}
		})
	}
	other := mustCrypt4TestKey(t)
	payload := encryptCrypt4(t, other, plaintext, base64.StdEncoding)
	_, err := NewSourceResolver(NewCrypt4Decoder(key)).Resolve(context.Background(), "happ://crypt4/"+payload)
	var sourceErr *SourceError
	if !errors.As(err, &sourceErr) || sourceErr.Code != "decrypt_failure" {
		t.Fatalf("RSA failure was not classified: %v", err)
	}
	nonURL := encryptCrypt4(t, key, []byte("not-a-subscription"), base64.StdEncoding)
	_, err = NewSourceResolver(NewCrypt4Decoder(key)).Resolve(context.Background(), "happ://crypt4/"+nonURL)
	if !errors.As(err, &sourceErr) || sourceErr.Code != "plaintext_not_url" {
		t.Fatalf("non-URL plaintext was not classified: %v", err)
	}
}

func mustCrypt4TestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func encryptCrypt4(t *testing.T, key *rsa.PrivateKey, plaintext []byte, encoding *base64.Encoding) string {
	t.Helper()
	max := key.Size() - 11
	ciphertext := make([]byte, 0, ((len(plaintext)+max-1)/max)*key.Size())
	for offset := 0; offset < len(plaintext); offset += max {
		end := offset + max
		if end > len(plaintext) {
			end = len(plaintext)
		}
		block, err := rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, plaintext[offset:end])
		if err != nil {
			t.Fatal(err)
		}
		ciphertext = append(ciphertext, block...)
	}
	return encoding.EncodeToString(ciphertext)
}
