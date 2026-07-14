package geoip

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

const (
	MetadataSchemaVersion = 1
	DefaultMaxBytes       = 16 << 20
)

type Metadata struct {
	SchemaVersion int       `json:"schema_version"`
	SourceURL     string    `json:"source_url"`
	SourceVersion string    `json:"source_version"`
	ETag          string    `json:"etag,omitempty"`
	LastModified  string    `json:"last_modified,omitempty"`
	SHA256        string    `json:"sha256"`
	Bytes         int64     `json:"bytes"`
	DatabaseType  string    `json:"database_type"`
	BuildEpoch    uint      `json:"build_epoch"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type Evidence struct {
	DatabaseType  string    `json:"database_type"`
	SourceVersion string    `json:"source_version"`
	SHA256        string    `json:"sha256"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type cacheEntry struct {
	reader       *maxminddb.Reader
	metadataHash string
	databaseSize int64
	modifiedNS   int64
	metadata     Metadata
}

var readerCache = struct {
	sync.Mutex
	entries map[string]*cacheEntry
}{entries: map[string]*cacheEntry{}}

func MetadataPath(databasePath string) string { return databasePath + ".meta.json" }
func PreviousPath(databasePath string) string { return databasePath + ".previous" }

func Lookup(databasePath string, address netip.Addr, maxAge time.Duration, now time.Time) (string, Evidence, error) {
	if databasePath == "" || !address.IsValid() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return "", Evidence{}, errors.New("invalid GeoIP lookup")
	}
	entry, err := openVerified(databasePath, maxAge, now)
	if err != nil {
		return "", Evidence{}, err
	}
	var record struct {
		CountryCode string `maxminddb:"country_code"`
	}
	if err := entry.reader.Lookup(net.IP(address.AsSlice()), &record); err != nil {
		return "", Evidence{}, errors.New("GeoIP lookup failed")
	}
	country := strings.ToUpper(strings.TrimSpace(record.CountryCode))
	if !validCountry(country) {
		return "", Evidence{}, errors.New("GeoIP country is unknown")
	}
	return country, Evidence{
		DatabaseType: entry.metadata.DatabaseType, SourceVersion: entry.metadata.SourceVersion,
		SHA256: entry.metadata.SHA256, UpdatedAt: entry.metadata.UpdatedAt,
	}, nil
}

func Verify(databasePath string, maxAge time.Duration, now time.Time) (Metadata, error) {
	entry, err := openVerified(databasePath, maxAge, now)
	if err != nil {
		return Metadata{}, err
	}
	return entry.metadata, nil
}

func Invalidate(databasePath string) {
	readerCache.Lock()
	if entry := readerCache.entries[databasePath]; entry != nil {
		_ = entry.reader.Close()
		delete(readerCache.entries, databasePath)
	}
	readerCache.Unlock()
}

func openVerified(databasePath string, maxAge time.Duration, now time.Time) (*cacheEntry, error) {
	metadataRaw, metadata, err := loadMetadata(databasePath)
	if err != nil {
		return nil, err
	}
	if maxAge > 0 && (metadata.UpdatedAt.IsZero() || now.Sub(metadata.UpdatedAt) > maxAge || metadata.UpdatedAt.After(now.Add(24*time.Hour))) {
		return nil, errors.New("GeoIP database is stale")
	}
	info, err := secureRegularFile(databasePath, DefaultMaxBytes)
	if err != nil {
		return nil, err
	}
	if info.Size() != metadata.Bytes {
		return nil, errors.New("GeoIP database size mismatch")
	}
	metadataHash := hashBytes(metadataRaw)
	readerCache.Lock()
	defer readerCache.Unlock()
	if cached := readerCache.entries[databasePath]; cached != nil && cached.metadataHash == metadataHash && cached.databaseSize == info.Size() && cached.modifiedNS == info.ModTime().UnixNano() {
		return cached, nil
	}
	actualHash, err := hashFile(databasePath)
	if err != nil {
		return nil, err
	}
	if actualHash != metadata.SHA256 {
		return nil, errors.New("GeoIP database hash mismatch")
	}
	reader, err := maxminddb.Open(databasePath)
	if err != nil {
		return nil, errors.New("GeoIP database is not a valid MMDB file")
	}
	if reader.Metadata.DatabaseType == "" || reader.Metadata.DatabaseType != metadata.DatabaseType || reader.Metadata.BuildEpoch != metadata.BuildEpoch {
		_ = reader.Close()
		return nil, errors.New("GeoIP MMDB metadata mismatch")
	}
	if previous := readerCache.entries[databasePath]; previous != nil {
		_ = previous.reader.Close()
	}
	entry := &cacheEntry{reader: reader, metadataHash: metadataHash, databaseSize: info.Size(), modifiedNS: info.ModTime().UnixNano(), metadata: metadata}
	readerCache.entries[databasePath] = entry
	return entry, nil
}

func loadMetadata(databasePath string) ([]byte, Metadata, error) {
	path := MetadataPath(databasePath)
	if _, err := secureRegularFile(path, 64<<10); err != nil {
		return nil, Metadata{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, Metadata{}, err
	}
	var metadata Metadata
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return nil, Metadata{}, errors.New("invalid GeoIP metadata")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, Metadata{}, errors.New("trailing GeoIP metadata")
	}
	if metadata.SchemaVersion != MetadataSchemaVersion || metadata.SourceURL == "" || metadata.SourceVersion == "" || metadata.DatabaseType == "" || metadata.Bytes <= 0 || metadata.Bytes > DefaultMaxBytes || !validHash(metadata.SHA256) {
		return nil, Metadata{}, errors.New("incomplete GeoIP metadata")
	}
	return raw, metadata, nil
}

func secureRegularFile(path string, maxBytes int64) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxBytes {
		return nil, errors.New("GeoIP file is unsafe or oversized")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return nil, errors.New("GeoIP file must have mode 0600")
	}
	return info, nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func hashBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validHash(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func validCountry(value string) bool {
	return len(value) == 2 && value[0] >= 'A' && value[0] <= 'Z' && value[1] >= 'A' && value[1] <= 'Z'
}

func metadataForReader(sourceURL, sourceVersion, etag, lastModified, sha string, bytes int64, reader *maxminddb.Reader, now time.Time) Metadata {
	return Metadata{
		SchemaVersion: MetadataSchemaVersion, SourceURL: sourceURL, SourceVersion: sourceVersion,
		ETag: etag, LastModified: lastModified, SHA256: sha, Bytes: bytes,
		DatabaseType: reader.Metadata.DatabaseType, BuildEpoch: reader.Metadata.BuildEpoch, UpdatedAt: now.UTC(),
	}
}

func formatError(prefix string, err error) error {
	if err == nil {
		return errors.New(prefix)
	}
	return fmt.Errorf("%s: %w", prefix, err)
}
