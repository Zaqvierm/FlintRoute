package geoip

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

type UpdateResult struct {
	Status            string    `json:"status"`
	SHA256            string    `json:"sha256,omitempty"`
	Bytes             int64     `json:"bytes,omitempty"`
	SourceVersion     string    `json:"source_version,omitempty"`
	DatabaseType      string    `json:"database_type,omitempty"`
	PreviousPreserved bool      `json:"previous_preserved"`
	UpdatedAt         time.Time `json:"updated_at,omitempty"`
}

func Update(ctx context.Context, client *http.Client, sourceURL, databasePath string, maxBytes int64, now time.Time) (UpdateResult, error) {
	parsed, err := url.Parse(sourceURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return UpdateResult{}, errors.New("GeoIP source must be HTTPS without credentials or fragment")
	}
	if strings.TrimSpace(databasePath) == "" {
		return UpdateResult{}, errors.New("GeoIP database path is required")
	}
	if maxBytes <= 0 || maxBytes > DefaultMaxBytes {
		maxBytes = DefaultMaxBytes
	}
	if client == nil {
		client = &http.Client{}
	}
	requestClient := *client
	requestClient.Timeout = 2 * time.Minute
	requestClient.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) > 5 || request.URL.Scheme != "https" || request.URL.User != nil {
			return errors.New("unsafe GeoIP redirect")
		}
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return UpdateResult{}, errors.New("GeoIP request creation failed")
	}
	request.Header.Set("User-Agent", "router-policy-geoip/1")
	if _, existing, metadataErr := loadMetadata(databasePath); metadataErr == nil && existing.SourceURL == parsed.String() {
		if existing.ETag != "" {
			request.Header.Set("If-None-Match", existing.ETag)
		}
		if existing.LastModified != "" {
			request.Header.Set("If-Modified-Since", existing.LastModified)
		}
	}
	response, err := requestClient.Do(request)
	if err != nil {
		return UpdateResult{}, errors.New("GeoIP download failed")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		metadata, err := Verify(databasePath, 0, now)
		if err != nil {
			return UpdateResult{}, errors.New("GeoIP server returned not-modified for an invalid local database")
		}
		return UpdateResult{Status: "NOT_MODIFIED", SHA256: metadata.SHA256, Bytes: metadata.Bytes, SourceVersion: metadata.SourceVersion, DatabaseType: metadata.DatabaseType, UpdatedAt: metadata.UpdatedAt}, nil
	}
	if response.StatusCode != http.StatusOK {
		return UpdateResult{}, fmt.Errorf("GeoIP source returned HTTP %d", response.StatusCode)
	}
	if response.ContentLength > maxBytes {
		return UpdateResult{}, errors.New("GeoIP database exceeds size limit")
	}
	if err := os.MkdirAll(filepath.Dir(databasePath), 0o700); err != nil {
		return UpdateResult{}, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(databasePath), ".geoip-download-*")
	if err != nil {
		return UpdateResult{}, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := os.Chmod(temporaryPath, 0o600); err != nil {
		_ = temporary.Close()
		return UpdateResult{}, err
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, hasher), io.LimitReader(response.Body, maxBytes+1))
	if copyErr != nil || written <= 0 || written > maxBytes {
		_ = temporary.Close()
		return UpdateResult{}, errors.New("GeoIP database download is empty, truncated or oversized")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return UpdateResult{}, err
	}
	if err := temporary.Close(); err != nil {
		return UpdateResult{}, err
	}
	reader, err := maxminddb.Open(temporaryPath)
	if err != nil {
		return UpdateResult{}, errors.New("downloaded GeoIP database is not valid MMDB")
	}
	if err := validateCountryReader(reader); err != nil {
		_ = reader.Close()
		return UpdateResult{}, err
	}
	sha := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	etag := boundedHeader(response.Header.Get("ETag"))
	lastModified := boundedHeader(response.Header.Get("Last-Modified"))
	sourceVersion := firstNonEmpty(lastModified, etag, strconv.FormatUint(uint64(reader.Metadata.BuildEpoch), 10))
	metadata := metadataForReader(parsed.String(), sourceVersion, etag, lastModified, sha, written, reader, now)
	_ = reader.Close()

	previousPreserved := false
	if _, err := Verify(databasePath, 0, now); err == nil {
		if err := copyFileAtomic(databasePath, PreviousPath(databasePath), DefaultMaxBytes); err != nil {
			return UpdateResult{}, errors.New("could not preserve previous GeoIP database")
		}
		if err := copyFileAtomic(MetadataPath(databasePath), MetadataPath(PreviousPath(databasePath)), 64<<10); err != nil {
			return UpdateResult{}, errors.New("could not preserve previous GeoIP metadata")
		}
		previousPreserved = true
	}
	Invalidate(databasePath)
	if err := replaceDownloadedFile(temporaryPath, databasePath); err != nil {
		return UpdateResult{}, err
	}
	metadataRaw, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		_ = restorePrevious(databasePath, previousPreserved)
		return UpdateResult{}, err
	}
	if err := writeBytesAtomic(MetadataPath(databasePath), append(metadataRaw, '\n'), 0o600); err != nil {
		_ = restorePrevious(databasePath, previousPreserved)
		return UpdateResult{}, err
	}
	Invalidate(databasePath)
	if _, err := Verify(databasePath, 0, now); err != nil {
		_ = restorePrevious(databasePath, previousPreserved)
		return UpdateResult{}, errors.New("installed GeoIP database failed verification")
	}
	return UpdateResult{
		Status: "UPDATED", SHA256: sha, Bytes: written, SourceVersion: sourceVersion,
		DatabaseType: metadata.DatabaseType, PreviousPreserved: previousPreserved, UpdatedAt: metadata.UpdatedAt,
	}, nil
}

func validateCountryReader(reader *maxminddb.Reader) error {
	if reader == nil || reader.Metadata.DatabaseType == "" || reader.Metadata.NodeCount == 0 {
		return errors.New("GeoIP MMDB metadata is incomplete")
	}
	for _, sample := range []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("1.1.1.1")} {
		var record struct {
			CountryCode string `maxminddb:"country_code"`
		}
		if err := reader.Lookup(sample, &record); err == nil && validCountry(strings.ToUpper(strings.TrimSpace(record.CountryCode))) {
			return nil
		}
	}
	return errors.New("GeoIP MMDB does not expose country_code records")
}

func restorePrevious(databasePath string, previous bool) error {
	Invalidate(databasePath)
	if !previous {
		_ = os.Remove(databasePath)
		_ = os.Remove(MetadataPath(databasePath))
		return nil
	}
	if err := copyFileAtomic(PreviousPath(databasePath), databasePath, DefaultMaxBytes); err != nil {
		return err
	}
	return copyFileAtomic(MetadataPath(PreviousPath(databasePath)), MetadataPath(databasePath), 64<<10)
}

func replaceDownloadedFile(source, target string) error {
	if existing, err := os.Lstat(target); err == nil {
		if !existing.Mode().IsRegular() || existing.Mode()&os.ModeSymlink != 0 {
			return errors.New("existing GeoIP database is unsafe")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if runtime.GOOS != "windows" {
		return os.Rename(source, target)
	}
	old := target + ".replace-old"
	_ = os.Remove(old)
	hadOld := false
	if _, err := os.Lstat(target); err == nil {
		if err := os.Rename(target, old); err != nil {
			return err
		}
		hadOld = true
	}
	if err := os.Rename(source, target); err != nil {
		if hadOld {
			_ = os.Rename(old, target)
		}
		return err
	}
	if hadOld {
		_ = os.Remove(old)
	}
	return nil
}

func copyFileAtomic(source, target string, maxBytes int64) error {
	if _, err := secureRegularFile(source, maxBytes); err != nil {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), ".geoip-copy-*")
	if err != nil {
		return err
	}
	path := temporary.Name()
	defer os.Remove(path)
	if err := os.Chmod(path, 0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	written, err := io.Copy(temporary, io.LimitReader(input, maxBytes+1))
	if err != nil || written <= 0 || written > maxBytes {
		_ = temporary.Close()
		return errors.New("GeoIP copy failed")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return replaceDownloadedFile(path, target)
}

func writeBytesAtomic(target string, raw []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), ".geoip-meta-*")
	if err != nil {
		return err
	}
	path := temporary.Name()
	defer os.Remove(path)
	if err := os.Chmod(path, mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return replaceDownloadedFile(path, target)
}

func boundedHeader(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 512 || strings.ContainsAny(value, "\r\n\x00") {
		return ""
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return "unknown"
}
