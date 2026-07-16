package zapret

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

const maxCatalogFileBytes = 256 << 10

type CatalogFile struct {
	Version  int                  `json:"version"`
	Profiles []CatalogFileProfile `json:"profiles"`
	Bundles  []BundleSpec         `json:"bundles"`
}

type CatalogFileProfile struct {
	ID              string   `json:"id"`
	Provider        string   `json:"provider"`
	ProviderVersion string   `json:"provider_version"`
	BinaryDigest    string   `json:"binary_digest"`
	RouteType       string   `json:"route_type"`
	IPFamilies      []string `json:"ip_families"`
	Transports      []string `json:"transports"`
	Ports           []uint16 `json:"ports"`
	Queue           uint16   `json:"queue"`
	Safety          string   `json:"safety"`
	StrategyDigest  string   `json:"strategy_digest"`
	Strategy        string   `json:"strategy"`
}

func LoadCatalogFile(path string) (*Catalog, *BundleCatalog, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxCatalogFileBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(raw) > maxCatalogFileBytes {
		return nil, nil, errors.New("Zapret catalog file exceeds 256 KiB")
	}
	var document CatalogFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, nil, fmt.Errorf("decode Zapret catalog: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, nil, errors.New("Zapret catalog must contain one JSON document")
	}
	if document.Version != 1 {
		return nil, nil, errors.New("unsupported Zapret catalog version")
	}
	profiles := make([]Profile, 0, len(document.Profiles))
	for _, rawProfile := range document.Profiles {
		profiles = append(profiles, Profile{
			ID: rawProfile.ID, Provider: rawProfile.Provider, ProviderVersion: rawProfile.ProviderVersion,
			BinaryDigest: rawProfile.BinaryDigest, RouteType: rawProfile.RouteType,
			IPFamilies: rawProfile.IPFamilies, Transports: rawProfile.Transports, Ports: rawProfile.Ports,
			Queue: rawProfile.Queue, Safety: rawProfile.Safety, StrategyDigest: rawProfile.StrategyDigest,
			Strategy: []byte(rawProfile.Strategy),
		})
	}
	profileCatalog, err := NewCatalog(profiles)
	if err != nil {
		return nil, nil, err
	}
	bundleCatalog, err := NewBundleCatalog(document.Bundles, profileCatalog)
	if err != nil {
		return nil, nil, err
	}
	return profileCatalog, bundleCatalog, nil
}
