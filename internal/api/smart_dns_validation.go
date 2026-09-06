package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/probe"
)

type SmartDNSValidator func(context.Context, string, string) (probe.SmartDNSValidationResult, error)

type smartDNSValidationRecord struct {
	Endpoint  string                         `json:"endpoint"`
	Domain    string                         `json:"domain"`
	Result    probe.SmartDNSValidationResult `json:"result"`
	PassedAt  time.Time                      `json:"passed_at"`
	ExpiresAt time.Time                      `json:"expires_at"`
}

func smartDNSValidationKey(endpoint string) string {
	sum := sha256.Sum256([]byte(endpoint))
	return hex.EncodeToString(sum[:])
}

func (s *Server) saveSmartDNSValidation(endpoint, domain string, result probe.SmartDNSValidationResult) error {
	now := time.Now().UTC()
	return s.store.SaveJSON("smart_dns_validations", smartDNSValidationKey(endpoint), smartDNSValidationRecord{
		Endpoint: endpoint, Domain: domain, Result: result, PassedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	})
}

func (s *Server) loadSmartDNSValidation(endpoint string) (smartDNSValidationRecord, bool) {
	var record smartDNSValidationRecord
	if err := s.store.LoadJSON("smart_dns_validations", smartDNSValidationKey(endpoint), &record); err != nil {
		return smartDNSValidationRecord{}, false
	}
	if record.Endpoint != endpoint || !time.Now().UTC().Before(record.ExpiresAt) || !record.Result.UDP.Safe || !record.Result.TCP.Safe || !record.Result.TLSOK || !record.Result.HTTPOK {
		return smartDNSValidationRecord{}, false
	}
	return record, true
}

func (s *Server) smartDNSCandidateValidations(active, candidate *config.Config) []Validation {
	if active == nil || candidate == nil {
		return nil
	}
	activeByTag := make(map[string]config.Route, len(active.Routes))
	for _, route := range active.Routes {
		activeByTag[route.Tag] = route
	}
	validations := []Validation{}
	for _, route := range candidate.Routes {
		if route.Type != "smart_dns" || !route.Enabled() {
			continue
		}
		previous, existed := activeByTag[route.Tag]
		if existed && previous.Enabled() && previous.DNSServer == route.DNSServer && previous.DNSFallbackServer == route.DNSFallbackServer {
			continue
		}
		for _, endpoint := range []string{route.DNSServer, route.DNSFallbackServer} {
			if endpoint == "" {
				continue
			}
			record, ok := s.loadSmartDNSValidation(endpoint)
			if !ok {
				validations = append(validations, Validation{Level: "error", Code: "smart_dns_validation_required", Message: fmt.Sprintf("Smart DNS route %s endpoint %s must pass UDP, TCP and HTTP/TLS validation before apply", route.Tag, endpoint)})
				continue
			}
			validations = append(validations, Validation{Level: "info", Code: "smart_dns_validation_passed", Message: fmt.Sprintf("Smart DNS route %s passed validation for %s", route.Tag, record.Domain)})
		}
	}
	return validations
}
