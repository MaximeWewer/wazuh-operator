/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certcommon

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/go-logr/logr"

	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

// ErrInvalidCertificatePEM is returned when the certificate PEM data is invalid.
var ErrInvalidCertificatePEM = errors.New("invalid certificate PEM data")

// DomainValidationResult contains the result of a certificate domain validation.
type DomainValidationResult struct {
	// HasMismatch indicates if the certificate has SANs with a different cluster domain
	HasMismatch bool
	// ExpectedDomain is the configured cluster domain
	ExpectedDomain string
	// MismatchedSANs contains the SANs that don't match the expected domain
	MismatchedSANs []string
	// ActualDomains contains the domains found in the certificate SANs
	ActualDomains []string
}

// CertificateDomainMismatch checks if a certificate's SANs match the configured cluster domain.
// Returns true if any SAN contains a Kubernetes FQDN with a different cluster domain suffix.
//
// This function examines DNS names in the certificate looking for patterns like:
//   - service.namespace.svc.cluster.local
//   - pod.service.namespace.svc.cluster.local
//
// If the domain after ".svc." doesn't match the configured dns.ClusterDomain(),
// it indicates a mismatch that requires certificate regeneration.
func CertificateDomainMismatch(cert *x509.Certificate) bool {
	result := ValidateCertificateDomain(cert)
	return result.HasMismatch
}

// ValidateCertificateDomain performs a detailed validation of certificate SANs against
// the configured cluster domain. Returns a DomainValidationResult with details about
// any mismatches found.
func ValidateCertificateDomain(cert *x509.Certificate) DomainValidationResult {
	if cert == nil {
		return DomainValidationResult{
			HasMismatch:    false,
			ExpectedDomain: dns.ClusterDomain(),
		}
	}

	result := DomainValidationResult{
		HasMismatch:    false,
		ExpectedDomain: dns.ClusterDomain(),
		MismatchedSANs: []string{},
		ActualDomains:  []string{},
	}

	seenDomains := make(map[string]bool)

	for _, san := range cert.DNSNames {
		// Extract domain using the helper function
		actualDomain, ok := ExtractDomainFromSAN(san)
		if !ok {
			continue
		}

		// Track unique domains found
		if !seenDomains[actualDomain] {
			seenDomains[actualDomain] = true
			result.ActualDomains = append(result.ActualDomains, actualDomain)
		}

		// Check if domain matches the configured cluster domain
		if actualDomain != dns.ClusterDomain() {
			result.HasMismatch = true
			result.MismatchedSANs = append(result.MismatchedSANs, san)
		}
	}

	return result
}

// RequiresDomainRegeneration checks if a certificate needs regeneration due to domain mismatch.
// If a mismatch is detected, it logs detailed information for audit purposes.
//
// Parameters:
//   - cert: The x509 certificate to validate
//   - secretName: Name of the secret containing the certificate (for logging)
//   - namespace: Namespace of the secret (for logging)
//   - log: Logger for audit trail
//
// Returns true if the certificate should be regenerated due to domain mismatch.
func RequiresDomainRegeneration(cert *x509.Certificate, secretName, namespace string, log logr.Logger) bool {
	result := ValidateCertificateDomain(cert)

	if result.HasMismatch {
		log.Info("certificate domain mismatch detected, regeneration required",
			"secret", secretName,
			"namespace", namespace,
			"expectedDomain", result.ExpectedDomain,
			"actualDomains", result.ActualDomains,
			"mismatchedSANs", result.MismatchedSANs,
		)
		return true
	}

	return false
}

// ExtractDomainFromSAN extracts the cluster domain from a Kubernetes FQDN SAN.
// Returns the domain and true if extraction was successful, or empty string and false otherwise.
//
// The function finds the LAST occurrence of ".svc." to correctly handle edge cases
// where the service or namespace name might contain "svc" as a substring.
//
// Examples:
//   - "my-service.my-ns.svc.cluster.local" -> "cluster.local", true
//   - "my-pod.my-svc.my-ns.svc.custom.domain" -> "custom.domain", true
//   - "pod.svc.ns.svc.cluster.local" -> "cluster.local", true (service named "svc")
//   - "localhost" -> "", false
//   - "external.example.com" -> "", false
func ExtractDomainFromSAN(san string) (string, bool) {
	// Find the LAST occurrence of ".svc." to handle edge cases
	// where the service name might contain "svc"
	lastIdx := strings.LastIndex(san, ".svc.")
	if lastIdx == -1 {
		return "", false
	}

	// Extract domain after ".svc."
	domain := san[lastIdx+5:] // 5 = len(".svc.")
	if domain == "" {
		return "", false
	}

	return domain, true
}

// ParseCertificateFromPEM parses a PEM-encoded certificate and returns the x509.Certificate.
// This is a convenience wrapper for certificate domain validation.
func ParseCertificateFromPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, ErrInvalidCertificatePEM
	}

	return x509.ParseCertificate(block.Bytes)
}
