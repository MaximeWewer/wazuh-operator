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
	"testing"

	"github.com/go-logr/logr"

	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

func TestExtractDomainFromSAN(t *testing.T) {
	tests := []struct {
		name           string
		san            string
		expectedDomain string
		expectedOK     bool
	}{
		{
			name:           "standard kubernetes FQDN",
			san:            "my-service.my-namespace.svc.cluster.local",
			expectedDomain: "cluster.local",
			expectedOK:     true,
		},
		{
			name:           "pod FQDN with headless service",
			san:            "my-pod-0.my-service.my-namespace.svc.cluster.local",
			expectedDomain: "cluster.local",
			expectedOK:     true,
		},
		{
			name:           "custom domain",
			san:            "my-service.my-namespace.svc.custom.company.local",
			expectedDomain: "custom.company.local",
			expectedOK:     true,
		},
		{
			name:           "localhost - not a kubernetes FQDN",
			san:            "localhost",
			expectedDomain: "",
			expectedOK:     false,
		},
		{
			name:           "external domain - no svc",
			san:            "api.example.com",
			expectedDomain: "",
			expectedOK:     false,
		},
		{
			name:           "IP address",
			san:            "192.168.1.1",
			expectedDomain: "",
			expectedOK:     false,
		},
		{
			name:           "wildcard SAN",
			san:            "*.my-service.my-namespace.svc.cluster.local",
			expectedDomain: "cluster.local",
			expectedOK:     true,
		},
		{
			name:           "empty string",
			san:            "",
			expectedDomain: "",
			expectedOK:     false,
		},
		{
			name:           "just svc",
			san:            ".svc.",
			expectedDomain: "",
			expectedOK:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, ok := ExtractDomainFromSAN(tt.san)
			if ok != tt.expectedOK {
				t.Errorf("ExtractDomainFromSAN(%q) ok = %v, want %v", tt.san, ok, tt.expectedOK)
			}
			if domain != tt.expectedDomain {
				t.Errorf("ExtractDomainFromSAN(%q) domain = %q, want %q", tt.san, domain, tt.expectedDomain)
			}
		})
	}
}

func TestCertificateDomainMismatch(t *testing.T) {
	// Initialize DNS package for tests
	if err := dns.InitializeWithDomain("cluster.local"); err != nil {
		t.Fatalf("Failed to initialize DNS: %v", err)
	}
	defer dns.Reset()

	tests := []struct {
		name             string
		dnsNames         []string
		expectedMismatch bool
	}{
		{
			name:             "nil certificate",
			dnsNames:         nil,
			expectedMismatch: false,
		},
		{
			name:             "matching domain",
			dnsNames:         []string{"my-service.my-ns.svc.cluster.local", "localhost"},
			expectedMismatch: false,
		},
		{
			name:             "mismatched domain",
			dnsNames:         []string{"my-service.my-ns.svc.old.domain", "localhost"},
			expectedMismatch: true,
		},
		{
			name:             "mixed domains - one mismatch",
			dnsNames:         []string{"my-service.my-ns.svc.cluster.local", "another.svc.wrong.domain"},
			expectedMismatch: true,
		},
		{
			name:             "no kubernetes FQDNs",
			dnsNames:         []string{"localhost", "api.example.com"},
			expectedMismatch: false,
		},
		{
			name:             "empty DNS names",
			dnsNames:         []string{},
			expectedMismatch: false,
		},
		{
			name: "multiple matching FQDNs",
			dnsNames: []string{
				"indexer.wazuh.svc.cluster.local",
				"indexer-0.indexer-headless.wazuh.svc.cluster.local",
				"*.indexer-headless.wazuh.svc.cluster.local",
			},
			expectedMismatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cert *x509.Certificate
			if tt.dnsNames != nil {
				cert = &x509.Certificate{
					DNSNames: tt.dnsNames,
				}
			}

			result := CertificateDomainMismatch(cert)
			if result != tt.expectedMismatch {
				t.Errorf("CertificateDomainMismatch() = %v, want %v", result, tt.expectedMismatch)
			}
		})
	}
}

func TestValidateCertificateDomain(t *testing.T) {
	// Initialize DNS package for tests with custom domain
	if err := dns.InitializeWithDomain("custom.local"); err != nil {
		t.Fatalf("Failed to initialize DNS: %v", err)
	}
	defer dns.Reset()

	tests := []struct {
		name                 string
		dnsNames             []string
		expectMismatch       bool
		expectMismatchedSANs int
		expectActualDomains  []string
	}{
		{
			name:                 "all matching custom domain",
			dnsNames:             []string{"svc.ns.svc.custom.local", "pod.svc.ns.svc.custom.local"},
			expectMismatch:       false,
			expectMismatchedSANs: 0,
			expectActualDomains:  []string{"custom.local"},
		},
		{
			name:                 "old cluster.local domain",
			dnsNames:             []string{"svc.ns.svc.cluster.local"},
			expectMismatch:       true,
			expectMismatchedSANs: 1,
			expectActualDomains:  []string{"cluster.local"},
		},
		{
			name:                 "mixed old and new domains",
			dnsNames:             []string{"svc.ns.svc.custom.local", "other.ns.svc.cluster.local"},
			expectMismatch:       true,
			expectMismatchedSANs: 1,
			expectActualDomains:  []string{"custom.local", "cluster.local"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				DNSNames: tt.dnsNames,
			}

			result := ValidateCertificateDomain(cert)

			if result.HasMismatch != tt.expectMismatch {
				t.Errorf("HasMismatch = %v, want %v", result.HasMismatch, tt.expectMismatch)
			}

			if result.ExpectedDomain != "custom.local" {
				t.Errorf("ExpectedDomain = %q, want %q", result.ExpectedDomain, "custom.local")
			}

			if len(result.MismatchedSANs) != tt.expectMismatchedSANs {
				t.Errorf("MismatchedSANs count = %d, want %d", len(result.MismatchedSANs), tt.expectMismatchedSANs)
			}
		})
	}
}

func TestRequiresDomainRegeneration(t *testing.T) {
	// Initialize DNS package for tests
	if err := dns.InitializeWithDomain("new.domain"); err != nil {
		t.Fatalf("Failed to initialize DNS: %v", err)
	}
	defer dns.Reset()

	// Use a no-op logger for tests
	log := logr.Discard()

	tests := []struct {
		name             string
		dnsNames         []string
		expectRegenerate bool
	}{
		{
			name:             "needs regeneration - old domain",
			dnsNames:         []string{"svc.ns.svc.cluster.local"},
			expectRegenerate: true,
		},
		{
			name:             "no regeneration needed - matching domain",
			dnsNames:         []string{"svc.ns.svc.new.domain"},
			expectRegenerate: false,
		},
		{
			name:             "no kubernetes FQDNs - no regeneration",
			dnsNames:         []string{"localhost", "127.0.0.1"},
			expectRegenerate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				DNSNames: tt.dnsNames,
			}

			result := RequiresDomainRegeneration(cert, "test-secret", "test-ns", log)
			if result != tt.expectRegenerate {
				t.Errorf("RequiresDomainRegeneration() = %v, want %v", result, tt.expectRegenerate)
			}
		})
	}
}

func TestParseCertificateFromPEM(t *testing.T) {
	// Initialize DNS package for tests (required for cert generation)
	if err := dns.InitializeWithDomain("cluster.local"); err != nil {
		t.Fatalf("Failed to initialize DNS: %v", err)
	}
	defer dns.Reset()

	// Generate a test CA certificate
	caConfig := DefaultCAConfig("test-ca")
	caResult, err := GenerateCA(caConfig)
	if err != nil {
		t.Fatalf("Failed to generate test CA: %v", err)
	}

	tests := []struct {
		name        string
		certPEM     []byte
		expectError bool
	}{
		{
			name:        "valid certificate PEM",
			certPEM:     caResult.CertificatePEM,
			expectError: false,
		},
		{
			name:        "invalid PEM data",
			certPEM:     []byte("not a valid PEM"),
			expectError: true,
		},
		{
			name:        "empty PEM data",
			certPEM:     []byte{},
			expectError: true,
		},
		{
			name:        "nil PEM data",
			certPEM:     nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := ParseCertificateFromPEM(tt.certPEM)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if cert == nil {
					t.Error("Expected certificate, got nil")
				}
			}
		})
	}
}

func TestDomainValidationResultFields(t *testing.T) {
	// Initialize DNS package for tests
	if err := dns.InitializeWithDomain("expected.domain"); err != nil {
		t.Fatalf("Failed to initialize DNS: %v", err)
	}
	defer dns.Reset()

	cert := &x509.Certificate{
		DNSNames: []string{
			"svc1.ns.svc.wrong.domain",
			"svc2.ns.svc.expected.domain",
			"svc3.ns.svc.another.wrong",
			"localhost",
		},
	}

	result := ValidateCertificateDomain(cert)

	// Should have mismatch
	if !result.HasMismatch {
		t.Error("Expected HasMismatch to be true")
	}

	// Expected domain should match
	if result.ExpectedDomain != "expected.domain" {
		t.Errorf("ExpectedDomain = %q, want %q", result.ExpectedDomain, "expected.domain")
	}

	// Should have 2 mismatched SANs
	if len(result.MismatchedSANs) != 2 {
		t.Errorf("MismatchedSANs count = %d, want 2", len(result.MismatchedSANs))
	}

	// Should have 3 actual domains found
	if len(result.ActualDomains) != 3 {
		t.Errorf("ActualDomains count = %d, want 3", len(result.ActualDomains))
	}
}
