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

package certificates

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"time"

	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

const (
	// DefaultDashboardCommonName is the default common name for dashboard certificates
	DefaultDashboardCommonName = "dashboard"
)

// DashboardCertConfig holds configuration for dashboard certificate generation
type DashboardCertConfig struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	State              string
	Locality           string
	Validity           time.Duration // Certificate validity as duration
	KeySize            int           // Only used for RSA
	KeyAlgorithm       KeyAlgorithm
	ECDSACurve         ECDSACurve
	DNSNames           []string
	IPAddresses        []net.IP
}

// DefaultDashboardCertConfig returns a DashboardCertConfig with default values
func DefaultDashboardCertConfig() *DashboardCertConfig {
	return &DashboardCertConfig{
		CommonName:         DefaultDashboardCommonName,
		Organization:       DefaultOrganization,
		OrganizationalUnit: DefaultOrganizationalUnit,
		Country:            DefaultCountry,
		State:              DefaultState,
		Locality:           DefaultLocality,
		Validity:           MustParseCertDuration(DefaultNodeValidityStr),
		KeySize:            DefaultKeySize,
		KeyAlgorithm:       KeyAlgorithmRSA,
		ECDSACurve:         ECDSACurveP256,
		DNSNames:           []string{},
		IPAddresses:        []net.IP{},
	}
}

// DashboardCertResult contains the generated dashboard certificate and private key
type DashboardCertResult struct {
	Certificate    *x509.Certificate
	PrivateKey     crypto.PrivateKey
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

// GenerateDashboardCert generates a dashboard certificate signed by the CA
func GenerateDashboardCert(config *DashboardCertConfig, ca *CAResult) (*DashboardCertResult, error) {
	if config == nil {
		return nil, fmt.Errorf("dashboard cert config is required")
	}

	if ca == nil {
		return nil, fmt.Errorf("CA is required")
	}

	// Apply defaults for empty fields
	if config.CommonName == "" {
		config.CommonName = DefaultDashboardCommonName
	}
	if config.Organization == "" {
		config.Organization = DefaultOrganization
	}
	if config.OrganizationalUnit == "" {
		config.OrganizationalUnit = DefaultOrganizationalUnit
	}
	if config.Country == "" {
		config.Country = DefaultCountry
	}
	if config.State == "" {
		config.State = DefaultState
	}
	if config.Locality == "" {
		config.Locality = DefaultLocality
	}
	if config.Validity <= 0 {
		config.Validity = MustParseCertDuration(DefaultNodeValidityStr)
	}
	if config.KeySize <= 0 {
		config.KeySize = DefaultKeySize
	}

	// Generate private key based on algorithm
	privateKey, err := generatePrivateKey(config.KeyAlgorithm, config.KeySize, config.ECDSACurve)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Calculate validity period
	notBefore := time.Now()
	notAfter := notBefore.Add(config.Validity)

	// Create certificate template
	// Dashboard cert needs both server and client auth for HTTPS and indexer communication
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         config.CommonName,
			Organization:       []string{config.Organization},
			OrganizationalUnit: []string{config.OrganizationalUnit},
			Country:            []string{config.Country},
			Province:           []string{config.State},
			Locality:           []string{config.Locality},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              config.DNSNames,
		IPAddresses:           config.IPAddresses,
	}

	// Sign the certificate with the CA
	publicKey := getPublicKey(privateKey)
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, publicKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create dashboard certificate: %w", err)
	}

	// Parse the certificate to get the x509.Certificate object
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dashboard certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyPEM, err := encodePrivateKeyToPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	return &DashboardCertResult{
		Certificate:    cert,
		PrivateKey:     privateKey,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
	}, nil
}

// GenerateDashboardSANs generates Subject Alternative Names for dashboard
func GenerateDashboardSANs(clusterName, namespace string) []string {
	dashboardService := clusterName + "-dashboard"
	return []string{
		"localhost",
		dashboardService,
		fmt.Sprintf("%s.%s", dashboardService, namespace),
		fmt.Sprintf("%s.%s.svc", dashboardService, namespace),
		dns.ServiceFQDN(dashboardService, namespace),
	}
}

// ParseDashboardCert parses a dashboard certificate and private key from PEM data
func ParseDashboardCert(certPEM, keyPEM []byte) (*DashboardCertResult, error) {
	// Parse certificate
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Parse private key
	privateKey, err := parsePrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &DashboardCertResult{
		Certificate:    cert,
		PrivateKey:     privateKey,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
	}, nil
}

// IsExpired checks if the dashboard certificate is expired
func (d *DashboardCertResult) IsExpired() bool {
	return time.Now().After(d.Certificate.NotAfter)
}

// NeedsRenewal checks if the dashboard certificate needs renewal
// The threshold parameter specifies how long before expiry to trigger renewal
func (d *DashboardCertResult) NeedsRenewal(threshold time.Duration) bool {
	renewalTime := d.Certificate.NotAfter.Add(-threshold)
	return time.Now().After(renewalTime)
}

// DaysUntilExpiry returns the number of days until the certificate expires
func (d *DashboardCertResult) DaysUntilExpiry() int {
	duration := time.Until(d.Certificate.NotAfter)
	return int(duration.Hours() / 24)
}
