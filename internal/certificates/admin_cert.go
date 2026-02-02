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
	"time"
)

const (
	// DefaultAdminCommonName is the default common name for admin certificates
	DefaultAdminCommonName = "admin"
)

// AdminCertConfig holds configuration for admin certificate generation
type AdminCertConfig struct {
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
}

// DefaultAdminCertConfig returns an AdminCertConfig with default values
func DefaultAdminCertConfig() *AdminCertConfig {
	return &AdminCertConfig{
		CommonName:         DefaultAdminCommonName,
		Organization:       DefaultOrganization,
		OrganizationalUnit: DefaultOrganizationalUnit,
		Country:            DefaultCountry,
		State:              DefaultState,
		Locality:           DefaultLocality,
		Validity:           MustParseCertDuration(DefaultNodeValidityStr), // Admin uses node validity
		KeySize:            DefaultKeySize,
		KeyAlgorithm:       KeyAlgorithmRSA,
		ECDSACurve:         ECDSACurveP256,
	}
}

// AdminCertResult contains the generated admin certificate and private key
type AdminCertResult struct {
	Certificate    *x509.Certificate
	PrivateKey     crypto.PrivateKey
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

// GenerateAdminCert generates an admin certificate signed by the CA
// Admin certificates are used for OpenSearch security management (securityadmin.sh)
func GenerateAdminCert(config *AdminCertConfig, ca *CAResult) (*AdminCertResult, error) {
	if config == nil {
		return nil, fmt.Errorf("admin cert config is required")
	}

	if ca == nil {
		return nil, fmt.Errorf("CA is required")
	}

	// Apply defaults for empty fields
	if config.CommonName == "" {
		config.CommonName = DefaultAdminCommonName
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

	// Create certificate template for admin cert
	// Admin certs only need client authentication for running security commands
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
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		// Admin cert typically doesn't need SANs as it's used for CLI operations
		DNSNames:    []string{"localhost"},
		IPAddresses: nil,
	}

	// Sign the certificate with the CA
	publicKey := getPublicKey(privateKey)
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, publicKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create admin certificate: %w", err)
	}

	// Parse the certificate to get the x509.Certificate object
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse admin certificate: %w", err)
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

	return &AdminCertResult{
		Certificate:    cert,
		PrivateKey:     privateKey,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
	}, nil
}

// ParseAdminCert parses an admin certificate and private key from PEM data
func ParseAdminCert(certPEM, keyPEM []byte) (*AdminCertResult, error) {
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

	return &AdminCertResult{
		Certificate:    cert,
		PrivateKey:     privateKey,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
	}, nil
}

// IsExpired checks if the admin certificate is expired
func (a *AdminCertResult) IsExpired() bool {
	return time.Now().After(a.Certificate.NotAfter)
}

// NeedsRenewal checks if the admin certificate needs renewal
// The threshold parameter specifies how long before expiry to trigger renewal
func (a *AdminCertResult) NeedsRenewal(threshold time.Duration) bool {
	renewalTime := a.Certificate.NotAfter.Add(-threshold)
	return time.Now().After(renewalTime)
}

// DaysUntilExpiry returns the number of days until the certificate expires
func (a *AdminCertResult) DaysUntilExpiry() int {
	duration := time.Until(a.Certificate.NotAfter)
	return int(duration.Hours() / 24)
}
