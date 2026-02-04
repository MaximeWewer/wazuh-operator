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
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

const (
	// DefaultKeySize is the default RSA key size
	DefaultKeySize = 2048

	// DefaultOrganization is the default organization name
	DefaultOrganization = "Wazuh"

	// DefaultOrganizationalUnit is the default organizational unit
	DefaultOrganizationalUnit = "Security"

	// DefaultCountry is the default country code
	DefaultCountry = "US"

	// DefaultState is the default state/province
	DefaultState = "California"

	// DefaultLocality is the default city/locality
	DefaultLocality = "San Francisco"

	// DefaultAdminCommonName is the default common name for admin certificates
	DefaultAdminCommonName = "admin"
)

// CAConfig holds configuration for CA certificate generation
type CAConfig struct {
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

// DefaultCAConfig returns a CAConfig with default values
func DefaultCAConfig(commonName string) *CAConfig {
	return &CAConfig{
		CommonName:         commonName,
		Organization:       DefaultOrganization,
		OrganizationalUnit: DefaultOrganizationalUnit,
		Country:            DefaultCountry,
		State:              DefaultState,
		Locality:           DefaultLocality,
		Validity:           MustParseCertDuration(DefaultCAValidityStr),
		KeySize:            DefaultKeySize,
		KeyAlgorithm:       KeyAlgorithmRSA,
		ECDSACurve:         ECDSACurveP256,
	}
}

// FormatDN formats a Distinguished Name string from the given components
// Format: CN={commonName},OU={ou},O={org},L={locality},ST={state},C={country}
func FormatDN(commonName, ou, org, locality, state, country string) string {
	return fmt.Sprintf("CN=%s,OU=%s,O=%s,L=%s,ST=%s,C=%s",
		commonName, ou, org, locality, state, country)
}

// DefaultAdminDN returns the default Distinguished Name for admin certificates
func DefaultAdminDN() string {
	return FormatDN(DefaultAdminCommonName, DefaultOrganizationalUnit, DefaultOrganization,
		DefaultLocality, DefaultState, DefaultCountry)
}

// DefaultNodesDN returns the default Distinguished Name pattern for node certificates
// Uses wildcard CN=* to match any node certificate
func DefaultNodesDN() string {
	return FormatDN("*", DefaultOrganizationalUnit, DefaultOrganization,
		DefaultLocality, DefaultState, DefaultCountry)
}

// DNOptions holds the options for generating Distinguished Names
// Note: CommonName is typically auto-generated based on certificate type:
//   - CA: "<cluster>-ca"
//   - Indexer nodes: "<cluster>-indexer"
//   - Admin: "admin" (required by OpenSearch security plugin)
//   - Dashboard: "<cluster>-dashboard"
//   - Filebeat: "<cluster>-filebeat"
type DNOptions struct {
	CommonName         string // Usually auto-generated, only used internally
	OrganizationalUnit string
	Organization       string
	Locality           string
	State              string
	Country            string
}

// DefaultDNOptions returns the default DN options
func DefaultDNOptions() DNOptions {
	return DNOptions{
		CommonName:         DefaultAdminCommonName,
		OrganizationalUnit: DefaultOrganizationalUnit,
		Organization:       DefaultOrganization,
		Locality:           DefaultLocality,
		State:              DefaultState,
		Country:            DefaultCountry,
	}
}

// AdminDN returns the admin Distinguished Name using the given options
func AdminDN(opts DNOptions) string {
	// Apply defaults for any empty values
	if opts.CommonName == "" {
		opts.CommonName = DefaultAdminCommonName
	}
	if opts.OrganizationalUnit == "" {
		opts.OrganizationalUnit = DefaultOrganizationalUnit
	}
	if opts.Organization == "" {
		opts.Organization = DefaultOrganization
	}
	if opts.Locality == "" {
		opts.Locality = DefaultLocality
	}
	if opts.State == "" {
		opts.State = DefaultState
	}
	if opts.Country == "" {
		opts.Country = DefaultCountry
	}
	return FormatDN(opts.CommonName, opts.OrganizationalUnit, opts.Organization,
		opts.Locality, opts.State, opts.Country)
}

// NodesDN returns the nodes Distinguished Name pattern using the given options
// Uses wildcard CN=* to match any node certificate
func NodesDN(opts DNOptions) string {
	// Apply defaults for any empty values
	if opts.OrganizationalUnit == "" {
		opts.OrganizationalUnit = DefaultOrganizationalUnit
	}
	if opts.Organization == "" {
		opts.Organization = DefaultOrganization
	}
	if opts.Locality == "" {
		opts.Locality = DefaultLocality
	}
	if opts.State == "" {
		opts.State = DefaultState
	}
	if opts.Country == "" {
		opts.Country = DefaultCountry
	}
	return FormatDN("*", opts.OrganizationalUnit, opts.Organization,
		opts.Locality, opts.State, opts.Country)
}

// CAResult contains the generated CA certificate and private key
type CAResult struct {
	Certificate    *x509.Certificate
	PrivateKey     crypto.PrivateKey
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

// GenerateCA generates a new CA certificate and private key
func GenerateCA(config *CAConfig) (*CAResult, error) {
	if config == nil {
		return nil, fmt.Errorf("CA config is required")
	}

	if config.CommonName == "" {
		return nil, fmt.Errorf("common name is required")
	}

	// Apply defaults for empty fields
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
		config.Validity = MustParseCertDuration(DefaultCAValidityStr)
	}
	if config.KeySize <= 0 {
		config.KeySize = DefaultKeySize
	}

	// Generate private key based on algorithm
	privateKey, err := GeneratePrivateKey(config.KeyAlgorithm, config.KeySize, config.ECDSACurve)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Calculate validity period
	notBefore := time.Now()
	notAfter := notBefore.Add(config.Validity)

	// Create CA certificate template
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
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}

	// Self-sign the CA certificate
	publicKey := GetPublicKey(privateKey)
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Parse the certificate to get the x509.Certificate object
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyPEM, err := EncodePrivateKeyToPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	return &CAResult{
		Certificate:    cert,
		PrivateKey:     privateKey,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
	}, nil
}

// ParseCA parses a CA certificate and private key from PEM data
func ParseCA(certPEM, keyPEM []byte) (*CAResult, error) {
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
	privateKey, err := ParsePrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &CAResult{
		Certificate:    cert,
		PrivateKey:     privateKey,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
	}, nil
}

// GenerateSerialNumber generates a random serial number for certificates
func GenerateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

// IsExpired checks if the CA certificate is expired
func (ca *CAResult) IsExpired() bool {
	return time.Now().After(ca.Certificate.NotAfter)
}

// NeedsRenewal checks if the CA certificate needs renewal
// The threshold parameter specifies how long before expiry to trigger renewal
func (ca *CAResult) NeedsRenewal(threshold time.Duration) bool {
	renewalTime := ca.Certificate.NotAfter.Add(-threshold)
	return time.Now().After(renewalTime)
}

// DaysUntilExpiry returns the number of days until the certificate expires
func (ca *CAResult) DaysUntilExpiry() int {
	duration := time.Until(ca.Certificate.NotAfter)
	return int(duration.Hours() / 24)
}

// GetCertificateExpiry extracts the expiry time from a PEM-encoded certificate
func GetCertificateExpiry(certPEM []byte) (time.Time, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return time.Time{}, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.NotAfter, nil
}
