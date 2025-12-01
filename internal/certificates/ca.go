/*
Copyright 2025.

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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

const (
	// DefaultCAValidityDays is the default validity period for CA certificates
	DefaultCAValidityDays = 3650 // 10 years

	// DefaultKeySize is the default RSA key size
	DefaultKeySize = 2048

	// DefaultOrganization is the default organization name
	DefaultOrganization = "Wazuh"

	// DefaultOrganizationalUnit is the default organizational unit
	DefaultOrganizationalUnit = "Wazuh"

	// DefaultCountry is the default country code
	DefaultCountry = "US"

	// DefaultState is the default state/province
	DefaultState = "California"

	// DefaultLocality is the default city/locality
	DefaultLocality = "California"
)

// CAConfig holds configuration for CA certificate generation
type CAConfig struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	State              string
	Locality           string
	ValidityDays       int
	ValidityMinutes    int // For testing short-lived certs (takes precedence over ValidityDays if > 0)
	KeySize            int
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
		ValidityDays:       DefaultCAValidityDays,
		KeySize:            DefaultKeySize,
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

// CAResult contains the generated CA certificate and private key
type CAResult struct {
	Certificate    *x509.Certificate
	PrivateKey     *rsa.PrivateKey
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
	if config.ValidityDays <= 0 {
		config.ValidityDays = DefaultCAValidityDays
	}
	if config.KeySize <= 0 {
		config.KeySize = DefaultKeySize
	}

	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, config.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Generate serial number
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Calculate validity period
	notBefore := time.Now()
	var notAfter time.Time
	if config.ValidityMinutes > 0 {
		// Use minutes for testing short-lived certificates
		notAfter = notBefore.Add(time.Duration(config.ValidityMinutes) * time.Minute)
	} else {
		notAfter = notBefore.AddDate(0, 0, config.ValidityDays)
	}

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
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
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
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

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
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	var privateKey *rsa.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
		}
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", keyBlock.Type)
	}

	return &CAResult{
		Certificate:    cert,
		PrivateKey:     privateKey,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
	}, nil
}

// generateSerialNumber generates a random serial number for certificates
func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

// IsExpired checks if the CA certificate is expired
func (ca *CAResult) IsExpired() bool {
	return time.Now().After(ca.Certificate.NotAfter)
}

// NeedsRenewal checks if the CA certificate needs renewal
func (ca *CAResult) NeedsRenewal(renewBeforeDays int) bool {
	renewalTime := ca.Certificate.NotAfter.AddDate(0, 0, -renewBeforeDays)
	return time.Now().After(renewalTime)
}

// DaysUntilExpiry returns the number of days until the certificate expires
func (ca *CAResult) DaysUntilExpiry() int {
	duration := time.Until(ca.Certificate.NotAfter)
	return int(duration.Hours() / 24)
}

// NeedsRenewalMinutes checks if the CA certificate needs renewal based on minutes
// Useful for testing short-lived certificates
func (ca *CAResult) NeedsRenewalMinutes(renewBeforeMinutes int) bool {
	renewalTime := ca.Certificate.NotAfter.Add(-time.Duration(renewBeforeMinutes) * time.Minute)
	return time.Now().After(renewalTime)
}

// MinutesUntilExpiry returns the number of minutes until the certificate expires
func (ca *CAResult) MinutesUntilExpiry() int {
	duration := time.Until(ca.Certificate.NotAfter)
	return int(duration.Minutes())
}
