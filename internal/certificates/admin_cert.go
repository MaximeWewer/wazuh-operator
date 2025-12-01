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
	"time"
)

const (
	// DefaultAdminValidityDays is the default validity period for admin certificates
	DefaultAdminValidityDays = 365

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
	ValidityDays       int
	ValidityMinutes    int // For testing short-lived certs (takes precedence over ValidityDays if > 0)
	KeySize            int
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
		ValidityDays:       DefaultAdminValidityDays,
		KeySize:            DefaultKeySize,
	}
}

// AdminCertResult contains the generated admin certificate and private key
type AdminCertResult struct {
	Certificate    *x509.Certificate
	PrivateKey     *rsa.PrivateKey
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
	if config.ValidityDays <= 0 {
		config.ValidityDays = DefaultAdminValidityDays
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
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, &privateKey.PublicKey, ca.PrivateKey)
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
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

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
func (a *AdminCertResult) NeedsRenewal(renewBeforeDays int) bool {
	renewalTime := a.Certificate.NotAfter.AddDate(0, 0, -renewBeforeDays)
	return time.Now().After(renewalTime)
}

// DaysUntilExpiry returns the number of days until the certificate expires
func (a *AdminCertResult) DaysUntilExpiry() int {
	duration := time.Until(a.Certificate.NotAfter)
	return int(duration.Hours() / 24)
}

// NeedsRenewalMinutes checks if the admin certificate needs renewal based on minutes
// Useful for testing short-lived certificates
func (a *AdminCertResult) NeedsRenewalMinutes(renewBeforeMinutes int) bool {
	renewalTime := a.Certificate.NotAfter.Add(-time.Duration(renewBeforeMinutes) * time.Minute)
	return time.Now().After(renewalTime)
}

// MinutesUntilExpiry returns the number of minutes until the certificate expires
func (a *AdminCertResult) MinutesUntilExpiry() int {
	duration := time.Until(a.Certificate.NotAfter)
	return int(duration.Minutes())
}
