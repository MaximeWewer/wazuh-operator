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
	"net"
	"time"
)

const (
	// DefaultDashboardValidityDays is the default validity period for dashboard certificates
	DefaultDashboardValidityDays = 365

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
	ValidityDays       int
	ValidityMinutes    int // For testing short-lived certs (takes precedence over ValidityDays if > 0)
	KeySize            int
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
		ValidityDays:       DefaultDashboardValidityDays,
		KeySize:            DefaultKeySize,
		DNSNames:           []string{},
		IPAddresses:        []net.IP{},
	}
}

// DashboardCertResult contains the generated dashboard certificate and private key
type DashboardCertResult struct {
	Certificate    *x509.Certificate
	PrivateKey     *rsa.PrivateKey
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
	if config.ValidityDays <= 0 {
		config.ValidityDays = DefaultDashboardValidityDays
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
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, &privateKey.PublicKey, ca.PrivateKey)
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
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return &DashboardCertResult{
		Certificate:    cert,
		PrivateKey:     privateKey,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
	}, nil
}

// GenerateDashboardSANs generates Subject Alternative Names for dashboard
func GenerateDashboardSANs(clusterName, namespace string) []string {
	return []string{
		"localhost",
		fmt.Sprintf("%s-dashboard", clusterName),
		fmt.Sprintf("%s-dashboard.%s", clusterName, namespace),
		fmt.Sprintf("%s-dashboard.%s.svc", clusterName, namespace),
		fmt.Sprintf("%s-dashboard.%s.svc.cluster.local", clusterName, namespace),
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
func (d *DashboardCertResult) NeedsRenewal(renewBeforeDays int) bool {
	renewalTime := d.Certificate.NotAfter.AddDate(0, 0, -renewBeforeDays)
	return time.Now().After(renewalTime)
}

// DaysUntilExpiry returns the number of days until the certificate expires
func (d *DashboardCertResult) DaysUntilExpiry() int {
	duration := time.Until(d.Certificate.NotAfter)
	return int(duration.Hours() / 24)
}

// NeedsRenewalMinutes checks if the dashboard certificate needs renewal based on minutes
// Useful for testing short-lived certificates
func (d *DashboardCertResult) NeedsRenewalMinutes(renewBeforeMinutes int) bool {
	renewalTime := d.Certificate.NotAfter.Add(-time.Duration(renewBeforeMinutes) * time.Minute)
	return time.Now().After(renewalTime)
}

// MinutesUntilExpiry returns the number of minutes until the certificate expires
func (d *DashboardCertResult) MinutesUntilExpiry() int {
	duration := time.Until(d.Certificate.NotAfter)
	return int(duration.Minutes())
}
