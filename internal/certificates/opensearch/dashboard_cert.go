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

package opensearchcerts

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"time"

	certcommon "github.com/MaximeWewer/wazuh-operator/internal/certificates/common"
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
	Validity           time.Duration
	KeySize            int
	KeyAlgorithm       certcommon.KeyAlgorithm
	ECDSACurve         certcommon.ECDSACurve
	DNSNames           []string
	IPAddresses        []net.IP
}

// DefaultDashboardCertConfig returns a DashboardCertConfig with default values
func DefaultDashboardCertConfig() *DashboardCertConfig {
	return &DashboardCertConfig{
		CommonName:         DefaultDashboardCommonName,
		Organization:       certcommon.DefaultOrganization,
		OrganizationalUnit: certcommon.DefaultOrganizationalUnit,
		Country:            certcommon.DefaultCountry,
		State:              certcommon.DefaultState,
		Locality:           certcommon.DefaultLocality,
		Validity:           certcommon.MustParseCertDuration(certcommon.DefaultNodeValidityStr),
		KeySize:            certcommon.DefaultKeySize,
		KeyAlgorithm:       certcommon.KeyAlgorithmRSA,
		ECDSACurve:         certcommon.ECDSACurveP256,
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
func GenerateDashboardCert(config *DashboardCertConfig, ca *certcommon.CAResult) (*DashboardCertResult, error) {
	if config == nil {
		return nil, fmt.Errorf("dashboard cert config is required")
	}

	if ca == nil {
		return nil, fmt.Errorf("CA is required")
	}

	if config.CommonName == "" {
		config.CommonName = DefaultDashboardCommonName
	}
	if config.Organization == "" {
		config.Organization = certcommon.DefaultOrganization
	}
	if config.OrganizationalUnit == "" {
		config.OrganizationalUnit = certcommon.DefaultOrganizationalUnit
	}
	if config.Country == "" {
		config.Country = certcommon.DefaultCountry
	}
	if config.State == "" {
		config.State = certcommon.DefaultState
	}
	if config.Locality == "" {
		config.Locality = certcommon.DefaultLocality
	}
	if config.Validity <= 0 {
		config.Validity = certcommon.MustParseCertDuration(certcommon.DefaultNodeValidityStr)
	}
	if config.KeySize <= 0 {
		config.KeySize = certcommon.DefaultKeySize
	}

	privateKey, err := certcommon.GeneratePrivateKey(config.KeyAlgorithm, config.KeySize, config.ECDSACurve)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumber, err := certcommon.GenerateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(config.Validity)

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

	publicKey := certcommon.GetPublicKey(privateKey)
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, publicKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create dashboard certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dashboard certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM, err := certcommon.EncodePrivateKeyToPEM(privateKey)
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

// ParseDashboardCert parses a dashboard certificate and private key from PEM data
func ParseDashboardCert(certPEM, keyPEM []byte) (*DashboardCertResult, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	privateKey, err := certcommon.ParsePrivateKeyFromPEM(keyPEM)
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
func (d *DashboardCertResult) NeedsRenewal(threshold time.Duration) bool {
	renewalTime := d.Certificate.NotAfter.Add(-threshold)
	return time.Now().After(renewalTime)
}

// DaysUntilExpiry returns the number of days until the certificate expires
func (d *DashboardCertResult) DaysUntilExpiry() int {
	duration := time.Until(d.Certificate.NotAfter)
	return int(duration.Hours() / 24)
}

// GetCertificate returns the x509 certificate
func (d *DashboardCertResult) GetCertificate() *x509.Certificate { return d.Certificate }

// GetPrivateKey returns the private key
func (d *DashboardCertResult) GetPrivateKey() crypto.PrivateKey { return d.PrivateKey }

// GetCertificatePEM returns the PEM-encoded certificate
func (d *DashboardCertResult) GetCertificatePEM() []byte { return d.CertificatePEM }

// GetPrivateKeyPEM returns the PEM-encoded private key
func (d *DashboardCertResult) GetPrivateKeyPEM() []byte { return d.PrivateKeyPEM }
