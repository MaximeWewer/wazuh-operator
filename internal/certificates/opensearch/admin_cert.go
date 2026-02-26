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
	"time"

	certcommon "github.com/MaximeWewer/wazuh-operator/internal/certificates/common"
)

// AdminCertConfig holds configuration for admin certificate generation
type AdminCertConfig struct {
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
}

// DefaultAdminCertConfig returns an AdminCertConfig with default values
func DefaultAdminCertConfig() *AdminCertConfig {
	return &AdminCertConfig{
		CommonName:         certcommon.DefaultAdminCommonName,
		Organization:       certcommon.DefaultOrganization,
		OrganizationalUnit: certcommon.DefaultOrganizationalUnit,
		Country:            certcommon.DefaultCountry,
		State:              certcommon.DefaultState,
		Locality:           certcommon.DefaultLocality,
		Validity:           certcommon.MustParseCertDuration(certcommon.DefaultNodeValidityStr),
		KeySize:            certcommon.DefaultKeySize,
		KeyAlgorithm:       certcommon.KeyAlgorithmRSA,
		ECDSACurve:         certcommon.ECDSACurveP256,
	}
}

// AdminCertResult contains the generated admin certificate and private key
type AdminCertResult struct {
	Certificate    *x509.Certificate
	PrivateKey     crypto.PrivateKey
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

// GenerateAdminCert generates an admin certificate signed by the CA.
// Admin certificates are used for OpenSearch security management (securityadmin.sh).
func GenerateAdminCert(config *AdminCertConfig, ca *certcommon.CAResult) (*AdminCertResult, error) {
	if config == nil {
		return nil, fmt.Errorf("admin cert config is required")
	}

	if ca == nil {
		return nil, fmt.Errorf("CA is required")
	}

	// Apply defaults for empty fields
	if config.CommonName == "" {
		config.CommonName = certcommon.DefaultAdminCommonName
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
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{"localhost"},
		IPAddresses:           nil,
	}

	publicKey := certcommon.GetPublicKey(privateKey)
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, publicKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create admin certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse admin certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM, err := certcommon.EncodePrivateKeyToPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}
	keyPEM, err = certcommon.ConvertPrivateKeyPEMToPKCS8(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to convert admin private key to PKCS#8: %w", err)
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
func (a *AdminCertResult) NeedsRenewal(threshold time.Duration) bool {
	renewalTime := a.Certificate.NotAfter.Add(-threshold)
	return time.Now().After(renewalTime)
}

// DaysUntilExpiry returns the number of days until the certificate expires
func (a *AdminCertResult) DaysUntilExpiry() int {
	duration := time.Until(a.Certificate.NotAfter)
	return int(duration.Hours() / 24)
}

// GetCertificate returns the x509 certificate
func (a *AdminCertResult) GetCertificate() *x509.Certificate { return a.Certificate }

// GetPrivateKey returns the private key
func (a *AdminCertResult) GetPrivateKey() crypto.PrivateKey { return a.PrivateKey }

// GetCertificatePEM returns the PEM-encoded certificate
func (a *AdminCertResult) GetCertificatePEM() []byte { return a.CertificatePEM }

// GetPrivateKeyPEM returns the PEM-encoded private key
func (a *AdminCertResult) GetPrivateKeyPEM() []byte { return a.PrivateKeyPEM }
