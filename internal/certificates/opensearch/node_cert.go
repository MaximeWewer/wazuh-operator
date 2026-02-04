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

// NodeCertConfig holds configuration for node certificate generation.
// Used for OpenSearch indexer and manager node certificates.
type NodeCertConfig struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	State              string
	Locality           string
	Validity           time.Duration // Certificate validity as duration
	KeySize            int           // Only used for RSA
	KeyAlgorithm       certcommon.KeyAlgorithm
	ECDSACurve         certcommon.ECDSACurve
	DNSNames           []string
	IPAddresses        []net.IP
}

// DefaultNodeCertConfig returns a NodeCertConfig with default values
func DefaultNodeCertConfig(commonName string) *NodeCertConfig {
	return &NodeCertConfig{
		CommonName:         commonName,
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

// NodeCertResult contains the generated node certificate and private key
type NodeCertResult struct {
	Certificate    *x509.Certificate
	PrivateKey     crypto.PrivateKey
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

// GenerateNodeCert generates a node certificate signed by the CA
func GenerateNodeCert(config *NodeCertConfig, ca *certcommon.CAResult) (*NodeCertResult, error) {
	if config == nil {
		return nil, fmt.Errorf("node cert config is required")
	}

	if ca == nil {
		return nil, fmt.Errorf("CA is required")
	}

	if config.CommonName == "" {
		return nil, fmt.Errorf("common name is required")
	}

	// Apply defaults for empty fields
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

	// Generate private key based on algorithm
	privateKey, err := certcommon.GeneratePrivateKey(config.KeyAlgorithm, config.KeySize, config.ECDSACurve)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := certcommon.GenerateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Calculate validity period
	notBefore := time.Now()
	notAfter := notBefore.Add(config.Validity)

	// Create certificate template
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
	publicKey := certcommon.GetPublicKey(privateKey)
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, publicKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create node certificate: %w", err)
	}

	// Parse the certificate to get the x509.Certificate object
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse node certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyPEM, err := certcommon.EncodePrivateKeyToPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	return &NodeCertResult{
		Certificate:    cert,
		PrivateKey:     privateKey,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
	}, nil
}

// ParseNodeCert parses a node certificate and private key from PEM data
func ParseNodeCert(certPEM, keyPEM []byte) (*NodeCertResult, error) {
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

	return &NodeCertResult{
		Certificate:    cert,
		PrivateKey:     privateKey,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
	}, nil
}

// IsExpired checks if the node certificate is expired
func (n *NodeCertResult) IsExpired() bool {
	return time.Now().After(n.Certificate.NotAfter)
}

// NeedsRenewal checks if the node certificate needs renewal
func (n *NodeCertResult) NeedsRenewal(threshold time.Duration) bool {
	renewalTime := n.Certificate.NotAfter.Add(-threshold)
	return time.Now().After(renewalTime)
}

// DaysUntilExpiry returns the number of days until the certificate expires
func (n *NodeCertResult) DaysUntilExpiry() int {
	duration := time.Until(n.Certificate.NotAfter)
	return int(duration.Hours() / 24)
}

// GetCertificate returns the x509 certificate
func (n *NodeCertResult) GetCertificate() *x509.Certificate {
	return n.Certificate
}

// GetPrivateKey returns the private key
func (n *NodeCertResult) GetPrivateKey() crypto.PrivateKey {
	return n.PrivateKey
}

// GetCertificatePEM returns the PEM-encoded certificate
func (n *NodeCertResult) GetCertificatePEM() []byte {
	return n.CertificatePEM
}

// GetPrivateKeyPEM returns the PEM-encoded private key
func (n *NodeCertResult) GetPrivateKeyPEM() []byte {
	return n.PrivateKeyPEM
}
