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
	// DefaultFilebeatCommonName is the default common name for filebeat certificates
	DefaultFilebeatCommonName = "filebeat"
)

// FilebeatCertConfig holds configuration for filebeat certificate generation
type FilebeatCertConfig struct {
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

// DefaultFilebeatCertConfig returns a FilebeatCertConfig with default values
func DefaultFilebeatCertConfig() *FilebeatCertConfig {
	return &FilebeatCertConfig{
		CommonName:         DefaultFilebeatCommonName,
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

// FilebeatCertResult contains the generated filebeat certificate and private key
type FilebeatCertResult struct {
	Certificate    *x509.Certificate
	PrivateKey     crypto.PrivateKey
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

// GenerateFilebeatCert generates a filebeat certificate signed by the CA
// Filebeat certificates are used for secure communication with OpenSearch
func GenerateFilebeatCert(config *FilebeatCertConfig, ca *CAResult) (*FilebeatCertResult, error) {
	if config == nil {
		return nil, fmt.Errorf("filebeat cert config is required")
	}

	if ca == nil {
		return nil, fmt.Errorf("CA is required")
	}

	// Apply defaults for empty fields
	if config.CommonName == "" {
		config.CommonName = DefaultFilebeatCommonName
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
	// Filebeat cert is client-only for connecting to OpenSearch
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
		DNSNames:              config.DNSNames,
		IPAddresses:           config.IPAddresses,
	}

	// Sign the certificate with the CA
	publicKey := getPublicKey(privateKey)
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, publicKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create filebeat certificate: %w", err)
	}

	// Parse the certificate to get the x509.Certificate object
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse filebeat certificate: %w", err)
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

	return &FilebeatCertResult{
		Certificate:    cert,
		PrivateKey:     privateKey,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
	}, nil
}

// GenerateFilebeatSANs generates Subject Alternative Names for filebeat
// Filebeat runs as sidecar in manager pods, so SANs include manager service names
func GenerateFilebeatSANs(clusterName, namespace string, workerReplicas int32) []string {
	masterService := clusterName + "-manager-master"
	workersService := clusterName + "-manager-workers"
	masterPod := clusterName + "-manager-master-0"

	sans := []string{
		"localhost",
		// Master node
		masterService,
		fmt.Sprintf("%s.%s", masterService, namespace),
		fmt.Sprintf("%s.%s.svc", masterService, namespace),
		dns.ServiceFQDN(masterService, namespace),
		masterPod,
		dns.PodFQDN(masterPod, masterService, namespace),
		// Worker nodes
		workersService,
		fmt.Sprintf("%s.%s", workersService, namespace),
		fmt.Sprintf("%s.%s.svc", workersService, namespace),
		dns.ServiceFQDN(workersService, namespace),
	}

	// Add individual worker pod names
	for i := int32(0); i < workerReplicas; i++ {
		podName := fmt.Sprintf("%s-manager-workers-%d", clusterName, i)
		sans = append(sans, podName, dns.PodFQDN(podName, workersService, namespace))
	}

	return sans
}

// ParseFilebeatCert parses a filebeat certificate and private key from PEM data
func ParseFilebeatCert(certPEM, keyPEM []byte) (*FilebeatCertResult, error) {
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

	return &FilebeatCertResult{
		Certificate:    cert,
		PrivateKey:     privateKey,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
	}, nil
}

// IsExpired checks if the filebeat certificate is expired
func (f *FilebeatCertResult) IsExpired() bool {
	return time.Now().After(f.Certificate.NotAfter)
}

// NeedsRenewal checks if the filebeat certificate needs renewal
// The threshold parameter specifies how long before expiry to trigger renewal
func (f *FilebeatCertResult) NeedsRenewal(threshold time.Duration) bool {
	renewalTime := f.Certificate.NotAfter.Add(-threshold)
	return time.Now().After(renewalTime)
}

// DaysUntilExpiry returns the number of days until the certificate expires
func (f *FilebeatCertResult) DaysUntilExpiry() int {
	duration := time.Until(f.Certificate.NotAfter)
	return int(duration.Hours() / 24)
}
