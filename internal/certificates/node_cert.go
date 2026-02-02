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

// Node certificate constants are defined in duration.go

// NodeCertConfig holds configuration for node certificate generation
type NodeCertConfig struct {
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

// DefaultNodeCertConfig returns a NodeCertConfig with default values
func DefaultNodeCertConfig(commonName string) *NodeCertConfig {
	return &NodeCertConfig{
		CommonName:         commonName,
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

// NodeCertResult contains the generated node certificate and private key
type NodeCertResult struct {
	Certificate    *x509.Certificate
	PrivateKey     crypto.PrivateKey
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

// GenerateNodeCert generates a node certificate signed by the CA
func GenerateNodeCert(config *NodeCertConfig, ca *CAResult) (*NodeCertResult, error) {
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
	keyPEM, err := encodePrivateKeyToPEM(privateKey)
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

// GenerateIndexerNodeSANs generates Subject Alternative Names for indexer nodes
func GenerateIndexerNodeSANs(clusterName, namespace string, replicas int32) []string {
	indexerService := clusterName + "-indexer"
	headlessService := clusterName + "-indexer-headless"

	sans := []string{
		"localhost",
		indexerService,
		fmt.Sprintf("%s.%s", indexerService, namespace),
		fmt.Sprintf("%s.%s.svc", indexerService, namespace),
		dns.ServiceFQDN(indexerService, namespace),
		dns.WildcardServiceFQDN(headlessService, namespace),
	}

	// Add individual pod names
	for i := int32(0); i < replicas; i++ {
		podName := fmt.Sprintf("%s-indexer-%d", clusterName, i)
		sans = append(sans, podName, dns.PodFQDN(podName, headlessService, namespace))
	}

	return sans
}

// GenerateManagerNodeSANs generates Subject Alternative Names for manager nodes
func GenerateManagerNodeSANs(clusterName, namespace string, workerReplicas int32) []string {
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
		// Worker nodes service
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

// ParseNodeCert parses a node certificate and private key from PEM data
func ParseNodeCert(certPEM, keyPEM []byte) (*NodeCertResult, error) {
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
// The threshold parameter specifies how long before expiry to trigger renewal
func (n *NodeCertResult) NeedsRenewal(threshold time.Duration) bool {
	renewalTime := n.Certificate.NotAfter.Add(-threshold)
	return time.Now().After(renewalTime)
}

// DaysUntilExpiry returns the number of days until the certificate expires
func (n *NodeCertResult) DaysUntilExpiry() int {
	duration := time.Until(n.Certificate.NotAfter)
	return int(duration.Hours() / 24)
}
