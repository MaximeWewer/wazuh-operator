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
	// DefaultNodeValidityDays is the default validity period for node certificates
	DefaultNodeValidityDays = 365
)

// NodeCertConfig holds configuration for node certificate generation
type NodeCertConfig struct {
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

// DefaultNodeCertConfig returns a NodeCertConfig with default values
func DefaultNodeCertConfig(commonName string) *NodeCertConfig {
	return &NodeCertConfig{
		CommonName:         commonName,
		Organization:       DefaultOrganization,
		OrganizationalUnit: DefaultOrganizationalUnit,
		Country:            DefaultCountry,
		State:              DefaultState,
		Locality:           DefaultLocality,
		ValidityDays:       DefaultNodeValidityDays,
		KeySize:            DefaultKeySize,
		DNSNames:           []string{},
		IPAddresses:        []net.IP{},
	}
}

// NodeCertResult contains the generated node certificate and private key
type NodeCertResult struct {
	Certificate    *x509.Certificate
	PrivateKey     *rsa.PrivateKey
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
	if config.ValidityDays <= 0 {
		config.ValidityDays = DefaultNodeValidityDays
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
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return &NodeCertResult{
		Certificate:    cert,
		PrivateKey:     privateKey,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
	}, nil
}

// GenerateIndexerNodeSANs generates Subject Alternative Names for indexer nodes
func GenerateIndexerNodeSANs(clusterName, namespace string, replicas int32) []string {
	sans := []string{
		"localhost",
		fmt.Sprintf("%s-indexer", clusterName),
		fmt.Sprintf("%s-indexer.%s", clusterName, namespace),
		fmt.Sprintf("%s-indexer.%s.svc", clusterName, namespace),
		fmt.Sprintf("%s-indexer.%s.svc.cluster.local", clusterName, namespace),
		fmt.Sprintf("*.%s-indexer-headless.%s.svc.cluster.local", clusterName, namespace),
	}

	// Add individual pod names
	for i := int32(0); i < replicas; i++ {
		podName := fmt.Sprintf("%s-indexer-%d", clusterName, i)
		sans = append(sans, podName)
		sans = append(sans, fmt.Sprintf("%s.%s-indexer-headless.%s.svc.cluster.local", podName, clusterName, namespace))
	}

	return sans
}

// GenerateManagerNodeSANs generates Subject Alternative Names for manager nodes
func GenerateManagerNodeSANs(clusterName, namespace string, workerReplicas int32) []string {
	sans := []string{
		"localhost",
		// Master node
		fmt.Sprintf("%s-manager-master", clusterName),
		fmt.Sprintf("%s-manager-master.%s", clusterName, namespace),
		fmt.Sprintf("%s-manager-master.%s.svc", clusterName, namespace),
		fmt.Sprintf("%s-manager-master.%s.svc.cluster.local", clusterName, namespace),
		fmt.Sprintf("%s-manager-master-0", clusterName),
		fmt.Sprintf("%s-manager-master-0.%s-manager-master.%s.svc.cluster.local", clusterName, clusterName, namespace),
		// Worker nodes service
		fmt.Sprintf("%s-manager-workers", clusterName),
		fmt.Sprintf("%s-manager-workers.%s", clusterName, namespace),
		fmt.Sprintf("%s-manager-workers.%s.svc", clusterName, namespace),
		fmt.Sprintf("%s-manager-workers.%s.svc.cluster.local", clusterName, namespace),
	}

	// Add individual worker pod names
	for i := int32(0); i < workerReplicas; i++ {
		podName := fmt.Sprintf("%s-manager-workers-%d", clusterName, i)
		sans = append(sans, podName)
		sans = append(sans, fmt.Sprintf("%s.%s-manager-workers.%s.svc.cluster.local", podName, clusterName, namespace))
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
func (n *NodeCertResult) NeedsRenewal(renewBeforeDays int) bool {
	renewalTime := n.Certificate.NotAfter.AddDate(0, 0, -renewBeforeDays)
	return time.Now().After(renewalTime)
}

// NeedsRenewalMinutes checks if the node certificate needs renewal based on minutes
// Useful for testing short-lived certificates
func (n *NodeCertResult) NeedsRenewalMinutes(renewBeforeMinutes int) bool {
	renewalTime := n.Certificate.NotAfter.Add(-time.Duration(renewBeforeMinutes) * time.Minute)
	return time.Now().After(renewalTime)
}

// MinutesUntilExpiry returns the number of minutes until the certificate expires
func (n *NodeCertResult) MinutesUntilExpiry() int {
	duration := time.Until(n.Certificate.NotAfter)
	return int(duration.Minutes())
}

// DaysUntilExpiry returns the number of days until the certificate expires
func (n *NodeCertResult) DaysUntilExpiry() int {
	duration := time.Until(n.Certificate.NotAfter)
	return int(duration.Hours() / 24)
}
