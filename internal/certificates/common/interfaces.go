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
	"crypto/x509"
	"time"
)

// CertificateResult is the common interface for all certificate generation results.
// All certificate types (CA, Node, Admin, Dashboard, Filebeat) implement this interface.
type CertificateResult interface {
	// IsExpired checks if the certificate has expired
	IsExpired() bool
	// NeedsRenewal checks if the certificate needs renewal given a threshold duration
	NeedsRenewal(threshold time.Duration) bool
	// DaysUntilExpiry returns the number of days until the certificate expires
	DaysUntilExpiry() int
	// GetCertificate returns the x509 certificate
	GetCertificate() *x509.Certificate
	// GetPrivateKey returns the private key
	GetPrivateKey() crypto.PrivateKey
	// GetCertificatePEM returns the PEM-encoded certificate
	GetCertificatePEM() []byte
	// GetPrivateKeyPEM returns the PEM-encoded private key
	GetPrivateKeyPEM() []byte
}

// Ensure CAResult implements CertificateResult
var _ CertificateResult = (*CAResult)(nil)

// GetCertificate returns the x509 certificate
func (ca *CAResult) GetCertificate() *x509.Certificate {
	return ca.Certificate
}

// GetPrivateKey returns the private key
func (ca *CAResult) GetPrivateKey() crypto.PrivateKey {
	return ca.PrivateKey
}

// GetCertificatePEM returns the PEM-encoded certificate
func (ca *CAResult) GetCertificatePEM() []byte {
	return ca.CertificatePEM
}

// GetPrivateKeyPEM returns the PEM-encoded private key
func (ca *CAResult) GetPrivateKeyPEM() []byte {
	return ca.PrivateKeyPEM
}
