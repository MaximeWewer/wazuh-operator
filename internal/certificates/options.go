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

// Package certificates provides certificate generation utilities
package certificates

import (
	"time"
)

// CertificateOptions holds the certificate generation options from the CRD
// These options are used to configure certificate validity, renewal thresholds, and subject fields
type CertificateOptions struct {
	// CAValidity is the validity period for CA certificates
	// Default: 3650 days (10 years)
	CAValidity time.Duration

	// CARenewalThreshold is the duration before CA expiry to trigger renewal
	// Default: 60 days
	CARenewalThreshold time.Duration

	// NodeValidity is the validity period for node certificates (indexer)
	// Default: 365 days (1 year)
	NodeValidity time.Duration

	// RenewalThreshold is the duration before expiry to trigger renewal for node certs
	// Default: 30 days
	RenewalThreshold time.Duration

	// AdminValidity is the validity period for admin certificates
	// Admin certs are used for OpenSearch security API authentication
	// Default: 365 days (1 year)
	AdminValidity time.Duration

	// AdminRenewalThreshold is the duration before expiry to trigger renewal for admin certs
	// Default: 30 days
	AdminRenewalThreshold time.Duration

	// DashboardValidity is the validity period for dashboard certificates
	// Dashboard certs are used for HTTPS on the Wazuh Dashboard
	// Renewal requires dashboard pod restart
	// Default: 365 days (1 year)
	DashboardValidity time.Duration

	// DashboardRenewalThreshold is the duration before expiry to trigger renewal for dashboard certs
	// Default: 30 days
	DashboardRenewalThreshold time.Duration

	// FilebeatValidity is the validity period for filebeat certificates
	// Filebeat certs are used for TLS between managers and indexer
	// Renewal requires manager pod restart
	// Default: 365 days (1 year)
	FilebeatValidity time.Duration

	// FilebeatRenewalThreshold is the duration before expiry to trigger renewal for filebeat certs
	// Default: 30 days
	FilebeatRenewalThreshold time.Duration

	// Certificate Subject Fields (from CRD TLS.CertConfig)

	// Country is the country code for certificate subject (e.g., "US", "FR")
	// Default: "US"
	Country string

	// State is the state/province for certificate subject
	// Default: "California"
	State string

	// Locality is the city/locality for certificate subject
	// Default: "San Francisco"
	Locality string

	// Organization is the organization name for certificate subject
	// Default: "Wazuh"
	Organization string

	// OrganizationalUnit is the organizational unit for certificate subject
	// Default: "Security"
	OrganizationalUnit string

	// CommonName is the common name for certificates (may be overridden per cert)
	// Default: derived from cluster name
	CommonName string

	// KeyAlgorithm specifies the key algorithm to use (RSA or ECDSA)
	// Default: RSA
	KeyAlgorithm KeyAlgorithm

	// ECDSACurve specifies the ECDSA curve to use when KeyAlgorithm is ECDSA
	// Default: P256
	ECDSACurve ECDSACurve
}

// DefaultCertificateOptions returns the default certificate options
func DefaultCertificateOptions() *CertificateOptions {
	return &CertificateOptions{
		CAValidity:         MustParseCertDuration(DefaultCAValidityStr),
		CARenewalThreshold: MustParseCertDuration(DefaultCARenewalThresholdStr),
		NodeValidity:       MustParseCertDuration(DefaultNodeValidityStr),
		RenewalThreshold:   MustParseCertDuration(DefaultNodeRenewalThresholdStr),
		// Admin certificate defaults (same as node certs)
		AdminValidity:         MustParseCertDuration(DefaultNodeValidityStr),
		AdminRenewalThreshold: MustParseCertDuration(DefaultNodeRenewalThresholdStr),
		// Dashboard certificate defaults (same as node certs)
		DashboardValidity:         MustParseCertDuration(DefaultNodeValidityStr),
		DashboardRenewalThreshold: MustParseCertDuration(DefaultNodeRenewalThresholdStr),
		// Filebeat certificate defaults (same as node certs)
		FilebeatValidity:         MustParseCertDuration(DefaultNodeValidityStr),
		FilebeatRenewalThreshold: MustParseCertDuration(DefaultNodeRenewalThresholdStr),
		// Certificate subject defaults
		Country:            DefaultCountry,
		State:              DefaultState,
		Locality:           DefaultLocality,
		Organization:       DefaultOrganization,
		OrganizationalUnit: DefaultOrganizationalUnit,
		// Key algorithm defaults
		KeyAlgorithm: KeyAlgorithmRSA,
		ECDSACurve:   ECDSACurveP256,
	}
}

// GetCAValidity returns the CA validity period
func (o *CertificateOptions) GetCAValidity() time.Duration {
	if o.CAValidity > 0 {
		return o.CAValidity
	}
	return MustParseCertDuration(DefaultCAValidityStr)
}

// GetNodeValidity returns the node certificate validity period
func (o *CertificateOptions) GetNodeValidity() time.Duration {
	if o.NodeValidity > 0 {
		return o.NodeValidity
	}
	return MustParseCertDuration(DefaultNodeValidityStr)
}

// GetCARenewalThreshold returns the CA renewal threshold
func (o *CertificateOptions) GetCARenewalThreshold() time.Duration {
	if o.CARenewalThreshold > 0 {
		return o.CARenewalThreshold
	}
	return MustParseCertDuration(DefaultCARenewalThresholdStr)
}

// GetRenewalThreshold returns the node cert renewal threshold
func (o *CertificateOptions) GetRenewalThreshold() time.Duration {
	if o.RenewalThreshold > 0 {
		return o.RenewalThreshold
	}
	return MustParseCertDuration(DefaultNodeRenewalThresholdStr)
}

// GetAdminValidity returns the admin certificate validity period
func (o *CertificateOptions) GetAdminValidity() time.Duration {
	if o.AdminValidity > 0 {
		return o.AdminValidity
	}
	return MustParseCertDuration(DefaultNodeValidityStr)
}

// GetAdminRenewalThreshold returns the admin cert renewal threshold
func (o *CertificateOptions) GetAdminRenewalThreshold() time.Duration {
	if o.AdminRenewalThreshold > 0 {
		return o.AdminRenewalThreshold
	}
	return MustParseCertDuration(DefaultNodeRenewalThresholdStr)
}

// GetDashboardValidity returns the dashboard certificate validity period
func (o *CertificateOptions) GetDashboardValidity() time.Duration {
	if o.DashboardValidity > 0 {
		return o.DashboardValidity
	}
	return MustParseCertDuration(DefaultNodeValidityStr)
}

// GetDashboardRenewalThreshold returns the dashboard cert renewal threshold
func (o *CertificateOptions) GetDashboardRenewalThreshold() time.Duration {
	if o.DashboardRenewalThreshold > 0 {
		return o.DashboardRenewalThreshold
	}
	return MustParseCertDuration(DefaultNodeRenewalThresholdStr)
}

// GetFilebeatValidity returns the filebeat certificate validity period
func (o *CertificateOptions) GetFilebeatValidity() time.Duration {
	if o.FilebeatValidity > 0 {
		return o.FilebeatValidity
	}
	return MustParseCertDuration(DefaultNodeValidityStr)
}

// GetFilebeatRenewalThreshold returns the filebeat cert renewal threshold
func (o *CertificateOptions) GetFilebeatRenewalThreshold() time.Duration {
	if o.FilebeatRenewalThreshold > 0 {
		return o.FilebeatRenewalThreshold
	}
	return MustParseCertDuration(DefaultNodeRenewalThresholdStr)
}

// ShouldRenewCA checks if a CA certificate should be renewed based on options
func (o *CertificateOptions) ShouldRenewCA(ca *CAResult) bool {
	return ca.NeedsRenewal(o.GetCARenewalThreshold())
}

// ShouldRenewNode checks if a node certificate should be renewed based on options
func (o *CertificateOptions) ShouldRenewNode(cert *NodeCertResult) bool {
	return cert.NeedsRenewal(o.GetRenewalThreshold())
}

// ShouldRenewDashboard checks if a dashboard certificate should be renewed based on options
func (o *CertificateOptions) ShouldRenewDashboard(cert *DashboardCertResult) bool {
	return cert.NeedsRenewal(o.GetDashboardRenewalThreshold())
}

// ShouldRenewFilebeat checks if a filebeat certificate should be renewed based on options
func (o *CertificateOptions) ShouldRenewFilebeat(cert *FilebeatCertResult) bool {
	return cert.NeedsRenewal(o.GetFilebeatRenewalThreshold())
}

// ShouldRenewAdmin checks if an admin certificate should be renewed based on options
func (o *CertificateOptions) ShouldRenewAdmin(cert *AdminCertResult) bool {
	return cert.NeedsRenewal(o.GetAdminRenewalThreshold())
}
