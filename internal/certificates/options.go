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

// Package certificates provides certificate generation utilities
package certificates

import (
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// CertificateOptions holds the certificate generation options from the CRD
// These options are used to configure certificate validity, renewal thresholds, and subject fields
type CertificateOptions struct {
	// CAValidityDays is the validity period for CA certificates in days
	// Default: 3650 (10 years)
	CAValidityDays int

	// CARenewalThresholdDays is the number of days before CA expiry to trigger renewal
	// Default: 60
	CARenewalThresholdDays int

	// NodeValidityDays is the validity period for node certificates in days
	// Default: 365 (1 year)
	NodeValidityDays int

	// RenewalThresholdDays is the number of days before expiry to trigger renewal
	// Default: 30
	RenewalThresholdDays int

	// TestMode enables short-lived certificates for testing
	// When true, ValidityMinutes and RenewalThresholdMinutes are used instead
	TestMode bool

	// CAValidityMinutes is the CA validity period in minutes (only used in TestMode)
	// Default: 15
	CAValidityMinutes int

	// CARenewalThresholdMinutes is the CA renewal threshold in minutes (only used in TestMode)
	// Default: 5
	CARenewalThresholdMinutes int

	// ValidityMinutes is the node cert validity period in minutes (only used in TestMode)
	// Default: 8
	ValidityMinutes int

	// RenewalThresholdMinutes is the node cert renewal threshold in minutes (only used in TestMode)
	// Default: 3
	RenewalThresholdMinutes int

	// Certificate Subject Fields (from CRD TLS.CertConfig)

	// Country is the country code for certificate subject (e.g., "US", "FR")
	// Default: "US"
	Country string

	// State is the state/province for certificate subject
	// Default: "California"
	State string

	// Locality is the city/locality for certificate subject
	// Default: "California"
	Locality string

	// Organization is the organization name for certificate subject
	// Default: "Wazuh"
	Organization string

	// OrganizationalUnit is the organizational unit for certificate subject
	// Default: "Wazuh"
	OrganizationalUnit string

	// CommonName is the common name for certificates (may be overridden per cert)
	// Default: derived from cluster name
	CommonName string
}

// DefaultCertificateOptions returns the default certificate options
func DefaultCertificateOptions() *CertificateOptions {
	return &CertificateOptions{
		CAValidityDays:            DefaultCAValidityDays,
		CARenewalThresholdDays:    constants.CertRenewalThresholdCADays,
		NodeValidityDays:          DefaultNodeValidityDays,
		RenewalThresholdDays:      constants.CertRenewalThresholdNodeDays,
		TestMode:                  false,
		CAValidityMinutes:         constants.TestModeCAValidityMinutes,
		CARenewalThresholdMinutes: constants.TestModeCARenewalThresholdMinutes,
		ValidityMinutes:           constants.TestModeNodeValidityMinutes,
		RenewalThresholdMinutes:   constants.TestModeNodeRenewalThresholdMinutes,
		// Certificate subject defaults
		Country:            DefaultCountry,
		State:              DefaultState,
		Locality:           DefaultLocality,
		Organization:       DefaultOrganization,
		OrganizationalUnit: DefaultOrganizationalUnit,
	}
}

// TestModeCertificateOptions returns certificate options for test mode
func TestModeCertificateOptions() *CertificateOptions {
	return &CertificateOptions{
		CAValidityDays:            DefaultCAValidityDays,
		CARenewalThresholdDays:    constants.CertRenewalThresholdCADays,
		NodeValidityDays:          DefaultNodeValidityDays,
		RenewalThresholdDays:      constants.CertRenewalThresholdNodeDays,
		TestMode:                  true,
		CAValidityMinutes:         constants.TestModeCAValidityMinutes,
		CARenewalThresholdMinutes: constants.TestModeCARenewalThresholdMinutes,
		ValidityMinutes:           constants.TestModeNodeValidityMinutes,
		RenewalThresholdMinutes:   constants.TestModeNodeRenewalThresholdMinutes,
		// Certificate subject defaults
		Country:            DefaultCountry,
		State:              DefaultState,
		Locality:           DefaultLocality,
		Organization:       DefaultOrganization,
		OrganizationalUnit: DefaultOrganizationalUnit,
	}
}

// GetCAValidityDays returns the CA validity period based on options
func (o *CertificateOptions) GetCAValidityDays() int {
	if o.CAValidityDays > 0 {
		return o.CAValidityDays
	}
	return DefaultCAValidityDays
}

// GetNodeValidityDays returns the node certificate validity period based on options
func (o *CertificateOptions) GetNodeValidityDays() int {
	if o.NodeValidityDays > 0 {
		return o.NodeValidityDays
	}
	return DefaultNodeValidityDays
}

// GetCARenewalThresholdDays returns the CA renewal threshold in days
func (o *CertificateOptions) GetCARenewalThresholdDays() int {
	if o.CARenewalThresholdDays > 0 {
		return o.CARenewalThresholdDays
	}
	return constants.CertRenewalThresholdCADays
}

// GetRenewalThresholdDays returns the node cert renewal threshold in days
func (o *CertificateOptions) GetRenewalThresholdDays() int {
	if o.RenewalThresholdDays > 0 {
		return o.RenewalThresholdDays
	}
	return constants.CertRenewalThresholdNodeDays
}

// GetCAValidityMinutes returns the CA validity period in minutes for test mode
func (o *CertificateOptions) GetCAValidityMinutes() int {
	if o.CAValidityMinutes > 0 {
		return o.CAValidityMinutes
	}
	return constants.TestModeCAValidityMinutes
}

// GetCARenewalThresholdMinutes returns the CA renewal threshold in minutes for test mode
func (o *CertificateOptions) GetCARenewalThresholdMinutes() int {
	if o.CARenewalThresholdMinutes > 0 {
		return o.CARenewalThresholdMinutes
	}
	return constants.TestModeCARenewalThresholdMinutes
}

// GetValidityMinutes returns the node cert validity period in minutes for test mode
func (o *CertificateOptions) GetValidityMinutes() int {
	if o.ValidityMinutes > 0 {
		return o.ValidityMinutes
	}
	return constants.TestModeNodeValidityMinutes
}

// GetRenewalThresholdMinutes returns the node cert renewal threshold in minutes for test mode
func (o *CertificateOptions) GetRenewalThresholdMinutes() int {
	if o.RenewalThresholdMinutes > 0 {
		return o.RenewalThresholdMinutes
	}
	return constants.TestModeNodeRenewalThresholdMinutes
}

// ShouldRenewCA checks if a CA certificate should be renewed based on options
func (o *CertificateOptions) ShouldRenewCA(ca *CAResult) bool {
	if o.TestMode {
		return ca.NeedsRenewalMinutes(o.GetCARenewalThresholdMinutes())
	}
	return ca.NeedsRenewal(o.GetCARenewalThresholdDays())
}

// ShouldRenewNode checks if a node certificate should be renewed based on options
func (o *CertificateOptions) ShouldRenewNode(cert *NodeCertResult) bool {
	if o.TestMode {
		return cert.NeedsRenewalMinutes(o.GetRenewalThresholdMinutes())
	}
	return cert.NeedsRenewal(o.GetRenewalThresholdDays())
}

// ShouldRenewDashboard checks if a dashboard certificate should be renewed based on options
func (o *CertificateOptions) ShouldRenewDashboard(cert *DashboardCertResult) bool {
	if o.TestMode {
		return cert.NeedsRenewalMinutes(o.GetRenewalThresholdMinutes())
	}
	return cert.NeedsRenewal(o.GetRenewalThresholdDays())
}

// ShouldRenewFilebeat checks if a filebeat certificate should be renewed based on options
func (o *CertificateOptions) ShouldRenewFilebeat(cert *FilebeatCertResult) bool {
	if o.TestMode {
		return cert.NeedsRenewalMinutes(o.GetRenewalThresholdMinutes())
	}
	return cert.NeedsRenewal(o.GetRenewalThresholdDays())
}

// ShouldRenewAdmin checks if an admin certificate should be renewed based on options
func (o *CertificateOptions) ShouldRenewAdmin(cert *AdminCertResult) bool {
	if o.TestMode {
		return cert.NeedsRenewalMinutes(o.GetRenewalThresholdMinutes())
	}
	return cert.NeedsRenewal(o.GetRenewalThresholdDays())
}
