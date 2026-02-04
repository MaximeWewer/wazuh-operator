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

// Package certificates provides certificate generation utilities for the Wazuh operator.
// Domain-specific types are defined in subpackages (common, opensearch, wazuh).
// This file re-exports them for backward compatibility.
package certificates

import (
	"crypto/x509"
	"math/big"
	"time"

	"github.com/go-logr/logr"

	certcommon "github.com/MaximeWewer/wazuh-operator/internal/certificates/common"
	opensearchcerts "github.com/MaximeWewer/wazuh-operator/internal/certificates/opensearch"
	"github.com/MaximeWewer/wazuh-operator/internal/certificates/sans"
	wazuhcerts "github.com/MaximeWewer/wazuh-operator/internal/certificates/wazuh"
)

// --- Type aliases from certcommon ---

type (
	// CAConfig holds configuration for CA certificate generation
	CAConfig = certcommon.CAConfig
	// CAResult contains the generated CA certificate and private key
	CAResult = certcommon.CAResult
	// DNOptions holds the options for generating Distinguished Names
	DNOptions = certcommon.DNOptions
	// KeyAlgorithm represents the algorithm used for key generation
	KeyAlgorithm = certcommon.KeyAlgorithm
	// ECDSACurve represents the elliptic curve used for ECDSA
	ECDSACurve = certcommon.ECDSACurve
	// DomainValidationResult contains the result of a certificate domain validation
	DomainValidationResult = certcommon.DomainValidationResult
	// CertificateResult is the common interface for all certificate results
	CertificateResult = certcommon.CertificateResult
)

// --- Type aliases from opensearchcerts ---

type (
	// NodeCertConfig holds configuration for node certificate generation
	NodeCertConfig = opensearchcerts.NodeCertConfig
	// NodeCertResult contains the generated node certificate and private key
	NodeCertResult = opensearchcerts.NodeCertResult
	// AdminCertConfig holds configuration for admin certificate generation
	AdminCertConfig = opensearchcerts.AdminCertConfig
	// AdminCertResult contains the generated admin certificate and private key
	AdminCertResult = opensearchcerts.AdminCertResult
	// DashboardCertConfig holds configuration for dashboard certificate generation
	DashboardCertConfig = opensearchcerts.DashboardCertConfig
	// DashboardCertResult contains the generated dashboard certificate and private key
	DashboardCertResult = opensearchcerts.DashboardCertResult
)

// --- Type aliases from wazuhcerts ---

type (
	// FilebeatCertConfig holds configuration for filebeat certificate generation
	FilebeatCertConfig = wazuhcerts.FilebeatCertConfig
	// FilebeatCertResult contains the generated filebeat certificate and private key
	FilebeatCertResult = wazuhcerts.FilebeatCertResult
)

// --- Constant re-exports from certcommon ---

const (
	DefaultKeySize                 = certcommon.DefaultKeySize
	DefaultOrganization            = certcommon.DefaultOrganization
	DefaultOrganizationalUnit      = certcommon.DefaultOrganizationalUnit
	DefaultCountry                 = certcommon.DefaultCountry
	DefaultState                   = certcommon.DefaultState
	DefaultLocality                = certcommon.DefaultLocality
	DefaultAdminCommonName         = certcommon.DefaultAdminCommonName
	KeyAlgorithmRSA                = certcommon.KeyAlgorithmRSA
	KeyAlgorithmECDSA              = certcommon.KeyAlgorithmECDSA
	ECDSACurveP256                 = certcommon.ECDSACurveP256
	ECDSACurveP384                 = certcommon.ECDSACurveP384
	ECDSACurveP521                 = certcommon.ECDSACurveP521
	DefaultCAValidityStr           = certcommon.DefaultCAValidityStr
	DefaultNodeValidityStr         = certcommon.DefaultNodeValidityStr
	DefaultCARenewalThresholdStr   = certcommon.DefaultCARenewalThresholdStr
	DefaultNodeRenewalThresholdStr = certcommon.DefaultNodeRenewalThresholdStr
)

// --- Constant re-exports from opensearchcerts ---

const (
	DefaultDashboardCommonName = opensearchcerts.DefaultDashboardCommonName
)

// --- Constant re-exports from wazuhcerts ---

const (
	DefaultFilebeatCommonName = wazuhcerts.DefaultFilebeatCommonName
)

// ErrInvalidCertificatePEM is returned when the certificate PEM data is invalid.
var ErrInvalidCertificatePEM = certcommon.ErrInvalidCertificatePEM

// --- CA functions ---

// DefaultCAConfig returns a CAConfig with default values
func DefaultCAConfig(commonName string) *CAConfig {
	return certcommon.DefaultCAConfig(commonName)
}

// GenerateCA generates a new CA certificate and private key
func GenerateCA(config *CAConfig) (*CAResult, error) {
	return certcommon.GenerateCA(config)
}

// ParseCA parses a CA certificate and private key from PEM data
func ParseCA(certPEM, keyPEM []byte) (*CAResult, error) {
	return certcommon.ParseCA(certPEM, keyPEM)
}

// GetCertificateExpiry extracts the expiry time from a PEM-encoded certificate
func GetCertificateExpiry(certPEM []byte) (time.Time, error) {
	return certcommon.GetCertificateExpiry(certPEM)
}

// --- DN functions ---

// FormatDN formats a Distinguished Name string from the given components
func FormatDN(commonName, ou, org, locality, state, country string) string {
	return certcommon.FormatDN(commonName, ou, org, locality, state, country)
}

// DefaultAdminDN returns the default Distinguished Name for admin certificates
func DefaultAdminDN() string {
	return certcommon.DefaultAdminDN()
}

// DefaultNodesDN returns the default Distinguished Name pattern for node certificates
func DefaultNodesDN() string {
	return certcommon.DefaultNodesDN()
}

// DefaultDNOptions returns the default DN options
func DefaultDNOptions() DNOptions {
	return certcommon.DefaultDNOptions()
}

// AdminDN returns the admin Distinguished Name using the given options
func AdminDN(opts DNOptions) string {
	return certcommon.AdminDN(opts)
}

// NodesDN returns the nodes Distinguished Name pattern using the given options
func NodesDN(opts DNOptions) string {
	return certcommon.NodesDN(opts)
}

// --- Duration functions ---

// ParseCertDuration parses a duration string like "365d", "24h", "30m"
func ParseCertDuration(s string) (time.Duration, error) {
	return certcommon.ParseCertDuration(s)
}

// MustParseCertDuration parses a duration string and panics on error
func MustParseCertDuration(s string) time.Duration {
	return certcommon.MustParseCertDuration(s)
}

// FormatCertDuration formats a time.Duration as a human-readable string
func FormatCertDuration(d time.Duration) string {
	return certcommon.FormatCertDuration(d)
}

// DaysFromDuration converts a time.Duration to days (rounded down)
func DaysFromDuration(d time.Duration) int {
	return certcommon.DaysFromDuration(d)
}

// HoursFromDuration converts a time.Duration to hours (rounded down)
func HoursFromDuration(d time.Duration) int {
	return certcommon.HoursFromDuration(d)
}

// MinutesFromDuration converts a time.Duration to minutes (rounded down)
func MinutesFromDuration(d time.Duration) int {
	return certcommon.MinutesFromDuration(d)
}

// DurationFromDays converts days to time.Duration
func DurationFromDays(days int) time.Duration {
	return certcommon.DurationFromDays(days)
}

// DurationFromHours converts hours to time.Duration
func DurationFromHours(hours int) time.Duration {
	return certcommon.DurationFromHours(hours)
}

// DurationFromMinutes converts minutes to time.Duration
func DurationFromMinutes(minutes int) time.Duration {
	return certcommon.DurationFromMinutes(minutes)
}

// --- Domain validation functions ---

// CertificateDomainMismatch checks if a certificate's SANs match the configured cluster domain
func CertificateDomainMismatch(cert *x509.Certificate) bool {
	return certcommon.CertificateDomainMismatch(cert)
}

// ValidateCertificateDomain performs a detailed validation of certificate SANs
func ValidateCertificateDomain(cert *x509.Certificate) DomainValidationResult {
	return certcommon.ValidateCertificateDomain(cert)
}

// RequiresDomainRegeneration checks if a certificate needs regeneration due to domain mismatch
func RequiresDomainRegeneration(cert *x509.Certificate, secretName, namespace string, log logr.Logger) bool {
	return certcommon.RequiresDomainRegeneration(cert, secretName, namespace, log)
}

// ExtractDomainFromSAN extracts the cluster domain from a Kubernetes FQDN SAN
func ExtractDomainFromSAN(san string) (string, bool) {
	return certcommon.ExtractDomainFromSAN(san)
}

// ParseCertificateFromPEM parses a PEM-encoded certificate
func ParseCertificateFromPEM(certPEM []byte) (*x509.Certificate, error) {
	return certcommon.ParseCertificateFromPEM(certPEM)
}

// --- Key algorithm functions ---

// GenerateSerialNumber generates a random serial number for certificates
func GenerateSerialNumber() (*big.Int, error) {
	return certcommon.GenerateSerialNumber()
}

// --- OpenSearch node certificate functions ---

// DefaultNodeCertConfig returns a NodeCertConfig with default values
func DefaultNodeCertConfig(commonName string) *NodeCertConfig {
	return opensearchcerts.DefaultNodeCertConfig(commonName)
}

// GenerateNodeCert generates a node certificate signed by the CA
func GenerateNodeCert(config *NodeCertConfig, ca *CAResult) (*NodeCertResult, error) {
	return opensearchcerts.GenerateNodeCert(config, ca)
}

// ParseNodeCert parses a node certificate and private key from PEM data
func ParseNodeCert(certPEM, keyPEM []byte) (*NodeCertResult, error) {
	return opensearchcerts.ParseNodeCert(certPEM, keyPEM)
}

// --- SAN generation functions (from sans package) ---

// GenerateIndexerNodeSANs generates Subject Alternative Names for indexer nodes
func GenerateIndexerNodeSANs(clusterName, namespace string, replicas int32) []string {
	return sans.GenerateIndexerNodeSANs(clusterName, namespace, replicas)
}

// --- OpenSearch admin certificate functions ---

// DefaultAdminCertConfig returns an AdminCertConfig with default values
func DefaultAdminCertConfig() *AdminCertConfig {
	return opensearchcerts.DefaultAdminCertConfig()
}

// GenerateAdminCert generates an admin certificate signed by the CA
func GenerateAdminCert(config *AdminCertConfig, ca *CAResult) (*AdminCertResult, error) {
	return opensearchcerts.GenerateAdminCert(config, ca)
}

// ParseAdminCert parses an admin certificate and private key from PEM data
func ParseAdminCert(certPEM, keyPEM []byte) (*AdminCertResult, error) {
	return opensearchcerts.ParseAdminCert(certPEM, keyPEM)
}

// --- OpenSearch dashboard certificate functions ---

// DefaultDashboardCertConfig returns a DashboardCertConfig with default values
func DefaultDashboardCertConfig() *DashboardCertConfig {
	return opensearchcerts.DefaultDashboardCertConfig()
}

// GenerateDashboardCert generates a dashboard certificate signed by the CA
func GenerateDashboardCert(config *DashboardCertConfig, ca *CAResult) (*DashboardCertResult, error) {
	return opensearchcerts.GenerateDashboardCert(config, ca)
}

// GenerateDashboardSANs generates Subject Alternative Names for dashboard
func GenerateDashboardSANs(clusterName, namespace string) []string {
	return sans.GenerateDashboardSANs(clusterName, namespace)
}

// ParseDashboardCert parses a dashboard certificate and private key from PEM data
func ParseDashboardCert(certPEM, keyPEM []byte) (*DashboardCertResult, error) {
	return opensearchcerts.ParseDashboardCert(certPEM, keyPEM)
}

// --- Wazuh filebeat certificate functions ---

// DefaultFilebeatCertConfig returns a FilebeatCertConfig with default values
func DefaultFilebeatCertConfig() *FilebeatCertConfig {
	return wazuhcerts.DefaultFilebeatCertConfig()
}

// GenerateFilebeatCert generates a filebeat certificate signed by the CA
func GenerateFilebeatCert(config *FilebeatCertConfig, ca *CAResult) (*FilebeatCertResult, error) {
	return wazuhcerts.GenerateFilebeatCert(config, ca)
}

// GenerateFilebeatSANs generates Subject Alternative Names for filebeat
func GenerateFilebeatSANs(clusterName, namespace string, workerReplicas int32) []string {
	return sans.GenerateFilebeatSANs(clusterName, namespace, workerReplicas)
}

// ParseFilebeatCert parses a filebeat certificate and private key from PEM data
func ParseFilebeatCert(certPEM, keyPEM []byte) (*FilebeatCertResult, error) {
	return wazuhcerts.ParseFilebeatCert(certPEM, keyPEM)
}

// GenerateManagerNodeSANs generates Subject Alternative Names for manager nodes
func GenerateManagerNodeSANs(clusterName, namespace string, workerReplicas int32) []string {
	return sans.GenerateManagerNodeSANs(clusterName, namespace, workerReplicas)
}
