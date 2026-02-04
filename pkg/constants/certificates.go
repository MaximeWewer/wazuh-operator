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

package constants

// Certificate component names used for metrics and tracking
const (
	// CertComponentCA is the component name for CA certificate
	CertComponentCA = "ca"

	// CertComponentIndexer is the component name for indexer certificates
	CertComponentIndexer = "indexer"

	// CertComponentManagerMaster is the component name for manager master certificates
	CertComponentManagerMaster = "manager-master"

	// CertComponentManagerWorker is the component name for manager worker certificates
	CertComponentManagerWorker = "manager-worker"

	// CertComponentDashboard is the component name for dashboard certificates
	CertComponentDashboard = "dashboard"

	// CertComponentFilebeat is the component name for filebeat certificates
	CertComponentFilebeat = "filebeat"

	// CertComponentAdmin is the component name for admin certificates
	CertComponentAdmin = "admin"
)

// CertificateComponents is the list of all certificate components
var CertificateComponents = []string{
	CertComponentCA,
	CertComponentIndexer,
	CertComponentManagerMaster,
	CertComponentManagerWorker,
	CertComponentDashboard,
	CertComponentFilebeat,
	CertComponentAdmin,
}

// Certificate types
const (
	// CertTypeCA is the certificate type for CA
	CertTypeCA = "ca"

	// CertTypeNode is the certificate type for node/indexer certificates
	CertTypeNode = "node"

	// CertTypeAdmin is the certificate type for admin certificates
	CertTypeAdmin = "admin"

	// CertTypeFilebeat is the certificate type for filebeat certificates
	CertTypeFilebeat = "filebeat"

	// CertTypeDashboard is the certificate type for dashboard certificates
	CertTypeDashboard = "dashboard"
)

// CertificateTypes is the list of all certificate types
var CertificateTypes = []string{
	CertTypeCA,
	CertTypeNode,
	CertTypeAdmin,
	CertTypeFilebeat,
	CertTypeDashboard,
}

// Default certificate common names
const (
	// DefaultAdminCertCommonName is the default common name for admin certificates
	DefaultAdminCertCommonName = "admin"

	// DefaultKibanaServerCertCommonName is the default common name for kibanaserver certificates
	DefaultKibanaServerCertCommonName = "kibanaserver"
)

// Certificate validity defaults (duration strings)
// Use internal/certificates.ParseCertDuration() to parse these values
const (
	// DefaultCACertValidity is the default validity period for CA certificates (10 years)
	DefaultCACertValidity = "3650d"

	// DefaultNodeCertValidity is the default validity period for node certificates (1 year)
	DefaultNodeCertValidity = "365d"

	// DefaultAdminCertValidity is the default validity period for admin certificates (1 year)
	DefaultAdminCertValidity = "365d"

	// DefaultDashboardCertValidity is the default validity period for dashboard certificates (1 year)
	DefaultDashboardCertValidity = "365d"

	// DefaultFilebeatCertValidity is the default validity period for filebeat certificates (1 year)
	DefaultFilebeatCertValidity = "365d"

	// DefaultCertRenewalThreshold is the default threshold for certificate renewal (30 days)
	DefaultCertRenewalThreshold = "30d"
)

// Certificate renewal thresholds (duration strings)
const (
	// CertRenewalThresholdCA is the threshold before CA certificate expiry to trigger renewal (60 days)
	CertRenewalThresholdCA = "60d"

	// CertRenewalThresholdNode is the threshold before node certificate expiry to trigger renewal (30 days)
	CertRenewalThresholdNode = "30d"
)
