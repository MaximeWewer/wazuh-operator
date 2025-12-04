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

	// CertTypeNode is the certificate type for node certificates
	CertTypeNode = "node"
)

// CertificateTypes is the list of certificate types
var CertificateTypes = []string{
	CertTypeCA,
	CertTypeNode,
}

// Default certificate common names
const (
	// DefaultAdminCertCommonName is the default common name for admin certificates
	DefaultAdminCertCommonName = "admin"

	// DefaultKibanaServerCertCommonName is the default common name for kibanaserver certificates
	DefaultKibanaServerCertCommonName = "kibanaserver"
)

// Certificate validity defaults
const (
	// DefaultCACertValidityYears is the default validity period for CA certificates
	DefaultCACertValidityYears = 10

	// DefaultCACertValidityDays is the default validity period for CA certificates in days (10 years)
	DefaultCACertValidityDays = 3650

	// DefaultNodeCertValidityDays is the default validity period for node certificates (1 year)
	DefaultNodeCertValidityDays = 365

	// DefaultAdminCertValidityDays is the default validity period for admin certificates
	DefaultAdminCertValidityDays = 365

	// DefaultDashboardCertValidityDays is the default validity period for dashboard certificates
	DefaultDashboardCertValidityDays = 365

	// DefaultFilebeatCertValidityDays is the default validity period for filebeat certificates
	DefaultFilebeatCertValidityDays = 365

	// DefaultCertRenewalThresholdDays is the default threshold for certificate renewal
	DefaultCertRenewalThresholdDays = 30
)

// Certificate renewal thresholds
const (
	// CertRenewalThresholdCADays is the threshold in days before CA certificate expiry to trigger renewal
	CertRenewalThresholdCADays = 60

	// CertRenewalThresholdNodeDays is the threshold in days before node certificate expiry to trigger renewal
	CertRenewalThresholdNodeDays = 30
)

// Test mode certificate durations (in minutes)
const (
	// TestModeCAValidityMinutes is the CA certificate validity in test mode
	TestModeCAValidityMinutes = 15

	// TestModeNodeValidityMinutes is the node certificate validity in test mode
	TestModeNodeValidityMinutes = 8

	// TestModeCARenewalThresholdMinutes is the CA renewal threshold in test mode
	TestModeCARenewalThresholdMinutes = 5

	// TestModeNodeRenewalThresholdMinutes is the node renewal threshold in test mode
	TestModeNodeRenewalThresholdMinutes = 3
)
