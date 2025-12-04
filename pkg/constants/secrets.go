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

// Generic secret key names for credentials
const (
	// SecretKeyUsername is the generic key for username in secrets
	SecretKeyUsername = "username"

	// SecretKeyPassword is the generic key for password in secrets
	SecretKeyPassword = "password"

	// SecretKeyKibanaPassword is the key for kibanaserver password
	SecretKeyKibanaPassword = "kibana-password"
)

// OpenSearch security configuration file keys
const (
	// SecretKeyInternalUsers is the key for internal_users.yml in security secrets
	SecretKeyInternalUsers = "internal_users.yml"

	// SecretKeyRoles is the key for roles.yml in security secrets
	SecretKeyRoles = "roles.yml"

	// SecretKeyRolesMapping is the key for roles_mapping.yml in security secrets
	SecretKeyRolesMapping = "roles_mapping.yml"

	// SecretKeyActionGroups is the key for action_groups.yml in security secrets
	SecretKeyActionGroups = "action_groups.yml"

	// SecretKeyTenants is the key for tenants.yml in security secrets
	SecretKeyTenants = "tenants.yml"

	// SecretKeySecurityConfig is the key for config.yml in security secrets
	SecretKeySecurityConfig = "config.yml"
)

// Certificate file keys in secrets
const (
	// SecretKeyRootCA is the key for root CA certificate (PEM format)
	SecretKeyRootCA = "root-ca.pem"

	// SecretKeyDashboardCert is the key for dashboard certificate
	SecretKeyDashboardCert = "dashboard.pem"

	// SecretKeyDashboardKey is the key for dashboard private key
	SecretKeyDashboardKey = "dashboard-key.pem"

	// SecretKeyAdminCert is the key for admin certificate
	SecretKeyAdminCert = "admin.crt"

	// SecretKeyAdminKey is the key for admin private key
	SecretKeyAdminKey = "admin.key"

	// SecretKeyNodeCert is the key for node certificate
	SecretKeyNodeCert = "node.crt"

	// SecretKeyNodeKey is the key for node private key
	SecretKeyNodeKey = "node.key"
)
