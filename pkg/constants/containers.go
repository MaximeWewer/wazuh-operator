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

// Container names used in pod specs
const (
	// ContainerNameWazuhManager is the container name for Wazuh manager
	ContainerNameWazuhManager = "wazuh-manager"

	// ContainerNameOpenSearch is the container name for OpenSearch indexer
	ContainerNameOpenSearch = "opensearch"

	// ContainerNameDashboard is the container name for OpenSearch dashboard
	ContainerNameDashboard = "opensearch-dashboards"

	// ContainerNameFilebeat is the container name for Filebeat sidecar
	ContainerNameFilebeat = "filebeat"
)

// Init container names
const (
	// InitContainerNameSysctl is the init container for sysctl settings
	InitContainerNameSysctl = "sysctl"

	// InitContainerNamePermissions is the init container for permission fixes
	InitContainerNamePermissions = "fix-permissions"

	// InitContainerNameSecurityConfig is the init container for security config
	InitContainerNameSecurityConfig = "security-config"
)
