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

// Init container images
const (
	// ImageBusyboxInit is the busybox image used for init containers (versioned)
	ImageBusyboxInit = "busybox:1.36"

	// ImageBusyboxStable is the stable busybox image for utility containers
	ImageBusyboxStable = "busybox:stable"
)

// Monitoring images
const (
	// ImageWazuhExporter is the default Wazuh Prometheus exporter image
	ImageWazuhExporter = "kennyopennix/wazuh-exporter:latest"
)

// Exporter ports
const (
	// PortWazuhExporter is the default port for the Wazuh Prometheus exporter
	PortWazuhExporter int32 = 9090
)
