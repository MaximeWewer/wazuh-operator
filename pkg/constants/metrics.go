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

// Metrics namespace and subsystems for Prometheus metrics
const (
	// MetricsNamespace is the namespace for all Wazuh operator metrics
	MetricsNamespace = "wazuh_operator"

	// MetricsSubsystemReconciler is the subsystem for reconciler metrics
	MetricsSubsystemReconciler = "reconciler"

	// MetricsSubsystemCluster is the subsystem for cluster metrics
	MetricsSubsystemCluster = "cluster"

	// MetricsSubsystemCertificate is the subsystem for certificate metrics
	MetricsSubsystemCertificate = "certificate"

	// MetricsSubsystemOpenSearch is the subsystem for OpenSearch-specific metrics
	MetricsSubsystemOpenSearch = "opensearch"

	// MetricsSubsystemWazuh is the subsystem for Wazuh-specific metrics
	MetricsSubsystemWazuh = "wazuh"
)

// Metrics result labels
const (
	// MetricsResultSuccess is the label value for successful operations
	MetricsResultSuccess = "success"

	// MetricsResultFailure is the label value for failed operations
	MetricsResultFailure = "failure"

	// MetricsResultSkipped is the label value for skipped operations
	MetricsResultSkipped = "skipped"
)
