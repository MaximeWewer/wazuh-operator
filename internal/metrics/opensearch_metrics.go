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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// Re-export opensearch subsystem constant for backwards compatibility
const MetricsSubsystemOpenSearch = constants.MetricsSubsystemOpenSearch

var (
	// OpenSearchClusterHealth tracks the health of OpenSearch clusters
	OpenSearchClusterHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemOpenSearch,
			Name:      "cluster_health",
			Help:      "Health of OpenSearch clusters (2=green, 1=yellow, 0=red)",
		},
		[]string{"cluster", "namespace"},
	)

	// OpenSearchNodes tracks the number of OpenSearch nodes
	OpenSearchNodes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemOpenSearch,
			Name:      "nodes",
			Help:      "Number of OpenSearch nodes by status",
		},
		[]string{"cluster", "namespace", "status"},
	)

	// OpenSearchUsers tracks the number of security users
	OpenSearchUsers = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemOpenSearch,
			Name:      "users_total",
			Help:      "Total number of OpenSearch security users",
		},
		[]string{"cluster", "namespace"},
	)

	// OpenSearchRoles tracks the number of security roles
	OpenSearchRoles = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemOpenSearch,
			Name:      "roles_total",
			Help:      "Total number of OpenSearch security roles",
		},
		[]string{"cluster", "namespace"},
	)

	// OpenSearchIndices tracks the number of indices
	OpenSearchIndices = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemOpenSearch,
			Name:      "indices_total",
			Help:      "Total number of OpenSearch indices",
		},
		[]string{"cluster", "namespace"},
	)

	// OpenSearchISMPolicies tracks the number of ISM policies
	OpenSearchISMPolicies = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemOpenSearch,
			Name:      "ism_policies_total",
			Help:      "Total number of OpenSearch ISM policies",
		},
		[]string{"cluster", "namespace"},
	)

	// OpenSearchAPILatency tracks API call latency
	OpenSearchAPILatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemOpenSearch,
			Name:      "api_latency_seconds",
			Help:      "Latency of OpenSearch API calls in seconds",
			Buckets:   prometheus.ExponentialBuckets(0.001, 2, 15), // 1ms to ~30s
		},
		[]string{"cluster", "namespace", "operation"},
	)

	// OpenSearchAPIErrors tracks API errors
	OpenSearchAPIErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemOpenSearch,
			Name:      "api_errors_total",
			Help:      "Total number of OpenSearch API errors",
		},
		[]string{"cluster", "namespace", "operation", "status_code"},
	)
)

// RegisterOpenSearchMetrics registers OpenSearch-specific metrics
func RegisterOpenSearchMetrics() {
	metrics.Registry.MustRegister(
		OpenSearchClusterHealth,
		OpenSearchNodes,
		OpenSearchUsers,
		OpenSearchRoles,
		OpenSearchIndices,
		OpenSearchISMPolicies,
		OpenSearchAPILatency,
		OpenSearchAPIErrors,
	)
}

// HealthStatus represents OpenSearch cluster health
type HealthStatus int

const (
	HealthRed    HealthStatus = 0
	HealthYellow HealthStatus = 1
	HealthGreen  HealthStatus = 2
)

// SetOpenSearchClusterHealth sets the OpenSearch cluster health
func SetOpenSearchClusterHealth(cluster, namespace string, health HealthStatus) {
	OpenSearchClusterHealth.WithLabelValues(cluster, namespace).Set(float64(health))
}

// SetOpenSearchNodes sets the node count
func SetOpenSearchNodes(cluster, namespace, status string, count int) {
	OpenSearchNodes.WithLabelValues(cluster, namespace, status).Set(float64(count))
}

// SetOpenSearchUsers sets the user count
func SetOpenSearchUsers(cluster, namespace string, count int) {
	OpenSearchUsers.WithLabelValues(cluster, namespace).Set(float64(count))
}

// SetOpenSearchRoles sets the role count
func SetOpenSearchRoles(cluster, namespace string, count int) {
	OpenSearchRoles.WithLabelValues(cluster, namespace).Set(float64(count))
}

// SetOpenSearchIndices sets the index count
func SetOpenSearchIndices(cluster, namespace string, count int) {
	OpenSearchIndices.WithLabelValues(cluster, namespace).Set(float64(count))
}

// SetOpenSearchISMPolicies sets the ISM policy count
func SetOpenSearchISMPolicies(cluster, namespace string, count int) {
	OpenSearchISMPolicies.WithLabelValues(cluster, namespace).Set(float64(count))
}

// RecordOpenSearchAPILatency records API call latency
func RecordOpenSearchAPILatency(cluster, namespace, operation string, seconds float64) {
	OpenSearchAPILatency.WithLabelValues(cluster, namespace, operation).Observe(seconds)
}

// RecordOpenSearchAPIError records an API error
func RecordOpenSearchAPIError(cluster, namespace, operation, statusCode string) {
	OpenSearchAPIErrors.WithLabelValues(cluster, namespace, operation, statusCode).Inc()
}
