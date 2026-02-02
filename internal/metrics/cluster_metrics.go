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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// ClusterHealthStatus represents the health status of a Wazuh cluster
type ClusterHealthStatus int

const (
	// ClusterHealthUnknown indicates the cluster health is unknown
	ClusterHealthUnknown ClusterHealthStatus = 0
	// ClusterHealthRed indicates the cluster is unhealthy
	ClusterHealthRed ClusterHealthStatus = 1
	// ClusterHealthYellow indicates the cluster is degraded
	ClusterHealthYellow ClusterHealthStatus = 2
	// ClusterHealthGreen indicates the cluster is healthy
	ClusterHealthGreen ClusterHealthStatus = 3
)

var (
	// ClusterHealth tracks overall cluster health status
	// 0=unknown, 1=red (unhealthy), 2=yellow (degraded), 3=green (healthy)
	ClusterHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCluster,
			Name:      "health",
			Help:      "Cluster health status (0=unknown, 1=red, 2=yellow, 3=green)",
		},
		[]string{"cluster", "namespace"},
	)

	// ClusterComponentHealth tracks health of individual cluster components
	ClusterComponentHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCluster,
			Name:      "component_health",
			Help:      "Component health status (0=unknown, 1=unhealthy, 2=degraded, 3=healthy)",
		},
		[]string{"cluster", "namespace", "component"},
	)

	// ClusterReadyReplicas tracks ready replicas per component
	ClusterReadyReplicas = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCluster,
			Name:      "ready_replicas",
			Help:      "Number of ready replicas per component",
		},
		[]string{"cluster", "namespace", "component"},
	)

	// ClusterDesiredReplicas tracks desired replicas per component
	ClusterDesiredReplicas = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCluster,
			Name:      "desired_replicas",
			Help:      "Number of desired replicas per component",
		},
		[]string{"cluster", "namespace", "component"},
	)

	// CertificateExpiryDays tracks days until certificate expiration
	// This is a convenience metric that converts seconds to days
	CertificateExpiryDays = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCertificate,
			Name:      "expiry_days",
			Help:      "Days until certificate expiration (negative if expired)",
		},
		[]string{"cluster", "namespace", "certificate_type", "secret_name"},
	)

	// CertificateExpiryTimestamp tracks the certificate expiry timestamp
	CertificateExpiryTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCertificate,
			Name:      "expiry_timestamp_seconds",
			Help:      "Unix timestamp of certificate expiration",
		},
		[]string{"cluster", "namespace", "certificate_type", "secret_name"},
	)
)

// RegisterClusterMetrics registers cluster-specific metrics with the registry
func RegisterClusterMetrics() {
	metrics.Registry.MustRegister(
		ClusterHealth,
		ClusterComponentHealth,
		ClusterReadyReplicas,
		ClusterDesiredReplicas,
		CertificateExpiryDays,
		CertificateExpiryTimestamp,
	)
}

// SetClusterHealth sets the overall cluster health status
func SetClusterHealth(cluster, namespace string, status ClusterHealthStatus) {
	ClusterHealth.WithLabelValues(cluster, namespace).Set(float64(status))
}

// SetClusterComponentHealth sets the health status of a specific component
func SetClusterComponentHealth(cluster, namespace, component string, status ClusterHealthStatus) {
	ClusterComponentHealth.WithLabelValues(cluster, namespace, component).Set(float64(status))
}

// SetClusterReplicas sets both ready and desired replicas for a component
func SetClusterReplicas(cluster, namespace, component string, ready, desired int32) {
	ClusterReadyReplicas.WithLabelValues(cluster, namespace, component).Set(float64(ready))
	ClusterDesiredReplicas.WithLabelValues(cluster, namespace, component).Set(float64(desired))
}

// SetCertificateExpiryDays sets the certificate expiry days metric
func SetCertificateExpiryDays(cluster, namespace, certType, secretName string, daysUntilExpiry float64, expiryTimestamp float64) {
	CertificateExpiryDays.WithLabelValues(cluster, namespace, certType, secretName).Set(daysUntilExpiry)
	CertificateExpiryTimestamp.WithLabelValues(cluster, namespace, certType, secretName).Set(expiryTimestamp)
}

// DeleteClusterMetrics removes all metrics for a deleted cluster
func DeleteClusterMetrics(cluster, namespace string) {
	ClusterHealth.DeleteLabelValues(cluster, namespace)

	// Components to delete
	components := []string{"manager", "worker", "indexer", "dashboard"}
	for _, component := range components {
		ClusterComponentHealth.DeleteLabelValues(cluster, namespace, component)
		ClusterReadyReplicas.DeleteLabelValues(cluster, namespace, component)
		ClusterDesiredReplicas.DeleteLabelValues(cluster, namespace, component)
	}
}

// DeleteCertificateMetrics removes certificate metrics for a specific secret
func DeleteCertificateMetrics(cluster, namespace, certType, secretName string) {
	CertificateExpiryDays.DeleteLabelValues(cluster, namespace, certType, secretName)
	CertificateExpiryTimestamp.DeleteLabelValues(cluster, namespace, certType, secretName)
}

// CalculateOverallHealth calculates overall cluster health from component statuses
func CalculateOverallHealth(componentStatuses map[string]ClusterHealthStatus) ClusterHealthStatus {
	if len(componentStatuses) == 0 {
		return ClusterHealthUnknown
	}

	worst := ClusterHealthGreen
	for _, status := range componentStatuses {
		if status < worst {
			worst = status
		}
	}
	return worst
}
