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
)

const (
	// MetricsSubsystemWazuh is the subsystem for Wazuh-specific metrics
	MetricsSubsystemWazuh = "wazuh"
)

var (
	// WazuhClusterStatus tracks the status of Wazuh clusters
	WazuhClusterStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemWazuh,
			Name:      "cluster_status",
			Help:      "Status of Wazuh clusters (1=ready, 0=not ready)",
		},
		[]string{"cluster", "namespace"},
	)

	// WazuhManagerNodes tracks the number of manager nodes
	WazuhManagerNodes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemWazuh,
			Name:      "manager_nodes",
			Help:      "Number of Wazuh manager nodes by status",
		},
		[]string{"cluster", "namespace", "role", "status"},
	)

	// WazuhAgentsConnected tracks connected agents (placeholder for future)
	WazuhAgentsConnected = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemWazuh,
			Name:      "agents_connected",
			Help:      "Number of connected Wazuh agents",
		},
		[]string{"cluster", "namespace"},
	)

	// WazuhRulesTotal tracks the number of custom rules
	WazuhRulesTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemWazuh,
			Name:      "rules_total",
			Help:      "Total number of custom Wazuh rules",
		},
		[]string{"cluster", "namespace"},
	)

	// WazuhDecodersTotal tracks the number of custom decoders
	WazuhDecodersTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemWazuh,
			Name:      "decoders_total",
			Help:      "Total number of custom Wazuh decoders",
		},
		[]string{"cluster", "namespace"},
	)

	// WazuhCertificateExpiry tracks certificate expiry timestamps
	WazuhCertificateExpiry = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemWazuh,
			Name:      "certificate_expiry_seconds",
			Help:      "Certificate expiry time in Unix seconds",
		},
		[]string{"cluster", "namespace", "cert_type"},
	)
)

// RegisterWazuhMetrics registers Wazuh-specific metrics
func RegisterWazuhMetrics() {
	metrics.Registry.MustRegister(
		WazuhClusterStatus,
		WazuhManagerNodes,
		WazuhAgentsConnected,
		WazuhRulesTotal,
		WazuhDecodersTotal,
		WazuhCertificateExpiry,
	)
}

// SetWazuhClusterStatus sets the status of a Wazuh cluster
func SetWazuhClusterStatus(cluster, namespace string, ready bool) {
	var value float64
	if ready {
		value = 1
	}
	WazuhClusterStatus.WithLabelValues(cluster, namespace).Set(value)
}

// SetWazuhManagerNodes sets the manager node counts
func SetWazuhManagerNodes(cluster, namespace, role, status string, count int) {
	WazuhManagerNodes.WithLabelValues(cluster, namespace, role, status).Set(float64(count))
}

// SetWazuhAgentsConnected sets the connected agents count
func SetWazuhAgentsConnected(cluster, namespace string, count int) {
	WazuhAgentsConnected.WithLabelValues(cluster, namespace).Set(float64(count))
}

// SetWazuhRulesTotal sets the total rules count
func SetWazuhRulesTotal(cluster, namespace string, count int) {
	WazuhRulesTotal.WithLabelValues(cluster, namespace).Set(float64(count))
}

// SetWazuhDecodersTotal sets the total decoders count
func SetWazuhDecodersTotal(cluster, namespace string, count int) {
	WazuhDecodersTotal.WithLabelValues(cluster, namespace).Set(float64(count))
}

// SetWazuhCertificateExpiry sets the certificate expiry timestamp
func SetWazuhCertificateExpiry(cluster, namespace, certType string, expiryUnix int64) {
	WazuhCertificateExpiry.WithLabelValues(cluster, namespace, certType).Set(float64(expiryUnix))
}
