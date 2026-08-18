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

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// Re-export wazuh subsystem constant for backwards compatibility
const MetricsSubsystemWazuh = constants.MetricsSubsystemWazuh

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

	// WazuhAgentsConnected tracks connected (active) agents
	WazuhAgentsConnected = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemWazuh,
			Name:      "agents_connected",
			Help:      "Number of connected Wazuh agents",
		},
		[]string{"cluster", "namespace"},
	)

	// WazuhAgentsDisconnected tracks agents in the disconnected state.
	// A sudden jump here while the manager pods stay Ready is the signature of a
	// wazuh-db problem (e.g. corrupt global.db): agents keep-alive but their status
	// can no longer be recorded/synchronised.
	WazuhAgentsDisconnected = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemWazuh,
			Name:      "agents_disconnected",
			Help:      "Number of disconnected Wazuh agents",
		},
		[]string{"cluster", "namespace"},
	)

	// WazuhAgentsNeverConnected tracks agents that never connected
	WazuhAgentsNeverConnected = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemWazuh,
			Name:      "agents_never_connected",
			Help:      "Number of Wazuh agents that never connected",
		},
		[]string{"cluster", "namespace"},
	)

	// WazuhAgentsPending tracks agents in the pending state
	WazuhAgentsPending = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemWazuh,
			Name:      "agents_pending",
			Help:      "Number of Wazuh agents in the pending state",
		},
		[]string{"cluster", "namespace"},
	)

	// WazuhAgentsTotal tracks the total number of enrolled agents
	WazuhAgentsTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemWazuh,
			Name:      "agents_total",
			Help:      "Total number of enrolled Wazuh agents",
		},
		[]string{"cluster", "namespace"},
	)

	// WazuhAPIReachable tracks whether the operator could query the Manager API
	// agent summary on the last scrape (1=reachable, 0=unreachable). A value of 0
	// means the manager API/wazuh-db did not answer, which is invisible to the
	// TCP-only pod probes.
	WazuhAPIReachable = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemWazuh,
			Name:      "api_reachable",
			Help:      "Whether the Wazuh Manager API agent summary was reachable on the last scrape (1=yes, 0=no)",
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
		WazuhAgentsDisconnected,
		WazuhAgentsNeverConnected,
		WazuhAgentsPending,
		WazuhAgentsTotal,
		WazuhAPIReachable,
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

// SetWazuhAgentsDisconnected sets the disconnected agents count
func SetWazuhAgentsDisconnected(cluster, namespace string, count int) {
	WazuhAgentsDisconnected.WithLabelValues(cluster, namespace).Set(float64(count))
}

// SetWazuhAgentsNeverConnected sets the never-connected agents count
func SetWazuhAgentsNeverConnected(cluster, namespace string, count int) {
	WazuhAgentsNeverConnected.WithLabelValues(cluster, namespace).Set(float64(count))
}

// SetWazuhAgentsPending sets the pending agents count
func SetWazuhAgentsPending(cluster, namespace string, count int) {
	WazuhAgentsPending.WithLabelValues(cluster, namespace).Set(float64(count))
}

// SetWazuhAgentsTotal sets the total enrolled agents count
func SetWazuhAgentsTotal(cluster, namespace string, count int) {
	WazuhAgentsTotal.WithLabelValues(cluster, namespace).Set(float64(count))
}

// SetWazuhAPIReachable sets whether the Manager API agent summary was reachable
func SetWazuhAPIReachable(cluster, namespace string, reachable bool) {
	var value float64
	if reachable {
		value = 1
	}
	WazuhAPIReachable.WithLabelValues(cluster, namespace).Set(value)
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
