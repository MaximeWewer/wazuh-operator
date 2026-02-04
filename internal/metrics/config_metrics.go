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

// MetricsSubsystemConfig is the subsystem for config-related metrics
const MetricsSubsystemConfig = "config"

var (
	// ConfigChangeDetectedTotal counts configuration changes detected by type
	ConfigChangeDetectedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: constants.MetricsNamespace,
			Subsystem: MetricsSubsystemConfig,
			Name:      "change_detected_total",
			Help:      "Total number of configuration changes detected",
		},
		[]string{"cluster", "namespace", "change_type"},
	)

	// EnvFromChangeTotal counts EnvFrom (ConfigMapRef/SecretRef) changes
	EnvFromChangeTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: constants.MetricsNamespace,
			Subsystem: MetricsSubsystemConfig,
			Name:      "envfrom_change_total",
			Help:      "Total number of EnvFrom configuration changes detected",
		},
		[]string{"cluster", "namespace", "component", "source_type"},
	)

	// TLSConfigChangeTotal counts TLS configuration changes
	TLSConfigChangeTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: constants.MetricsNamespace,
			Subsystem: MetricsSubsystemConfig,
			Name:      "tls_config_change_total",
			Help:      "Total number of TLS configuration changes detected",
		},
		[]string{"cluster", "namespace", "component"},
	)

	// CertConfigChangeTotal counts certificate configuration changes
	CertConfigChangeTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: constants.MetricsNamespace,
			Subsystem: MetricsSubsystemConfig,
			Name:      "cert_config_change_total",
			Help:      "Total number of certificate configuration changes detected",
		},
		[]string{"cluster", "namespace", "cert_type", "field"},
	)

	// ConfigHashMismatchTotal counts hash mismatches that trigger updates
	ConfigHashMismatchTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: constants.MetricsNamespace,
			Subsystem: MetricsSubsystemConfig,
			Name:      "hash_mismatch_total",
			Help:      "Total number of configuration hash mismatches detected",
		},
		[]string{"cluster", "namespace", "component", "hash_type"},
	)

	// ConfigReconciliationTriggeredTotal counts reconciliations triggered by config changes
	ConfigReconciliationTriggeredTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: constants.MetricsNamespace,
			Subsystem: MetricsSubsystemConfig,
			Name:      "reconciliation_triggered_total",
			Help:      "Total number of reconciliations triggered by configuration changes",
		},
		[]string{"cluster", "namespace", "component", "trigger"},
	)

	// ConfigDetectionDuration measures time taken to detect configuration changes
	ConfigDetectionDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: constants.MetricsNamespace,
			Subsystem: MetricsSubsystemConfig,
			Name:      "detection_duration_seconds",
			Help:      "Duration of configuration change detection in seconds",
			Buckets:   prometheus.ExponentialBuckets(0.001, 2, 10), // 1ms to ~1s
		},
		[]string{"cluster", "namespace", "component"},
	)
)

// RegisterConfigMetrics registers config-specific metrics
func RegisterConfigMetrics() {
	metrics.Registry.MustRegister(
		ConfigChangeDetectedTotal,
		EnvFromChangeTotal,
		TLSConfigChangeTotal,
		CertConfigChangeTotal,
		ConfigHashMismatchTotal,
		ConfigReconciliationTriggeredTotal,
		ConfigDetectionDuration,
	)
}

// RecordConfigChangeDetected records a configuration change detection
// changeType should be: "env", "envfrom", "configmap", "secret", "tls-config", "cert-config", "spec"
func RecordConfigChangeDetected(cluster, namespace, changeType string) {
	ConfigChangeDetectedTotal.WithLabelValues(cluster, namespace, changeType).Inc()
}

// RecordEnvFromChange records an EnvFrom configuration change
// sourceType should be "configmap" or "secret"
func RecordEnvFromChange(cluster, namespace, component, sourceType string) {
	EnvFromChangeTotal.WithLabelValues(cluster, namespace, component, sourceType).Inc()
}

// RecordTLSConfigChange records a TLS configuration change
func RecordTLSConfigChange(cluster, namespace, component string) {
	TLSConfigChangeTotal.WithLabelValues(cluster, namespace, component).Inc()
}

// RecordCertConfigChange records a certificate configuration change
// certType: "ca", "node", "admin", "filebeat", "dashboard"
// field: "validity", "renewal_threshold", "key_algorithm", "subject", etc.
func RecordCertConfigChange(cluster, namespace, certType, field string) {
	CertConfigChangeTotal.WithLabelValues(cluster, namespace, certType, field).Inc()
}

// RecordConfigHashMismatch records a configuration hash mismatch
// hashType should be: "spec", "config", "cert", "envfrom", "composite"
func RecordConfigHashMismatch(cluster, namespace, component, hashType string) {
	ConfigHashMismatchTotal.WithLabelValues(cluster, namespace, component, hashType).Inc()
}

// RecordConfigReconciliationTriggered records a reconciliation triggered by config change
// trigger should describe what triggered it: "spec_change", "config_change", "cert_change", "envfrom_change"
func RecordConfigReconciliationTriggered(cluster, namespace, component, trigger string) {
	ConfigReconciliationTriggeredTotal.WithLabelValues(cluster, namespace, component, trigger).Inc()
}

// RecordConfigDetectionDuration records the time taken for config change detection
func RecordConfigDetectionDuration(cluster, namespace, component string, duration float64) {
	ConfigDetectionDuration.WithLabelValues(cluster, namespace, component).Observe(duration)
}

// ClearConfigMetrics clears all config metrics for a cluster
func ClearConfigMetrics(cluster, namespace string) {
	components := constants.CertificateComponents

	for _, component := range components {
		ConfigDetectionDuration.DeletePartialMatch(prometheus.Labels{
			"cluster":   cluster,
			"namespace": namespace,
			"component": component,
		})
	}
}
