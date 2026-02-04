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

// Re-export certificate subsystem constant for backwards compatibility
const MetricsSubsystemCertificate = constants.MetricsSubsystemCertificate

var (
	// CertificateExpirySeconds tracks time until certificate expiry
	CertificateExpirySeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCertificate,
			Name:      "expiry_seconds",
			Help:      "Seconds until certificate expiry (negative means expired)",
		},
		[]string{"cluster", "namespace", "component", "type"},
	)

	// CertificateRenewalsTotal counts certificate renewals
	CertificateRenewalsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCertificate,
			Name:      "renewals_total",
			Help:      "Total number of certificate renewals",
		},
		[]string{"cluster", "namespace", "component", "result"},
	)

	// CertificateRenewalDuration measures certificate renewal duration
	CertificateRenewalDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCertificate,
			Name:      "renewal_duration_seconds",
			Help:      "Duration of certificate renewal operations in seconds",
			Buckets:   prometheus.ExponentialBuckets(0.001, 2, 12), // 1ms to ~4s
		},
		[]string{"cluster", "namespace", "component"},
	)

	// CertificateRolloutWaitDuration measures time waiting for pod rollouts
	CertificateRolloutWaitDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCertificate,
			Name:      "rollout_wait_duration_seconds",
			Help:      "Duration of waiting for pod rollout after certificate renewal",
			Buckets:   prometheus.ExponentialBuckets(1, 2, 10), // 1s to ~17min
		},
		[]string{"cluster", "namespace", "component"},
	)

	// CertificateRolloutsPending tracks number of pending certificate rollouts
	CertificateRolloutsPending = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCertificate,
			Name:      "rollouts_pending",
			Help:      "Number of certificate rollouts pending completion",
		},
		[]string{"cluster", "namespace"},
	)

	// CertificateErrorsTotal counts certificate-related errors
	CertificateErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCertificate,
			Name:      "errors_total",
			Help:      "Total number of certificate-related errors",
		},
		[]string{"cluster", "namespace", "component", "error_type"},
	)

	// CertificateInfo provides certificate metadata
	CertificateInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCertificate,
			Name:      "info",
			Help:      "Certificate metadata (value is always 1)",
		},
		[]string{"cluster", "namespace", "component", "serial", "issuer"},
	)

	// HotReloadSuccessTotal counts successful certificate hot reloads
	HotReloadSuccessTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCertificate,
			Name:      "hotreload_success_total",
			Help:      "Total number of successful certificate hot reloads",
		},
		[]string{"cluster", "namespace", "component", "method"},
	)

	// HotReloadFailureTotal counts failed certificate hot reloads
	HotReloadFailureTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCertificate,
			Name:      "hotreload_failure_total",
			Help:      "Total number of failed certificate hot reloads",
		},
		[]string{"cluster", "namespace", "component", "reason"},
	)

	// HotReloadDuration measures duration of hot reload operations
	HotReloadDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCertificate,
			Name:      "hotreload_duration_seconds",
			Help:      "Duration of certificate hot reload operations in seconds",
			Buckets:   prometheus.ExponentialBuckets(0.1, 2, 10), // 100ms to ~51s
		},
		[]string{"cluster", "namespace", "component"},
	)

	// HotReloadFallbackTotal counts fallbacks from hot-reload to rolling restart
	HotReloadFallbackTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCertificate,
			Name:      "hotreload_fallback_total",
			Help:      "Total number of fallbacks from hot-reload to rolling restart",
		},
		[]string{"cluster", "namespace", "component", "reason"},
	)

	// RollingRestartTotal counts rolling restarts triggered by certificate renewal
	RollingRestartTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCertificate,
			Name:      "rolling_restart_total",
			Help:      "Total number of rolling restarts triggered by certificate renewal",
		},
		[]string{"cluster", "namespace", "component", "cert_type"},
	)

	// RollingRestartDuration measures duration of rolling restart operations
	RollingRestartDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCertificate,
			Name:      "rolling_restart_duration_seconds",
			Help:      "Duration of rolling restart operations in seconds",
			Buckets:   prometheus.ExponentialBuckets(1, 2, 12), // 1s to ~68min
		},
		[]string{"cluster", "namespace", "component"},
	)

	// CertificatePropagationDuration measures time for certificate propagation to pods
	CertificatePropagationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCertificate,
			Name:      "propagation_duration_seconds",
			Help:      "Duration for certificate propagation to pods in seconds",
		},
		[]string{"cluster", "namespace", "component"},
	)

	// PodSyncStatusGauge tracks per-pod certificate sync status
	PodSyncStatusGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCertificate,
			Name:      "pod_sync_status",
			Help:      "Certificate sync status per pod (1=synced, 0=pending, -1=failed)",
		},
		[]string{"cluster", "namespace", "component", "pod"},
	)
)

// RegisterCertificateMetrics registers certificate-specific metrics
func RegisterCertificateMetrics() {
	metrics.Registry.MustRegister(
		CertificateExpirySeconds,
		CertificateRenewalsTotal,
		CertificateRenewalDuration,
		CertificateRolloutWaitDuration,
		CertificateRolloutsPending,
		CertificateErrorsTotal,
		CertificateInfo,
		// Hot-reload metrics
		HotReloadSuccessTotal,
		HotReloadFailureTotal,
		HotReloadDuration,
		HotReloadFallbackTotal,
		// Rolling restart metrics
		RollingRestartTotal,
		RollingRestartDuration,
		// Propagation metrics
		CertificatePropagationDuration,
		PodSyncStatusGauge,
	)
}

// SetCertificateExpiry sets the seconds until certificate expiry
func SetCertificateExpiry(cluster, namespace, component, certType string, secondsUntilExpiry float64) {
	CertificateExpirySeconds.WithLabelValues(cluster, namespace, component, certType).Set(secondsUntilExpiry)
}

// RecordCertificateRenewal records a certificate renewal event
func RecordCertificateRenewal(cluster, namespace, component, result string, duration float64) {
	CertificateRenewalsTotal.WithLabelValues(cluster, namespace, component, result).Inc()
	CertificateRenewalDuration.WithLabelValues(cluster, namespace, component).Observe(duration)
}

// RecordCertificateRolloutWait records time spent waiting for rollout
func RecordCertificateRolloutWait(cluster, namespace, component string, duration float64) {
	CertificateRolloutWaitDuration.WithLabelValues(cluster, namespace, component).Observe(duration)
}

// SetCertificateRolloutsPending sets the number of pending rollouts
func SetCertificateRolloutsPending(cluster, namespace string, count float64) {
	CertificateRolloutsPending.WithLabelValues(cluster, namespace).Set(count)
}

// RecordCertificateError records a certificate-related error
func RecordCertificateError(cluster, namespace, component, errorType string) {
	CertificateErrorsTotal.WithLabelValues(cluster, namespace, component, errorType).Inc()
}

// SetCertificateInfo sets certificate metadata
func SetCertificateInfo(cluster, namespace, component, serial, issuer string) {
	CertificateInfo.WithLabelValues(cluster, namespace, component, serial, issuer).Set(1)
}

// RecordHotReloadSuccess records a successful hot reload
// method should be "api-call" or "automatic-file-watch"
func RecordHotReloadSuccess(cluster, namespace, component, method string, duration float64) {
	HotReloadSuccessTotal.WithLabelValues(cluster, namespace, component, method).Inc()
	HotReloadDuration.WithLabelValues(cluster, namespace, component).Observe(duration)
}

// RecordHotReloadFailure records a failed hot reload
// reason should describe why the hot reload failed (e.g., "api_error", "timeout", "pod_unreachable")
func RecordHotReloadFailure(cluster, namespace, component, reason string) {
	HotReloadFailureTotal.WithLabelValues(cluster, namespace, component, reason).Inc()
}

// RecordHotReloadFallback records a fallback from hot-reload to rolling restart
func RecordHotReloadFallback(cluster, namespace, component, reason string) {
	HotReloadFallbackTotal.WithLabelValues(cluster, namespace, component, reason).Inc()
}

// RecordRollingRestart records a rolling restart triggered by certificate renewal
// certType should be "ca", "node", "admin", "filebeat", or "dashboard"
func RecordRollingRestart(cluster, namespace, component, certType string, duration float64) {
	RollingRestartTotal.WithLabelValues(cluster, namespace, component, certType).Inc()
	if duration > 0 {
		RollingRestartDuration.WithLabelValues(cluster, namespace, component).Observe(duration)
	}
}

// RecordCertificatePropagation records the time taken for certificate propagation
func RecordCertificatePropagation(cluster, namespace, component string, duration float64) {
	CertificatePropagationDuration.WithLabelValues(cluster, namespace, component).Observe(duration)
}

// SetPodSyncStatus sets the certificate sync status for a specific pod
// status: 1=synced, 0=pending, -1=failed
func SetPodSyncStatus(cluster, namespace, component, pod string, status float64) {
	PodSyncStatusGauge.WithLabelValues(cluster, namespace, component, pod).Set(status)
}

// ClearPodSyncStatus clears the sync status for a specific pod
func ClearPodSyncStatus(cluster, namespace, component, pod string) {
	PodSyncStatusGauge.DeleteLabelValues(cluster, namespace, component, pod)
}

// ClearCertificateMetrics clears all certificate metrics for a cluster
// Call this when a cluster is deleted
func ClearCertificateMetrics(cluster, namespace string) {
	// Clear expiry metrics for all components
	components := constants.CertificateComponents
	certTypes := constants.CertificateTypes

	for _, component := range components {
		for _, certType := range certTypes {
			CertificateExpirySeconds.DeleteLabelValues(cluster, namespace, component, certType)
		}
		CertificateInfo.DeletePartialMatch(prometheus.Labels{
			"cluster":   cluster,
			"namespace": namespace,
			"component": component,
		})
		// Clear hot-reload metrics
		HotReloadDuration.DeletePartialMatch(prometheus.Labels{
			"cluster":   cluster,
			"namespace": namespace,
			"component": component,
		})
		// Clear rolling restart metrics
		RollingRestartDuration.DeletePartialMatch(prometheus.Labels{
			"cluster":   cluster,
			"namespace": namespace,
			"component": component,
		})
		// Clear propagation metrics
		CertificatePropagationDuration.DeletePartialMatch(prometheus.Labels{
			"cluster":   cluster,
			"namespace": namespace,
			"component": component,
		})
		// Clear pod sync status
		PodSyncStatusGauge.DeletePartialMatch(prometheus.Labels{
			"cluster":   cluster,
			"namespace": namespace,
			"component": component,
		})
	}

	CertificateRolloutsPending.DeleteLabelValues(cluster, namespace)
}
