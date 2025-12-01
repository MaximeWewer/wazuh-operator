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
	// MetricsSubsystemCertificate is the subsystem for certificate metrics
	MetricsSubsystemCertificate = "certificate"
)

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

	// CertificateTestMode indicates if test mode is enabled
	CertificateTestMode = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemCertificate,
			Name:      "test_mode_enabled",
			Help:      "Whether certificate test mode is enabled (1=enabled, 0=disabled)",
		},
		[]string{"cluster", "namespace"},
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
		CertificateTestMode,
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

// SetCertificateTestMode sets whether test mode is enabled
func SetCertificateTestMode(cluster, namespace string, enabled bool) {
	var value float64
	if enabled {
		value = 1
	}
	CertificateTestMode.WithLabelValues(cluster, namespace).Set(value)
}

// ClearCertificateMetrics clears all certificate metrics for a cluster
// Call this when a cluster is deleted
func ClearCertificateMetrics(cluster, namespace string) {
	// Clear expiry metrics for all components
	components := []string{"ca", "indexer", "manager-master", "manager-worker", "dashboard", "filebeat", "admin"}
	certTypes := []string{"ca", "node"}

	for _, component := range components {
		for _, certType := range certTypes {
			CertificateExpirySeconds.DeleteLabelValues(cluster, namespace, component, certType)
		}
		CertificateInfo.DeletePartialMatch(prometheus.Labels{
			"cluster":   cluster,
			"namespace": namespace,
			"component": component,
		})
	}

	CertificateRolloutsPending.DeleteLabelValues(cluster, namespace)
	CertificateTestMode.DeleteLabelValues(cluster, namespace)
}
