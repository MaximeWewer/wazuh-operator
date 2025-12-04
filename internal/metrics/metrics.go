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

// Package metrics provides Prometheus metrics for the Wazuh Operator
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// Re-export constants for backwards compatibility within the metrics package
const (
	MetricsNamespace           = constants.MetricsNamespace
	MetricsSubsystemReconciler = constants.MetricsSubsystemReconciler
	MetricsSubsystemCluster    = constants.MetricsSubsystemCluster
)

var (
	// ReconciliationsTotal counts total reconciliations by CRD and result
	ReconciliationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemReconciler,
			Name:      "reconciliations_total",
			Help:      "Total number of reconciliations by CRD and result",
		},
		[]string{"crd", "namespace", "result"},
	)

	// ReconciliationDuration measures reconciliation duration in seconds
	ReconciliationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemReconciler,
			Name:      "reconciliation_duration_seconds",
			Help:      "Duration of reconciliations in seconds",
			Buckets:   prometheus.ExponentialBuckets(0.01, 2, 15), // 10ms to ~5min
		},
		[]string{"crd", "namespace"},
	)

	// ReconciliationErrors counts reconciliation errors by type
	ReconciliationErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Subsystem: MetricsSubsystemReconciler,
			Name:      "errors_total",
			Help:      "Total number of reconciliation errors by CRD and error type",
		},
		[]string{"crd", "namespace", "error_type"},
	)

	// ManagedResources tracks the number of managed resources by type
	ManagedResources = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "managed_resources",
			Help:      "Number of managed resources by type and namespace",
		},
		[]string{"crd", "namespace"},
	)

	// DriftDetectionsTotal counts drift detection events
	DriftDetectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "drift_detections_total",
			Help:      "Total number of drift detections by CRD",
		},
		[]string{"crd", "namespace"},
	)

	// PatchDetectionsTotal counts spec/config change detections by component and change type
	PatchDetectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "patch_detections_total",
			Help:      "Total number of patch detections by component and change type",
		},
		[]string{"cluster", "namespace", "component", "change_type"},
	)

	// SpecHashChangesTotal counts spec hash changes that trigger updates
	SpecHashChangesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "spec_hash_changes_total",
			Help:      "Total number of spec hash changes detected",
		},
		[]string{"cluster", "namespace", "component"},
	)

	// ConfigHashChangesTotal counts config hash changes that trigger pod restarts
	ConfigHashChangesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "config_hash_changes_total",
			Help:      "Total number of config hash changes detected",
		},
		[]string{"cluster", "namespace", "component"},
	)

	// VersionUpgradesTotal counts version upgrades
	VersionUpgradesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "version_upgrades_total",
			Help:      "Total number of version upgrades initiated",
		},
		[]string{"cluster", "namespace", "from_version", "to_version"},
	)

	// ScaleOperationsTotal counts scale operations
	ScaleOperationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "scale_operations_total",
			Help:      "Total number of scale operations by component",
		},
		[]string{"cluster", "namespace", "component", "direction"},
	)

	// ResourceSyncStatus tracks sync status with external systems
	ResourceSyncStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "resource_sync_status",
			Help:      "Sync status of resources (1=synced, 0=not synced)",
		},
		[]string{"crd", "namespace", "name"},
	)

	// OperatorInfo provides information about the operator
	OperatorInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "info",
			Help:      "Information about the Wazuh Operator",
		},
		[]string{"version", "commit", "build_date"},
	)
)

// RegisterMetrics registers all metrics with the controller-runtime registry
func RegisterMetrics() {
	metrics.Registry.MustRegister(
		ReconciliationsTotal,
		ReconciliationDuration,
		ReconciliationErrors,
		ManagedResources,
		DriftDetectionsTotal,
		PatchDetectionsTotal,
		SpecHashChangesTotal,
		ConfigHashChangesTotal,
		VersionUpgradesTotal,
		ScaleOperationsTotal,
		ResourceSyncStatus,
		OperatorInfo,
	)
	// Register certificate-specific metrics
	RegisterCertificateMetrics()
}

// RecordReconciliation records a reconciliation event
func RecordReconciliation(crd, namespace, result string, duration float64) {
	ReconciliationsTotal.WithLabelValues(crd, namespace, result).Inc()
	ReconciliationDuration.WithLabelValues(crd, namespace).Observe(duration)
}

// RecordReconciliationError records a reconciliation error
func RecordReconciliationError(crd, namespace, errorType string) {
	ReconciliationErrors.WithLabelValues(crd, namespace, errorType).Inc()
}

// SetManagedResources sets the count of managed resources
func SetManagedResources(crd, namespace string, count float64) {
	ManagedResources.WithLabelValues(crd, namespace).Set(count)
}

// RecordDriftDetection records a drift detection event
func RecordDriftDetection(crd, namespace string) {
	DriftDetectionsTotal.WithLabelValues(crd, namespace).Inc()
}

// SetResourceSyncStatus sets the sync status of a resource
func SetResourceSyncStatus(crd, namespace, name string, synced bool) {
	var value float64
	if synced {
		value = 1
	}
	ResourceSyncStatus.WithLabelValues(crd, namespace, name).Set(value)
}

// SetOperatorInfo sets operator information
func SetOperatorInfo(version, commit, buildDate string) {
	OperatorInfo.WithLabelValues(version, commit, buildDate).Set(1)
}

// RecordPatchDetection records a patch detection event
func RecordPatchDetection(cluster, namespace, component, changeType string) {
	PatchDetectionsTotal.WithLabelValues(cluster, namespace, component, changeType).Inc()
}

// RecordSpecHashChange records a spec hash change event
func RecordSpecHashChange(cluster, namespace, component string) {
	SpecHashChangesTotal.WithLabelValues(cluster, namespace, component).Inc()
}

// RecordConfigHashChange records a config hash change event
func RecordConfigHashChange(cluster, namespace, component string) {
	ConfigHashChangesTotal.WithLabelValues(cluster, namespace, component).Inc()
}

// RecordVersionUpgrade records a version upgrade event
func RecordVersionUpgrade(cluster, namespace, fromVersion, toVersion string) {
	VersionUpgradesTotal.WithLabelValues(cluster, namespace, fromVersion, toVersion).Inc()
}

// RecordScaleOperation records a scale operation event
// direction should be "up" or "down"
func RecordScaleOperation(cluster, namespace, component, direction string) {
	ScaleOperationsTotal.WithLabelValues(cluster, namespace, component, direction).Inc()
}
