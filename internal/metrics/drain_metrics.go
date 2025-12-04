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

const (
	// MetricsSubsystemDrain is the subsystem for drain-related metrics
	MetricsSubsystemDrain = "drain"
)

// Drain metrics - Counters
var (
	// DrainOperationsTotal counts total drain operations by component and result
	DrainOperationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: constants.MetricsNamespace,
			Subsystem: MetricsSubsystemDrain,
			Name:      "operations_total",
			Help:      "Total number of drain operations by component and result",
		},
		[]string{"cluster", "namespace", "component", "result"},
	)

	// DrainRollbacksTotal counts total rollback operations
	DrainRollbacksTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: constants.MetricsNamespace,
			Subsystem: MetricsSubsystemDrain,
			Name:      "rollbacks_total",
			Help:      "Total number of drain rollback operations by component",
		},
		[]string{"cluster", "namespace", "component"},
	)

	// DrainRetriesTotal counts total retry attempts
	DrainRetriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: constants.MetricsNamespace,
			Subsystem: MetricsSubsystemDrain,
			Name:      "retries_total",
			Help:      "Total number of drain retry attempts by component",
		},
		[]string{"cluster", "namespace", "component"},
	)

	// DrainTimeoutsTotal counts drain operations that timed out
	DrainTimeoutsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: constants.MetricsNamespace,
			Subsystem: MetricsSubsystemDrain,
			Name:      "timeouts_total",
			Help:      "Total number of drain timeouts by component",
		},
		[]string{"cluster", "namespace", "component"},
	)

	// DrainDryRunsTotal counts dry-run evaluations
	DrainDryRunsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: constants.MetricsNamespace,
			Subsystem: MetricsSubsystemDrain,
			Name:      "dryruns_total",
			Help:      "Total number of dry-run evaluations by result",
		},
		[]string{"cluster", "namespace", "result"},
	)
)

// Drain metrics - Gauges
var (
	// DrainInProgress indicates if a drain is currently in progress (1) or not (0)
	DrainInProgress = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: constants.MetricsNamespace,
			Subsystem: MetricsSubsystemDrain,
			Name:      "in_progress",
			Help:      "Indicates if a drain operation is in progress (1=yes, 0=no)",
		},
		[]string{"cluster", "namespace", "component"},
	)

	// DrainProgress shows the current progress percentage (0-100)
	DrainProgress = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: constants.MetricsNamespace,
			Subsystem: MetricsSubsystemDrain,
			Name:      "progress_percent",
			Help:      "Current drain progress as percentage (0-100)",
		},
		[]string{"cluster", "namespace", "component"},
	)

	// DrainPhase shows the current drain phase as a numeric value
	DrainPhase = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: constants.MetricsNamespace,
			Subsystem: MetricsSubsystemDrain,
			Name:      "phase",
			Help:      "Current drain phase (0=Idle, 1=Pending, 2=Draining, 3=Verifying, 4=Complete, 5=Failed, 6=RollingBack)",
		},
		[]string{"cluster", "namespace", "component"},
	)

	// DrainRetryCount shows the current retry attempt count
	DrainRetryCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: constants.MetricsNamespace,
			Subsystem: MetricsSubsystemDrain,
			Name:      "retry_count",
			Help:      "Current retry attempt count",
		},
		[]string{"cluster", "namespace", "component"},
	)

	// IndexerShardCount shows the remaining shards on the target node during drain
	IndexerShardCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: constants.MetricsNamespace,
			Subsystem: MetricsSubsystemDrain,
			Name:      "indexer_shard_count",
			Help:      "Remaining shards on target indexer node during drain",
		},
		[]string{"cluster", "namespace", "node"},
	)

	// ManagerQueueDepth shows the remaining queue items during manager drain
	ManagerQueueDepth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: constants.MetricsNamespace,
			Subsystem: MetricsSubsystemDrain,
			Name:      "manager_queue_depth",
			Help:      "Remaining items in manager queue during drain",
		},
		[]string{"cluster", "namespace", "node"},
	)
)

// Drain metrics - Histograms
var (
	// DrainDuration measures the duration of drain operations in seconds
	DrainDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: constants.MetricsNamespace,
			Subsystem: MetricsSubsystemDrain,
			Name:      "duration_seconds",
			Help:      "Duration of drain operations in seconds",
			Buckets:   prometheus.ExponentialBuckets(1, 2, 15), // 1s to ~9 hours
		},
		[]string{"cluster", "namespace", "component", "result"},
	)

	// ShardRelocationDuration measures the duration of shard relocation in seconds
	ShardRelocationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: constants.MetricsNamespace,
			Subsystem: MetricsSubsystemDrain,
			Name:      "shard_relocation_duration_seconds",
			Help:      "Duration of individual shard relocations in seconds",
		},
		[]string{"cluster", "namespace"},
	)

	// QueueDrainDuration measures the duration of queue drain in seconds
	QueueDrainDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: constants.MetricsNamespace,
			Subsystem: MetricsSubsystemDrain,
			Name:      "queue_drain_duration_seconds",
			Help:      "Duration of manager queue drain in seconds",
		},
		[]string{"cluster", "namespace"},
	)
)

// RegisterDrainMetrics registers all drain-related metrics
func RegisterDrainMetrics() {
	// Counters
	metrics.Registry.MustRegister(
		DrainOperationsTotal,
		DrainRollbacksTotal,
		DrainRetriesTotal,
		DrainTimeoutsTotal,
		DrainDryRunsTotal,
	)

	// Gauges
	metrics.Registry.MustRegister(
		DrainInProgress,
		DrainProgress,
		DrainPhase,
		DrainRetryCount,
		IndexerShardCount,
		ManagerQueueDepth,
	)

	// Histograms
	metrics.Registry.MustRegister(
		DrainDuration,
		ShardRelocationDuration,
		QueueDrainDuration,
	)
}

// Helper functions for recording drain metrics

// RecordDrainOperation records a drain operation completion
func RecordDrainOperation(cluster, namespace, component, result string, durationSeconds float64) {
	DrainOperationsTotal.WithLabelValues(cluster, namespace, component, result).Inc()
	DrainDuration.WithLabelValues(cluster, namespace, component, result).Observe(durationSeconds)
}

// RecordDrainStarted records when a drain operation starts
func RecordDrainStarted(cluster, namespace, component string) {
	DrainInProgress.WithLabelValues(cluster, namespace, component).Set(1)
	DrainPhase.WithLabelValues(cluster, namespace, component).Set(2) // Draining
	DrainProgress.WithLabelValues(cluster, namespace, component).Set(0)
}

// RecordDrainProgress records drain progress
func RecordDrainProgress(cluster, namespace, component string, progress float64) {
	DrainProgress.WithLabelValues(cluster, namespace, component).Set(progress)
}

// RecordDrainCompleted records when a drain operation completes successfully
func RecordDrainCompleted(cluster, namespace, component string) {
	DrainInProgress.WithLabelValues(cluster, namespace, component).Set(0)
	DrainPhase.WithLabelValues(cluster, namespace, component).Set(4) // Complete
	DrainProgress.WithLabelValues(cluster, namespace, component).Set(100)
}

// RecordDrainFailed records when a drain operation fails
func RecordDrainFailed(cluster, namespace, component string) {
	DrainInProgress.WithLabelValues(cluster, namespace, component).Set(0)
	DrainPhase.WithLabelValues(cluster, namespace, component).Set(5) // Failed
}

// RecordDrainRollback records a rollback operation
func RecordDrainRollback(cluster, namespace, component string) {
	DrainRollbacksTotal.WithLabelValues(cluster, namespace, component).Inc()
	DrainPhase.WithLabelValues(cluster, namespace, component).Set(6) // RollingBack
}

// RecordDrainRetry records a retry attempt
func RecordDrainRetry(cluster, namespace, component string, attemptCount int32) {
	DrainRetriesTotal.WithLabelValues(cluster, namespace, component).Inc()
	DrainRetryCount.WithLabelValues(cluster, namespace, component).Set(float64(attemptCount))
	DrainPhase.WithLabelValues(cluster, namespace, component).Set(1) // Pending (restarting)
}

// RecordDrainTimeout records a drain timeout
func RecordDrainTimeout(cluster, namespace, component string) {
	DrainTimeoutsTotal.WithLabelValues(cluster, namespace, component).Inc()
}

// RecordDryRunResult records a dry-run evaluation result
func RecordDryRunResult(cluster, namespace string, feasible bool) {
	result := "feasible"
	if !feasible {
		result = "not_feasible"
	}
	DrainDryRunsTotal.WithLabelValues(cluster, namespace, result).Inc()
}

// SetIndexerShardCount sets the current shard count for an indexer node
func SetIndexerShardCount(cluster, namespace, node string, count int32) {
	IndexerShardCount.WithLabelValues(cluster, namespace, node).Set(float64(count))
}

// SetManagerQueueDepth sets the current queue depth for a manager node
func SetManagerQueueDepth(cluster, namespace, node string, depth int64) {
	ManagerQueueDepth.WithLabelValues(cluster, namespace, node).Set(float64(depth))
}

// ResetDrainMetrics resets drain-related metrics for a cluster
func ResetDrainMetrics(cluster, namespace, component string) {
	DrainInProgress.WithLabelValues(cluster, namespace, component).Set(0)
	DrainProgress.WithLabelValues(cluster, namespace, component).Set(0)
	DrainPhase.WithLabelValues(cluster, namespace, component).Set(0) // Idle
	DrainRetryCount.WithLabelValues(cluster, namespace, component).Set(0)
}

// PhaseToValue converts a drain phase string to numeric value for metrics
func PhaseToValue(phase string) float64 {
	switch phase {
	case constants.DrainPhaseIdle:
		return 0
	case constants.DrainPhasePending:
		return 1
	case constants.DrainPhaseDraining:
		return 2
	case constants.DrainPhaseVerifying:
		return 3
	case constants.DrainPhaseComplete:
		return 4
	case constants.DrainPhaseFailed:
		return 5
	case constants.DrainPhaseRollingBack:
		return 6
	default:
		return 0
	}
}
