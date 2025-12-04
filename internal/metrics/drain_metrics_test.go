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
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestRecordDrainOperation(t *testing.T) {
	// Reset metrics for test
	DrainOperationsTotal.Reset()
	DrainDuration.Reset()

	RecordDrainOperation("test-cluster", "default", "indexer", "success", 120.5)

	// Verify counter incremented
	metric := &dto.Metric{}
	counter, err := DrainOperationsTotal.GetMetricWithLabelValues("test-cluster", "default", "indexer", "success")
	if err != nil {
		t.Fatalf("Failed to get metric: %v", err)
	}

	if err := counter.Write(metric); err != nil {
		t.Fatalf("Failed to write metric: %v", err)
	}

	if metric.Counter.GetValue() != 1 {
		t.Errorf("Expected counter value 1, got %f", metric.Counter.GetValue())
	}
}

func TestRecordDrainStarted(t *testing.T) {
	// Reset metrics for test
	DrainInProgress.Reset()
	DrainPhase.Reset()
	DrainProgress.Reset()

	RecordDrainStarted("test-cluster", "default", "indexer")

	// Verify in progress is set to 1
	metric := &dto.Metric{}
	gauge, err := DrainInProgress.GetMetricWithLabelValues("test-cluster", "default", "indexer")
	if err != nil {
		t.Fatalf("Failed to get metric: %v", err)
	}

	if err := gauge.Write(metric); err != nil {
		t.Fatalf("Failed to write metric: %v", err)
	}

	if metric.Gauge.GetValue() != 1 {
		t.Errorf("Expected DrainInProgress value 1, got %f", metric.Gauge.GetValue())
	}

	// Verify phase is set to Draining (2)
	phaseGauge, _ := DrainPhase.GetMetricWithLabelValues("test-cluster", "default", "indexer")
	metric = &dto.Metric{}
	_ = phaseGauge.Write(metric)
	if metric.Gauge.GetValue() != 2 {
		t.Errorf("Expected DrainPhase value 2 (Draining), got %f", metric.Gauge.GetValue())
	}

	// Verify progress is 0
	progressGauge, _ := DrainProgress.GetMetricWithLabelValues("test-cluster", "default", "indexer")
	metric = &dto.Metric{}
	_ = progressGauge.Write(metric)
	if metric.Gauge.GetValue() != 0 {
		t.Errorf("Expected DrainProgress value 0, got %f", metric.Gauge.GetValue())
	}
}

func TestRecordDrainProgress(t *testing.T) {
	DrainProgress.Reset()

	RecordDrainProgress("test-cluster", "default", "indexer", 50.0)

	metric := &dto.Metric{}
	gauge, _ := DrainProgress.GetMetricWithLabelValues("test-cluster", "default", "indexer")
	_ = gauge.Write(metric)

	if metric.Gauge.GetValue() != 50.0 {
		t.Errorf("Expected progress value 50, got %f", metric.Gauge.GetValue())
	}
}

func TestRecordDrainCompleted(t *testing.T) {
	DrainInProgress.Reset()
	DrainPhase.Reset()
	DrainProgress.Reset()

	RecordDrainCompleted("test-cluster", "default", "indexer")

	// Verify in progress is set to 0
	metric := &dto.Metric{}
	gauge, _ := DrainInProgress.GetMetricWithLabelValues("test-cluster", "default", "indexer")
	_ = gauge.Write(metric)

	if metric.Gauge.GetValue() != 0 {
		t.Errorf("Expected DrainInProgress value 0, got %f", metric.Gauge.GetValue())
	}

	// Verify phase is Complete (4)
	phaseGauge, _ := DrainPhase.GetMetricWithLabelValues("test-cluster", "default", "indexer")
	metric = &dto.Metric{}
	_ = phaseGauge.Write(metric)
	if metric.Gauge.GetValue() != 4 {
		t.Errorf("Expected DrainPhase value 4 (Complete), got %f", metric.Gauge.GetValue())
	}

	// Verify progress is 100
	progressGauge, _ := DrainProgress.GetMetricWithLabelValues("test-cluster", "default", "indexer")
	metric = &dto.Metric{}
	_ = progressGauge.Write(metric)
	if metric.Gauge.GetValue() != 100 {
		t.Errorf("Expected DrainProgress value 100, got %f", metric.Gauge.GetValue())
	}
}

func TestRecordDrainFailed(t *testing.T) {
	DrainInProgress.Reset()
	DrainPhase.Reset()

	RecordDrainFailed("test-cluster", "default", "manager")

	// Verify in progress is set to 0
	metric := &dto.Metric{}
	gauge, _ := DrainInProgress.GetMetricWithLabelValues("test-cluster", "default", "manager")
	_ = gauge.Write(metric)

	if metric.Gauge.GetValue() != 0 {
		t.Errorf("Expected DrainInProgress value 0, got %f", metric.Gauge.GetValue())
	}

	// Verify phase is Failed (5)
	phaseGauge, _ := DrainPhase.GetMetricWithLabelValues("test-cluster", "default", "manager")
	metric = &dto.Metric{}
	_ = phaseGauge.Write(metric)
	if metric.Gauge.GetValue() != 5 {
		t.Errorf("Expected DrainPhase value 5 (Failed), got %f", metric.Gauge.GetValue())
	}
}

func TestRecordDrainRollback(t *testing.T) {
	DrainRollbacksTotal.Reset()
	DrainPhase.Reset()

	RecordDrainRollback("test-cluster", "default", "indexer")

	// Verify rollbacks counter incremented
	metric := &dto.Metric{}
	counter, _ := DrainRollbacksTotal.GetMetricWithLabelValues("test-cluster", "default", "indexer")
	_ = counter.Write(metric)

	if metric.Counter.GetValue() != 1 {
		t.Errorf("Expected rollback counter value 1, got %f", metric.Counter.GetValue())
	}

	// Verify phase is RollingBack (6)
	phaseGauge, _ := DrainPhase.GetMetricWithLabelValues("test-cluster", "default", "indexer")
	metric = &dto.Metric{}
	_ = phaseGauge.Write(metric)
	if metric.Gauge.GetValue() != 6 {
		t.Errorf("Expected DrainPhase value 6 (RollingBack), got %f", metric.Gauge.GetValue())
	}
}

func TestRecordDrainRetry(t *testing.T) {
	DrainRetriesTotal.Reset()
	DrainRetryCount.Reset()
	DrainPhase.Reset()

	RecordDrainRetry("test-cluster", "default", "indexer", 2)

	// Verify retries counter incremented
	metric := &dto.Metric{}
	counter, _ := DrainRetriesTotal.GetMetricWithLabelValues("test-cluster", "default", "indexer")
	_ = counter.Write(metric)

	if metric.Counter.GetValue() != 1 {
		t.Errorf("Expected retry counter value 1, got %f", metric.Counter.GetValue())
	}

	// Verify retry count gauge is set
	retryCountGauge, _ := DrainRetryCount.GetMetricWithLabelValues("test-cluster", "default", "indexer")
	metric = &dto.Metric{}
	_ = retryCountGauge.Write(metric)
	if metric.Gauge.GetValue() != 2 {
		t.Errorf("Expected retry count value 2, got %f", metric.Gauge.GetValue())
	}

	// Verify phase is Pending (1)
	phaseGauge, _ := DrainPhase.GetMetricWithLabelValues("test-cluster", "default", "indexer")
	metric = &dto.Metric{}
	_ = phaseGauge.Write(metric)
	if metric.Gauge.GetValue() != 1 {
		t.Errorf("Expected DrainPhase value 1 (Pending), got %f", metric.Gauge.GetValue())
	}
}

func TestRecordDryRunResult(t *testing.T) {
	DrainDryRunsTotal.Reset()

	// Test feasible result
	RecordDryRunResult("test-cluster", "default", true)

	metric := &dto.Metric{}
	counter, _ := DrainDryRunsTotal.GetMetricWithLabelValues("test-cluster", "default", "feasible")
	_ = counter.Write(metric)

	if metric.Counter.GetValue() != 1 {
		t.Errorf("Expected feasible counter value 1, got %f", metric.Counter.GetValue())
	}

	// Test not feasible result
	RecordDryRunResult("test-cluster", "default", false)

	counter2, _ := DrainDryRunsTotal.GetMetricWithLabelValues("test-cluster", "default", "not_feasible")
	metric = &dto.Metric{}
	_ = counter2.Write(metric)

	if metric.Counter.GetValue() != 1 {
		t.Errorf("Expected not_feasible counter value 1, got %f", metric.Counter.GetValue())
	}
}

func TestSetIndexerShardCount(t *testing.T) {
	IndexerShardCount.Reset()

	SetIndexerShardCount("test-cluster", "default", "indexer-0", 15)

	metric := &dto.Metric{}
	gauge, _ := IndexerShardCount.GetMetricWithLabelValues("test-cluster", "default", "indexer-0")
	_ = gauge.Write(metric)

	if metric.Gauge.GetValue() != 15 {
		t.Errorf("Expected shard count value 15, got %f", metric.Gauge.GetValue())
	}
}

func TestSetManagerQueueDepth(t *testing.T) {
	ManagerQueueDepth.Reset()

	SetManagerQueueDepth("test-cluster", "default", "manager-worker-0", 1000)

	metric := &dto.Metric{}
	gauge, _ := ManagerQueueDepth.GetMetricWithLabelValues("test-cluster", "default", "manager-worker-0")
	_ = gauge.Write(metric)

	if metric.Gauge.GetValue() != 1000 {
		t.Errorf("Expected queue depth value 1000, got %f", metric.Gauge.GetValue())
	}
}

func TestResetDrainMetrics(t *testing.T) {
	// Set some values first
	DrainInProgress.WithLabelValues("test-cluster", "default", "indexer").Set(1)
	DrainProgress.WithLabelValues("test-cluster", "default", "indexer").Set(50)
	DrainPhase.WithLabelValues("test-cluster", "default", "indexer").Set(2)
	DrainRetryCount.WithLabelValues("test-cluster", "default", "indexer").Set(3)

	// Reset them
	ResetDrainMetrics("test-cluster", "default", "indexer")

	// Verify all are reset
	tests := []struct {
		name     string
		gauge    prometheus.Gauge
		expected float64
	}{
		{"DrainInProgress", DrainInProgress.WithLabelValues("test-cluster", "default", "indexer"), 0},
		{"DrainProgress", DrainProgress.WithLabelValues("test-cluster", "default", "indexer"), 0},
		{"DrainPhase", DrainPhase.WithLabelValues("test-cluster", "default", "indexer"), 0},
		{"DrainRetryCount", DrainRetryCount.WithLabelValues("test-cluster", "default", "indexer"), 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metric := &dto.Metric{}
			_ = tt.gauge.Write(metric)
			if metric.Gauge.GetValue() != tt.expected {
				t.Errorf("Expected %s value %f, got %f", tt.name, tt.expected, metric.Gauge.GetValue())
			}
		})
	}
}

func TestPhaseToValue(t *testing.T) {
	tests := []struct {
		phase    string
		expected float64
	}{
		{"Idle", 0},
		{"Pending", 1},
		{"Draining", 2},
		{"Verifying", 3},
		{"Complete", 4},
		{"Failed", 5},
		{"RollingBack", 6},
		{"Unknown", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.phase, func(t *testing.T) {
			result := PhaseToValue(tt.phase)
			if result != tt.expected {
				t.Errorf("PhaseToValue(%s) = %f, expected %f", tt.phase, result, tt.expected)
			}
		})
	}
}
