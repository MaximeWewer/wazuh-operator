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

package reconciler

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/rolling"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// OrchestrateRollingRestart performs one step of a quorum-safe rolling restart
// for indexer StatefulSets. In simple mode, it handles a single StatefulSet.
// In advanced mode (NodePools), it iterates over each pool's StatefulSet.
//
// Returns nil result if no restart is needed.
func (r *IndexerReconciler) OrchestrateRollingRestart(ctx context.Context, cluster *wazuhv1.WazuhCluster) (_ *rolling.RestartResult, orchestrateErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "IndexerReconciler.OrchestrateRollingRestart",
		telemetry.WithAttributes(
			attribute.String("resource.name", cluster.Name),
			attribute.String("resource.namespace", cluster.Namespace),
		))
	defer span.End()
	defer func() {
		if orchestrateErr != nil {
			telemetry.RecordError(span, orchestrateErr)
		}
	}()

	log := logf.FromContext(ctx)
	startTime := time.Now()

	if cluster.Spec.Indexer == nil {
		return nil, nil
	}

	isAdvancedMode := cluster.Spec.Indexer.IsAdvancedMode()

	if isAdvancedMode {
		return r.orchestrateNodePoolRollingRestart(ctx, cluster)
	}

	// Simple mode: single StatefulSet
	stsName := constants.IndexerName(cluster.Name)
	sts := &appsv1.StatefulSet{}
	if err := r.Get(ctx, types.NamespacedName{Name: stsName, Namespace: cluster.Namespace}, sts); err != nil {
		return nil, fmt.Errorf("failed to get indexer StatefulSet %s: %w", stsName, err)
	}

	// Quick check: if no update pending, skip
	if sts.Status.UpdateRevision == sts.Status.CurrentRevision {
		return nil, nil
	}

	// Ensure we have an OpenSearch client for health checking
	if err := r.ensureOpenSearchClient(ctx, cluster); err != nil {
		log.V(1).Info("Cannot create OpenSearch client for health check, skipping rolling restart", "error", err)
		return nil, nil
	}

	metrics.SetDrainPhase(cluster.Name, cluster.Namespace, "indexer", metrics.PhaseToValue(constants.DrainPhaseDraining))

	desiredNodes := int(cluster.Spec.Indexer.Replicas)
	healthChecker := NewIndexerHealthChecker(r.osClient, desiredNodes)

	orchestrator := rolling.NewOrchestrator(r.Client)
	result, err := orchestrator.OrchestrateRestart(ctx, sts, healthChecker, true)
	if err != nil {
		metrics.SetDrainPhase(cluster.Name, cluster.Namespace, "indexer", metrics.PhaseToValue(constants.DrainPhaseFailed))
		return nil, fmt.Errorf("rolling restart failed for indexer: %w", err)
	}

	if result.Phase == rolling.RestartPhaseInProgress && result.CurrentPod != "" {
		r.Recorder.Eventf(cluster, corev1.EventTypeNormal, constants.EventReasonRollingRestartProgress,
			"Rolling restart: deleted indexer pod %s (%d/%d updated)", result.CurrentPod, result.UpdatedPods, result.TotalPods)
	}
	if result.Phase == rolling.RestartPhaseComplete {
		// Only emit event/metrics if status was tracking an active restart (avoids repeated events)
		if cluster.Status.RollingRestart != nil && cluster.Status.RollingRestart.Indexer != nil {
			metrics.SetDrainPhase(cluster.Name, cluster.Namespace, "indexer", metrics.PhaseToValue(constants.DrainPhaseComplete))
			metrics.ObserveDrainDuration(cluster.Name, cluster.Namespace, "indexer", time.Since(startTime).Seconds())
			r.Recorder.Event(cluster, corev1.EventTypeNormal, constants.EventReasonRollingRestartComplete,
				"Rolling restart complete for indexer")
		}
	}

	return result, nil
}

// orchestrateNodePoolRollingRestart handles rolling restarts for advanced mode (NodePools).
// It iterates over each pool and restarts one pod at a time across all pools.
func (r *IndexerReconciler) orchestrateNodePoolRollingRestart(ctx context.Context, cluster *wazuhv1.WazuhCluster) (*rolling.RestartResult, error) {
	log := logf.FromContext(ctx)
	startTime := time.Now()

	if err := r.ensureOpenSearchClient(ctx, cluster); err != nil {
		log.V(1).Info("Cannot create OpenSearch client for health check, skipping rolling restart", "error", err)
		return nil, nil
	}

	metrics.SetDrainPhase(cluster.Name, cluster.Namespace, "indexer", metrics.PhaseToValue(constants.DrainPhaseDraining))

	totalDesiredNodes := int(cluster.Spec.Indexer.GetTotalReplicas())
	healthChecker := NewIndexerHealthChecker(r.osClient, totalDesiredNodes)
	orchestrator := rolling.NewOrchestrator(r.Client)

	// Aggregate result across all pools
	var aggregatedTotalPods, aggregatedUpdatedPods int32

	for _, pool := range cluster.Spec.Indexer.NodePools {
		stsName := constants.IndexerNodePoolName(cluster.Name, pool.Name)
		sts := &appsv1.StatefulSet{}
		if err := r.Get(ctx, types.NamespacedName{Name: stsName, Namespace: cluster.Namespace}, sts); err != nil {
			log.V(1).Info("NodePool StatefulSet not found, skipping", "pool", pool.Name, "error", err)
			continue
		}

		aggregatedTotalPods += sts.Status.Replicas

		// If this pool needs no update, count all pods as updated
		if sts.Status.UpdateRevision == sts.Status.CurrentRevision {
			aggregatedUpdatedPods += sts.Status.Replicas
			continue
		}

		result, err := orchestrator.OrchestrateRestart(ctx, sts, healthChecker, true)
		if err != nil {
			metrics.SetDrainPhase(cluster.Name, cluster.Namespace, "indexer", metrics.PhaseToValue(constants.DrainPhaseFailed))
			return nil, fmt.Errorf("rolling restart failed for nodePool %s: %w", pool.Name, err)
		}

		aggregatedUpdatedPods += result.UpdatedPods

		if result.Phase == rolling.RestartPhaseInProgress {
			if result.CurrentPod != "" {
				r.Recorder.Eventf(cluster, corev1.EventTypeNormal, constants.EventReasonRollingRestartProgress,
					"Rolling restart: deleted indexer pod %s in pool %s (%d/%d updated)", result.CurrentPod, pool.Name, result.UpdatedPods, result.TotalPods)
			}
			// Only restart one pod at a time across all pools
			return &rolling.RestartResult{
				Phase:       rolling.RestartPhaseInProgress,
				TotalPods:   aggregatedTotalPods,
				UpdatedPods: aggregatedUpdatedPods,
				CurrentPod:  result.CurrentPod,
				Message:     fmt.Sprintf("pool %s: %s", pool.Name, result.Message),
			}, nil
		}
	}

	if aggregatedTotalPods == 0 {
		return nil, nil
	}

	// All pools complete — only emit event/metrics if status was tracking an active restart
	if cluster.Status.RollingRestart != nil && cluster.Status.RollingRestart.Indexer != nil {
		metrics.SetDrainPhase(cluster.Name, cluster.Namespace, "indexer", metrics.PhaseToValue(constants.DrainPhaseComplete))
		metrics.ObserveDrainDuration(cluster.Name, cluster.Namespace, "indexer", time.Since(startTime).Seconds())
		r.Recorder.Event(cluster, corev1.EventTypeNormal, constants.EventReasonRollingRestartComplete,
			"Rolling restart complete for all indexer node pools")
	}

	return &rolling.RestartResult{
		Phase:       rolling.RestartPhaseComplete,
		TotalPods:   aggregatedTotalPods,
		UpdatedPods: aggregatedUpdatedPods,
		Message:     "all node pools updated",
	}, nil
}
