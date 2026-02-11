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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"go.opentelemetry.io/otel/attribute"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/rolling"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// OrchestrateManagerRollingRestart performs one step of a quorum-safe rolling restart
// for manager StatefulSets. Workers are restarted first (highest ordinal first),
// then the master is restarted after all workers are complete.
//
// Returns nil results for components that don't need a restart.
func (r *ClusterReconciler) OrchestrateManagerRollingRestart(ctx context.Context, cluster *wazuhv1.WazuhCluster) (masterResult, workerResult *rolling.RestartResult, err error) {
	ctx, span := telemetry.Tracer().Start(ctx, "ClusterReconciler.OrchestrateManagerRollingRestart",
		telemetry.WithAttributes(
			attribute.String("resource.name", cluster.Name),
			attribute.String("resource.namespace", cluster.Namespace),
		))
	defer span.End()
	defer func() {
		if err != nil {
			telemetry.RecordError(span, err)
		}
	}()

	log := logf.FromContext(ctx)
	startTime := time.Now()

	if cluster.Spec.Manager == nil {
		return nil, nil, nil
	}

	orchestrator := rolling.NewOrchestrator(r.Client)

	// Step 1: Handle workers first (if any)
	metrics.SetDrainPhase(cluster.Name, cluster.Namespace, "manager-worker", metrics.PhaseToValue(constants.DrainPhaseDraining))
	workerResult, err = r.orchestrateWorkerRestart(ctx, cluster, orchestrator)
	if err != nil {
		metrics.SetDrainPhase(cluster.Name, cluster.Namespace, "manager-worker", metrics.PhaseToValue(constants.DrainPhaseFailed))
		return nil, nil, fmt.Errorf("worker rolling restart failed: %w", err)
	}

	// If workers are still in progress, don't start master restart yet
	if workerResult != nil && workerResult.Phase == rolling.RestartPhaseInProgress {
		log.V(1).Info("Waiting for worker rolling restart to complete before restarting master")
		return nil, workerResult, nil
	}

	if workerResult != nil && workerResult.Phase == rolling.RestartPhaseComplete {
		metrics.SetDrainPhase(cluster.Name, cluster.Namespace, "manager-worker", metrics.PhaseToValue(constants.DrainPhaseComplete))
		metrics.ObserveDrainDuration(cluster.Name, cluster.Namespace, "manager-worker", time.Since(startTime).Seconds())
	}

	// Step 2: Handle master after workers are complete
	metrics.SetDrainPhase(cluster.Name, cluster.Namespace, "manager-master", metrics.PhaseToValue(constants.DrainPhaseDraining))
	masterResult, err = r.orchestrateMasterRestart(ctx, cluster, orchestrator)
	if err != nil {
		metrics.SetDrainPhase(cluster.Name, cluster.Namespace, "manager-master", metrics.PhaseToValue(constants.DrainPhaseFailed))
		return nil, workerResult, fmt.Errorf("master rolling restart failed: %w", err)
	}

	if masterResult != nil && masterResult.Phase == rolling.RestartPhaseComplete {
		metrics.SetDrainPhase(cluster.Name, cluster.Namespace, "manager-master", metrics.PhaseToValue(constants.DrainPhaseComplete))
		metrics.ObserveDrainDuration(cluster.Name, cluster.Namespace, "manager-master", time.Since(startTime).Seconds())
	}

	return masterResult, workerResult, nil
}

// orchestrateWorkerRestart handles rolling restart for the worker StatefulSet.
func (r *ClusterReconciler) orchestrateWorkerRestart(ctx context.Context, cluster *wazuhv1.WazuhCluster, orchestrator *rolling.RollingRestartOrchestrator) (*rolling.RestartResult, error) {
	workerStsName := constants.ManagerWorkersName(cluster.Name)
	workerSts := &appsv1.StatefulSet{}
	if err := r.Get(ctx, types.NamespacedName{Name: workerStsName, Namespace: cluster.Namespace}, workerSts); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get worker StatefulSet: %w", err)
	}

	// Quick check: if no update pending, skip
	if workerSts.Status.UpdateRevision == workerSts.Status.CurrentRevision {
		return nil, nil
	}

	// Worker health checker: ensure all worker pods are ready before deleting next one
	workerLabels := constants.SelectorLabels(cluster.Name, "wazuh-manager")
	workerLabels[constants.LabelManagerNodeType] = "worker"
	healthChecker := NewManagerWorkerHealthChecker(r.Client, cluster.Namespace, workerLabels)

	result, err := orchestrator.OrchestrateRestart(ctx, workerSts, healthChecker, true)
	if err != nil {
		return nil, err
	}

	if result.Phase == rolling.RestartPhaseInProgress && result.CurrentPod != "" {
		r.Recorder.Eventf(cluster, corev1.EventTypeNormal, constants.EventReasonRollingRestartProgress,
			"Rolling restart: deleted worker pod %s (%d/%d updated)", result.CurrentPod, result.UpdatedPods, result.TotalPods)
	}
	if result.Phase == rolling.RestartPhaseComplete {
		r.Recorder.Event(cluster, corev1.EventTypeNormal, constants.EventReasonRollingRestartComplete,
			"Rolling restart complete for manager workers")
	}

	return result, nil
}

// orchestrateMasterRestart handles rolling restart for the master StatefulSet.
// Master is a single pod, so health check is just pod readiness.
func (r *ClusterReconciler) orchestrateMasterRestart(ctx context.Context, cluster *wazuhv1.WazuhCluster, orchestrator *rolling.RollingRestartOrchestrator) (*rolling.RestartResult, error) {
	masterStsName := constants.ManagerMasterName(cluster.Name)
	masterSts := &appsv1.StatefulSet{}
	if err := r.Get(ctx, types.NamespacedName{Name: masterStsName, Namespace: cluster.Namespace}, masterSts); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get master StatefulSet: %w", err)
	}

	// Quick check: if no update pending, skip
	if masterSts.Status.UpdateRevision == masterSts.Status.CurrentRevision {
		return nil, nil
	}

	// Master health checker: use master selector labels to check readiness
	masterLabels := constants.SelectorLabels(cluster.Name, "wazuh-manager")
	healthChecker := NewManagerWorkerHealthChecker(r.Client, cluster.Namespace, masterLabels)

	result, err := orchestrator.OrchestrateRestart(ctx, masterSts, healthChecker, true)
	if err != nil {
		return nil, err
	}

	if result.Phase == rolling.RestartPhaseInProgress && result.CurrentPod != "" {
		r.Recorder.Eventf(cluster, corev1.EventTypeNormal, constants.EventReasonRollingRestartProgress,
			"Rolling restart: deleted master pod %s", result.CurrentPod)
	}
	if result.Phase == rolling.RestartPhaseComplete {
		r.Recorder.Event(cluster, corev1.EventTypeNormal, constants.EventReasonRollingRestartComplete,
			"Rolling restart complete for manager master")
	}

	return result, nil
}
