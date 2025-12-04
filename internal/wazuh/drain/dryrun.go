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

package drain

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// DryRunEvaluator evaluates drain feasibility without executing
type DryRunEvaluator interface {
	// EvaluateIndexerDrain checks if indexer drain is feasible
	EvaluateIndexerDrain(ctx context.Context, cluster *v1alpha1.WazuhCluster, targetNode string) (*v1alpha1.DryRunResult, error)

	// EvaluateManagerDrain checks if manager drain is feasible
	EvaluateManagerDrain(ctx context.Context, cluster *v1alpha1.WazuhCluster, targetNode string) (*v1alpha1.DryRunResult, error)

	// EvaluateDashboard checks dashboard PDB constraints
	EvaluateDashboard(ctx context.Context, cluster *v1alpha1.WazuhCluster) (*v1alpha1.DryRunResult, error)

	// EvaluateAll runs all evaluations and returns combined result
	EvaluateAll(ctx context.Context, cluster *v1alpha1.WazuhCluster) (*v1alpha1.DryRunResult, error)
}

// IndexerDrainEvaluator evaluates indexer drain feasibility
type IndexerDrainEvaluator interface {
	EvaluateFeasibility(ctx context.Context, nodeName string) (*v1alpha1.DryRunResult, error)
}

// ManagerDrainEvaluator evaluates manager drain feasibility
type ManagerDrainEvaluator interface {
	EvaluateFeasibility(ctx context.Context, nodeName string) (*v1alpha1.DryRunResult, error)
}

// DryRunEvaluatorImpl implements DryRunEvaluator
type DryRunEvaluatorImpl struct {
	client           client.Client
	log              logr.Logger
	indexerEvaluator IndexerDrainEvaluator
	managerEvaluator ManagerDrainEvaluator
}

// NewDryRunEvaluator creates a new DryRunEvaluator
func NewDryRunEvaluator(c client.Client, log logr.Logger, indexerEval IndexerDrainEvaluator, managerEval ManagerDrainEvaluator) *DryRunEvaluatorImpl {
	return &DryRunEvaluatorImpl{
		client:           c,
		log:              log.WithName("dryrun-evaluator"),
		indexerEvaluator: indexerEval,
		managerEvaluator: managerEval,
	}
}

// EvaluateIndexerDrain checks if indexer drain is feasible
func (e *DryRunEvaluatorImpl) EvaluateIndexerDrain(ctx context.Context, cluster *v1alpha1.WazuhCluster, targetNode string) (*v1alpha1.DryRunResult, error) {
	e.log.Info("Evaluating indexer drain feasibility", "cluster", cluster.Name, "targetNode", targetNode)

	if e.indexerEvaluator == nil {
		return &v1alpha1.DryRunResult{
			Feasible:    false,
			EvaluatedAt: metav1.Now(),
			Component:   constants.DrainComponentIndexer,
			Blockers:    []string{"Indexer drain evaluator not configured"},
		}, nil
	}

	result, err := e.indexerEvaluator.EvaluateFeasibility(ctx, targetNode)
	if err != nil {
		return &v1alpha1.DryRunResult{
			Feasible:    false,
			EvaluatedAt: metav1.Now(),
			Component:   constants.DrainComponentIndexer,
			Blockers:    []string{fmt.Sprintf("Failed to evaluate: %v", err)},
		}, nil
	}

	e.log.Info("Indexer drain evaluation complete",
		"feasible", result.Feasible,
		"blockers", len(result.Blockers),
		"warnings", len(result.Warnings))

	return result, nil
}

// EvaluateManagerDrain checks if manager drain is feasible
func (e *DryRunEvaluatorImpl) EvaluateManagerDrain(ctx context.Context, cluster *v1alpha1.WazuhCluster, targetNode string) (*v1alpha1.DryRunResult, error) {
	e.log.Info("Evaluating manager drain feasibility", "cluster", cluster.Name, "targetNode", targetNode)

	if e.managerEvaluator == nil {
		return &v1alpha1.DryRunResult{
			Feasible:    false,
			EvaluatedAt: metav1.Now(),
			Component:   constants.DrainComponentManager,
			Blockers:    []string{"Manager drain evaluator not configured"},
		}, nil
	}

	result, err := e.managerEvaluator.EvaluateFeasibility(ctx, targetNode)
	if err != nil {
		return &v1alpha1.DryRunResult{
			Feasible:    false,
			EvaluatedAt: metav1.Now(),
			Component:   constants.DrainComponentManager,
			Blockers:    []string{fmt.Sprintf("Failed to evaluate: %v", err)},
		}, nil
	}

	e.log.Info("Manager drain evaluation complete",
		"feasible", result.Feasible,
		"blockers", len(result.Blockers),
		"warnings", len(result.Warnings))

	return result, nil
}

// EvaluateDashboard checks dashboard PDB constraints
func (e *DryRunEvaluatorImpl) EvaluateDashboard(ctx context.Context, cluster *v1alpha1.WazuhCluster) (*v1alpha1.DryRunResult, error) {
	e.log.Info("Evaluating dashboard PDB constraints", "cluster", cluster.Name)

	result := &v1alpha1.DryRunResult{
		Feasible:    true,
		EvaluatedAt: metav1.Now(),
		Component:   constants.DrainComponentDashboard,
	}

	// Check if Dashboard is configured
	if cluster.Spec.Dashboard == nil {
		result.Warnings = append(result.Warnings, "Dashboard not configured in cluster spec")
		return result, nil
	}

	// Check Dashboard replicas
	replicas := cluster.Spec.Dashboard.Replicas
	if replicas == 0 {
		replicas = 1 // Default
	}

	// Check if PDB exists
	pdbName := fmt.Sprintf("%s-dashboard", cluster.Name)
	pdb := &policyv1.PodDisruptionBudget{}
	err := e.client.Get(ctx, types.NamespacedName{Name: pdbName, Namespace: cluster.Namespace}, pdb)

	if err != nil && errors.IsNotFound(err) {
		result.Warnings = append(result.Warnings, "No PodDisruptionBudget found for Dashboard")
	} else if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to check PDB: %v", err))
	} else {
		// PDB exists, check constraints
		if pdb.Spec.MinAvailable != nil {
			minAvailable := pdb.Spec.MinAvailable.IntValue()
			if int32(minAvailable) >= replicas {
				result.Feasible = false
				result.Blockers = append(result.Blockers,
					fmt.Sprintf("PDB minAvailable (%d) >= replicas (%d): cannot scale down", minAvailable, replicas))
			} else {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("PDB protects Dashboard with minAvailable=%d", minAvailable))
			}
		}
		if pdb.Spec.MaxUnavailable != nil {
			maxUnavailable := pdb.Spec.MaxUnavailable.IntValue()
			if maxUnavailable == 0 {
				result.Feasible = false
				result.Blockers = append(result.Blockers,
					"PDB maxUnavailable is 0: cannot scale down")
			}
		}
	}

	// Check if scaling to 0
	if replicas == 1 {
		result.Warnings = append(result.Warnings,
			"Dashboard has only 1 replica: scaling down would remove all Dashboard instances")
	}

	// Estimate duration (dashboard has no drain, just PDB check)
	result.EstimatedDuration = &metav1.Duration{Duration: 30 * time.Second}

	e.log.Info("Dashboard evaluation complete",
		"feasible", result.Feasible,
		"blockers", len(result.Blockers),
		"warnings", len(result.Warnings))

	return result, nil
}

// EvaluateAll runs all evaluations and returns combined result
func (e *DryRunEvaluatorImpl) EvaluateAll(ctx context.Context, cluster *v1alpha1.WazuhCluster) (*v1alpha1.DryRunResult, error) {
	e.log.Info("Running comprehensive dry-run evaluation", "cluster", cluster.Name)

	combinedResult := &v1alpha1.DryRunResult{
		Feasible:    true,
		EvaluatedAt: metav1.Now(),
		Component:   "all",
	}

	var totalDuration time.Duration

	// Evaluate each component and combine results
	components := []struct {
		name     string
		evaluate func() (*v1alpha1.DryRunResult, error)
	}{
		{
			name: constants.DrainComponentIndexer,
			evaluate: func() (*v1alpha1.DryRunResult, error) {
				// Get target node for indexer (highest index pod that would be removed)
				targetNode := e.getTargetIndexerNode(cluster)
				if targetNode == "" {
					return &v1alpha1.DryRunResult{
						Feasible:    true,
						EvaluatedAt: metav1.Now(),
						Component:   constants.DrainComponentIndexer,
						Warnings:    []string{"No indexer scale-down detected"},
					}, nil
				}
				return e.EvaluateIndexerDrain(ctx, cluster, targetNode)
			},
		},
		{
			name: constants.DrainComponentManager,
			evaluate: func() (*v1alpha1.DryRunResult, error) {
				// Get target node for manager (highest index pod that would be removed)
				targetNode := e.getTargetManagerNode(cluster)
				if targetNode == "" {
					return &v1alpha1.DryRunResult{
						Feasible:    true,
						EvaluatedAt: metav1.Now(),
						Component:   constants.DrainComponentManager,
						Warnings:    []string{"No manager scale-down detected"},
					}, nil
				}
				return e.EvaluateManagerDrain(ctx, cluster, targetNode)
			},
		},
		{
			name: constants.DrainComponentDashboard,
			evaluate: func() (*v1alpha1.DryRunResult, error) {
				return e.EvaluateDashboard(ctx, cluster)
			},
		},
	}

	for _, comp := range components {
		result, err := comp.evaluate()
		if err != nil {
			e.log.Error(err, "Failed to evaluate component", "component", comp.name)
			combinedResult.Warnings = append(combinedResult.Warnings,
				fmt.Sprintf("%s: evaluation failed: %v", comp.name, err))
			continue
		}

		// Merge results
		if !result.Feasible {
			combinedResult.Feasible = false
		}

		// Prefix blockers and warnings with component name
		for _, blocker := range result.Blockers {
			combinedResult.Blockers = append(combinedResult.Blockers,
				fmt.Sprintf("[%s] %s", comp.name, blocker))
		}
		for _, warning := range result.Warnings {
			combinedResult.Warnings = append(combinedResult.Warnings,
				fmt.Sprintf("[%s] %s", comp.name, warning))
		}

		// Sum durations
		if result.EstimatedDuration != nil {
			totalDuration += result.EstimatedDuration.Duration
		}
	}

	if totalDuration > 0 {
		combinedResult.EstimatedDuration = &metav1.Duration{Duration: totalDuration}
	}

	e.log.Info("Comprehensive dry-run evaluation complete",
		"feasible", combinedResult.Feasible,
		"blockers", len(combinedResult.Blockers),
		"warnings", len(combinedResult.Warnings),
		"estimatedDuration", totalDuration)

	return combinedResult, nil
}

// getTargetIndexerNode determines the target node for indexer evaluation
func (e *DryRunEvaluatorImpl) getTargetIndexerNode(cluster *v1alpha1.WazuhCluster) string {
	// If drain status has a target pod, use it
	if cluster.Status.Drain != nil && cluster.Status.Drain.Indexer != nil {
		if cluster.Status.Drain.Indexer.TargetPod != "" {
			return cluster.Status.Drain.Indexer.TargetPod
		}
	}

	// Otherwise, calculate based on spec vs status replicas
	var desiredReplicas int32 = 3 // Default
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.Replicas > 0 {
		desiredReplicas = cluster.Spec.Indexer.Replicas
	}

	var currentReplicas int32 = 0
	if cluster.Status.Indexer != nil {
		currentReplicas = cluster.Status.Indexer.Replicas
	}

	if desiredReplicas < currentReplicas {
		// Scale down detected - target is highest index pod
		return fmt.Sprintf("%s-indexer-%d", cluster.Name, currentReplicas-1)
	}

	return ""
}

// getTargetManagerNode determines the target node for manager evaluation
func (e *DryRunEvaluatorImpl) getTargetManagerNode(cluster *v1alpha1.WazuhCluster) string {
	// If drain status has a target pod, use it
	if cluster.Status.Drain != nil && cluster.Status.Drain.Manager != nil {
		if cluster.Status.Drain.Manager.TargetPod != "" {
			return cluster.Status.Drain.Manager.TargetPod
		}
	}

	// Otherwise, calculate based on spec vs status replicas
	var desiredReplicas int32 = 0
	if cluster.Spec.Manager != nil {
		desiredReplicas = cluster.Spec.Manager.Workers.GetReplicas()
	}

	// Manager status is the combined status - for workers we need to check
	// the actual StatefulSet replicas. For now, use the drain target replicas
	// from the drain status if available.
	var currentReplicas int32 = 0
	if cluster.Status.Drain != nil && cluster.Status.Drain.Manager != nil {
		if cluster.Status.Drain.Manager.PreviousReplicas != nil {
			currentReplicas = *cluster.Status.Drain.Manager.PreviousReplicas
		}
	}

	if currentReplicas == 0 && desiredReplicas > 0 {
		// No drain in progress, can't detect scale-down from status alone
		// Return empty to indicate no evaluation needed
		return ""
	}

	if desiredReplicas < currentReplicas {
		// Scale down detected - target is highest index pod
		return fmt.Sprintf("%s-manager-worker-%d", cluster.Name, currentReplicas-1)
	}

	return ""
}
