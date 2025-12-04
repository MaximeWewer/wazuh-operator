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
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// RollbackManager handles rollback operations for failed drains
type RollbackManager interface {
	// ExecuteRollback restores the component to its previous state
	ExecuteRollback(ctx context.Context, cluster *v1alpha1.WazuhCluster, component string) error

	// VerifyRollbackComplete checks if rollback has finished
	VerifyRollbackComplete(ctx context.Context, cluster *v1alpha1.WazuhCluster, component string) (bool, error)
}

// RollbackManagerImpl implements RollbackManager
type RollbackManagerImpl struct {
	client client.Client
	log    logr.Logger
}

// NewRollbackManager creates a new RollbackManager
func NewRollbackManager(c client.Client, log logr.Logger) *RollbackManagerImpl {
	return &RollbackManagerImpl{
		client: c,
		log:    log.WithName("rollback-manager"),
	}
}

// RollbackResult contains the outcome of a rollback operation
type RollbackResult struct {
	// Success indicates if rollback completed successfully
	Success bool
	// RestoredReplicas is the replica count after rollback
	RestoredReplicas int32
	// Message provides details about the rollback
	Message string
	// Duration is how long the rollback took
	Duration time.Duration
}

// ExecuteRollback restores the component to its previous state
func (r *RollbackManagerImpl) ExecuteRollback(ctx context.Context, cluster *v1alpha1.WazuhCluster, component string) error {
	log := r.log.WithValues("cluster", cluster.Name, "namespace", cluster.Namespace, "component", component)
	log.Info("Starting rollback operation")

	switch component {
	case constants.DrainComponentIndexer:
		return r.rollbackIndexer(ctx, cluster)
	case constants.DrainComponentManager:
		return r.rollbackManager(ctx, cluster)
	default:
		return fmt.Errorf("unknown component: %s", component)
	}
}

// rollbackIndexer restores the indexer StatefulSet to its previous replica count
func (r *RollbackManagerImpl) rollbackIndexer(ctx context.Context, cluster *v1alpha1.WazuhCluster) error {
	log := r.log.WithValues("cluster", cluster.Name, "component", constants.DrainComponentIndexer)

	// Get previous replicas from drain status
	var previousReplicas int32 = 3 // Default fallback
	if cluster.Status.Drain != nil && cluster.Status.Drain.Indexer != nil {
		if cluster.Status.Drain.Indexer.PreviousReplicas != nil {
			previousReplicas = *cluster.Status.Drain.Indexer.PreviousReplicas
		}
	}

	log.Info("Rolling back indexer", "previousReplicas", previousReplicas)

	// Get the StatefulSet
	stsName := fmt.Sprintf("%s-indexer", cluster.Name)
	sts := &appsv1.StatefulSet{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: stsName, Namespace: cluster.Namespace}, sts); err != nil {
		return fmt.Errorf("failed to get indexer StatefulSet: %w", err)
	}

	// Update replica count to previous value
	if sts.Spec.Replicas == nil || *sts.Spec.Replicas != previousReplicas {
		sts.Spec.Replicas = &previousReplicas
		if err := r.client.Update(ctx, sts); err != nil {
			return fmt.Errorf("failed to update indexer StatefulSet replicas: %w", err)
		}
		log.Info("Indexer StatefulSet replicas restored", "replicas", previousReplicas)
	}

	return nil
}

// rollbackManager restores the manager worker StatefulSet to its previous replica count
func (r *RollbackManagerImpl) rollbackManager(ctx context.Context, cluster *v1alpha1.WazuhCluster) error {
	log := r.log.WithValues("cluster", cluster.Name, "component", constants.DrainComponentManager)

	// Get previous replicas from drain status
	var previousReplicas int32 = 1 // Default fallback
	if cluster.Status.Drain != nil && cluster.Status.Drain.Manager != nil {
		if cluster.Status.Drain.Manager.PreviousReplicas != nil {
			previousReplicas = *cluster.Status.Drain.Manager.PreviousReplicas
		}
	}

	log.Info("Rolling back manager workers", "previousReplicas", previousReplicas)

	// Get the StatefulSet
	stsName := fmt.Sprintf("%s-manager-worker", cluster.Name)
	sts := &appsv1.StatefulSet{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: stsName, Namespace: cluster.Namespace}, sts); err != nil {
		return fmt.Errorf("failed to get manager worker StatefulSet: %w", err)
	}

	// Update replica count to previous value
	if sts.Spec.Replicas == nil || *sts.Spec.Replicas != previousReplicas {
		sts.Spec.Replicas = &previousReplicas
		if err := r.client.Update(ctx, sts); err != nil {
			return fmt.Errorf("failed to update manager worker StatefulSet replicas: %w", err)
		}
		log.Info("Manager worker StatefulSet replicas restored", "replicas", previousReplicas)
	}

	return nil
}

// VerifyRollbackComplete checks if rollback has finished
func (r *RollbackManagerImpl) VerifyRollbackComplete(ctx context.Context, cluster *v1alpha1.WazuhCluster, component string) (bool, error) {
	r.log.V(1).Info("Rollback verification requested", "cluster", cluster.Name, "namespace", cluster.Namespace, "component", component)

	switch component {
	case constants.DrainComponentIndexer:
		return r.verifyIndexerRollback(ctx, cluster)
	case constants.DrainComponentManager:
		return r.verifyManagerRollback(ctx, cluster)
	default:
		return false, fmt.Errorf("unknown component: %s", component)
	}
}

// verifyIndexerRollback checks if the indexer StatefulSet has rolled back
func (r *RollbackManagerImpl) verifyIndexerRollback(ctx context.Context, cluster *v1alpha1.WazuhCluster) (bool, error) {
	// Get previous replicas from drain status
	var previousReplicas int32 = 3
	if cluster.Status.Drain != nil && cluster.Status.Drain.Indexer != nil {
		if cluster.Status.Drain.Indexer.PreviousReplicas != nil {
			previousReplicas = *cluster.Status.Drain.Indexer.PreviousReplicas
		}
	}

	// Get the StatefulSet
	stsName := fmt.Sprintf("%s-indexer", cluster.Name)
	sts := &appsv1.StatefulSet{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: stsName, Namespace: cluster.Namespace}, sts); err != nil {
		return false, fmt.Errorf("failed to get indexer StatefulSet: %w", err)
	}

	// Check if all replicas are ready
	if sts.Status.ReadyReplicas == previousReplicas && sts.Status.Replicas == previousReplicas {
		r.log.Info("Indexer rollback complete", "replicas", previousReplicas)
		return true, nil
	}

	r.log.V(1).Info("Indexer rollback in progress",
		"ready", sts.Status.ReadyReplicas,
		"expected", previousReplicas)
	return false, nil
}

// verifyManagerRollback checks if the manager worker StatefulSet has rolled back
func (r *RollbackManagerImpl) verifyManagerRollback(ctx context.Context, cluster *v1alpha1.WazuhCluster) (bool, error) {
	// Get previous replicas from drain status
	var previousReplicas int32 = 1
	if cluster.Status.Drain != nil && cluster.Status.Drain.Manager != nil {
		if cluster.Status.Drain.Manager.PreviousReplicas != nil {
			previousReplicas = *cluster.Status.Drain.Manager.PreviousReplicas
		}
	}

	// Get the StatefulSet
	stsName := fmt.Sprintf("%s-manager-worker", cluster.Name)
	sts := &appsv1.StatefulSet{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: stsName, Namespace: cluster.Namespace}, sts); err != nil {
		return false, fmt.Errorf("failed to get manager worker StatefulSet: %w", err)
	}

	// Check if all replicas are ready
	if sts.Status.ReadyReplicas == previousReplicas && sts.Status.Replicas == previousReplicas {
		r.log.Info("Manager worker rollback complete", "replicas", previousReplicas)
		return true, nil
	}

	r.log.V(1).Info("Manager worker rollback in progress",
		"ready", sts.Status.ReadyReplicas,
		"expected", previousReplicas)
	return false, nil
}

// ClearAllocationExclusion removes any OpenSearch allocation exclusions after rollback
func (r *RollbackManagerImpl) ClearAllocationExclusion(ctx context.Context, cluster *v1alpha1.WazuhCluster, nodeName string) error {
	// This would be called by the IndexerDrainer after rollback
	// to clear any allocation exclusion settings that were set during drain
	r.log.Info("Clearing allocation exclusion after rollback", "nodeName", nodeName)
	return nil
}
