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

	"go.opentelemetry.io/otel/attribute"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	retry "k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/security"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/patch"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// IndexReconciler handles reconciliation of OpenSearch indices
type IndexReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	ClientFactory *security.OpenSearchClientFactory
}

// NewIndexReconciler creates a new IndexReconciler
func NewIndexReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *IndexReconciler {
	return &IndexReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: recorder,
	}
}

// WithClientFactory sets the OpenSearch client factory for dynamic client resolution
func (r *IndexReconciler) WithClientFactory(factory *security.OpenSearchClientFactory) *IndexReconciler {
	r.ClientFactory = factory
	return r
}

// Reconcile reconciles an OpenSearch index
func (r *IndexReconciler) Reconcile(ctx context.Context, index *wazuhv1.OpenSearchIndex) (reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "IndexReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", index.Name),
			attribute.String("resource.namespace", index.Namespace),
		))
	defer span.End()
	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	log := logf.FromContext(ctx)

	// Handle finalizer
	if !controllerutil.ContainsFinalizer(index, constants.IndexFinalizer) {
		controllerutil.AddFinalizer(index, constants.IndexFinalizer)
		if err := r.Update(ctx, index); err != nil {
			return fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	// Check if being deleted
	if !index.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, index)
	}

	indexName := index.Name
	specHash, _ := patch.ComputeSpecHash(index.Spec)
	settings := r.buildIndexSettings(index)
	dynamicSettings := r.buildDynamicSettings(index)

	newStatuses := make([]wazuhv1.OpenSearchClusterStatus, 0, len(index.Spec.ClusterRefs))
	anyFailed := false
	anyPending := false
	allReady := len(index.Spec.ClusterRefs) > 0
	var firstErr error
	existingByKey := make(map[string]wazuhv1.OpenSearchClusterStatus, len(index.Status.ClusterStatuses))
	for _, s := range index.Status.ClusterStatuses {
		existingByKey[s.Namespace+"/"+s.Name] = s
	}

	for _, ref := range index.Spec.ClusterRefs {
		st := existingByKey[ref.Namespace+"/"+ref.Name]
		st.Name = ref.Name
		st.Namespace = ref.Namespace

		osClient, err := r.getOpenSearchClientForRef(ctx, ref)
		if err != nil {
			st.Phase = wazuhv1.OpenSearchResourcePhasePending
			st.Message = fmt.Sprintf("Failed to connect: %v", err)
			anyPending = true
			allReady = false
			if firstErr == nil {
				firstErr = err
			}
			r.recordEvent(index, corev1.EventTypeWarning, "ConnectionError",
				fmt.Sprintf("Failed to connect to %s/%s: %v", ref.Namespace, ref.Name, err))
			newStatuses = append(newStatuses, st)
			continue
		}
		exists, err := osClient.IndexExists(ctx, indexName)
		if err != nil {
			st.Phase = wazuhv1.OpenSearchResourcePhaseFailed
			st.Message = fmt.Sprintf("Failed to check index: %v", err)
			anyFailed = true
			allReady = false
			if firstErr == nil {
				firstErr = err
			}
			r.recordEvent(index, corev1.EventTypeWarning, "CheckFailed",
				fmt.Sprintf("Failed to check index on %s/%s: %v", ref.Namespace, ref.Name, err))
			newStatuses = append(newStatuses, st)
			continue
		}
		if !exists {
			if err := osClient.CreateIndex(ctx, indexName, settings); err != nil {
				st.Phase = wazuhv1.OpenSearchResourcePhaseFailed
				st.Message = err.Error()
				anyFailed = true
				allReady = false
				if firstErr == nil {
					firstErr = err
				}
				r.recordEvent(index, corev1.EventTypeWarning, "CreateFailed",
					fmt.Sprintf("Failed to create index on %s/%s: %v", ref.Namespace, ref.Name, err))
				newStatuses = append(newStatuses, st)
				continue
			}
			r.recordEvent(index, corev1.EventTypeNormal, "Created",
				fmt.Sprintf("Index created on %s/%s", ref.Namespace, ref.Name))
			log.Info("Created OpenSearch index", "name", indexName, "cluster", ref.Name, "clusterNamespace", ref.Namespace)
		} else if len(dynamicSettings) > 0 {
			if err := osClient.UpdateIndexSettings(ctx, indexName, dynamicSettings); err != nil {
				st.Phase = wazuhv1.OpenSearchResourcePhaseFailed
				st.Message = err.Error()
				anyFailed = true
				allReady = false
				if firstErr == nil {
					firstErr = err
				}
				r.recordEvent(index, corev1.EventTypeWarning, "UpdateFailed",
					fmt.Sprintf("Failed to update index settings on %s/%s: %v", ref.Namespace, ref.Name, err))
				newStatuses = append(newStatuses, st)
				continue
			}
			r.recordEvent(index, corev1.EventTypeNormal, "Updated",
				fmt.Sprintf("Index settings updated on %s/%s", ref.Namespace, ref.Name))
		}
		wasClusterReady := st.Phase == wazuhv1.OpenSearchResourcePhaseReady
		st.Phase = wazuhv1.OpenSearchResourcePhaseReady
		st.Message = ""
		st.LastAppliedHash = specHash
		if !wasClusterReady {
			now := metav1.Now()
			st.LastSyncTime = &now
		}
		newStatuses = append(newStatuses, st)
	}
	index.Status.ClusterStatuses = newStatuses

	if specHash != "" && index.Status.LastAppliedHash != "" && index.Status.LastAppliedHash != specHash {
		index.Status.DriftDetected = true
		now := metav1.Now()
		index.Status.LastDriftTime = &now
		metrics.RecordDriftDetection("OpenSearchIndex", index.Namespace)
		log.Info("Drift detected on OpenSearchIndex", "name", index.Name)
	} else {
		index.Status.DriftDetected = false
	}
	if specHash != "" {
		index.Status.LastAppliedHash = specHash
	}

	wasReady := index.Status.Phase == wazuhv1.OpenSearchResourcePhaseReady &&
		index.Status.ObservedGeneration == index.Generation
	var phase wazuhv1.OpenSearchResourcePhase
	var msg string
	switch {
	case anyFailed:
		phase = wazuhv1.OpenSearchResourcePhaseFailed
		msg = "One or more target clusters failed to sync"
	case anyPending:
		phase = wazuhv1.OpenSearchResourcePhasePending
		msg = "Waiting on one or more target clusters"
	case allReady:
		phase = wazuhv1.OpenSearchResourcePhaseReady
		msg = "Index reconciled on all target clusters"
	default:
		phase = wazuhv1.OpenSearchResourcePhasePending
	}
	if err := r.updateStatus(ctx, index, phase, msg, phase == wazuhv1.OpenSearchResourcePhaseReady && !wasReady); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	if firstErr != nil {
		return firstErr
	}
	log.Info("Index reconciliation completed", "name", index.Name)
	return nil
}

// recordEvent emits an event if the recorder is available
func (r *IndexReconciler) recordEvent(index *wazuhv1.OpenSearchIndex, eventType, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(index, eventType, reason, message)
	}
}

// buildIndexSettings builds index settings from spec
func (r *IndexReconciler) buildIndexSettings(index *wazuhv1.OpenSearchIndex) map[string]any {
	settings := make(map[string]any)
	indexSettings := make(map[string]any)

	if index.Spec.Settings != nil {
		if index.Spec.Settings.NumberOfShards != nil {
			indexSettings["number_of_shards"] = *index.Spec.Settings.NumberOfShards
		}
		if index.Spec.Settings.NumberOfReplicas != nil {
			indexSettings["number_of_replicas"] = *index.Spec.Settings.NumberOfReplicas
		}
	}

	if len(indexSettings) > 0 {
		settings["settings"] = map[string]any{
			"index": indexSettings,
		}
	}

	return settings
}

// buildDynamicSettings builds only the dynamic settings that can be updated on an existing index
func (r *IndexReconciler) buildDynamicSettings(index *wazuhv1.OpenSearchIndex) map[string]any {
	indexSettings := make(map[string]any)

	if index.Spec.Settings != nil && index.Spec.Settings.NumberOfReplicas != nil {
		indexSettings["number_of_replicas"] = *index.Spec.Settings.NumberOfReplicas
	}

	if len(indexSettings) == 0 {
		return nil
	}

	return map[string]any{
		"index": indexSettings,
	}
}

// getOpenSearchClient (legacy) returns a client for the first cluster ref.
func (r *IndexReconciler) getOpenSearchClient(ctx context.Context, index *wazuhv1.OpenSearchIndex) (*adapters.OpenSearchHTTPAdapter, error) {
	if len(index.Spec.ClusterRefs) == 0 {
		return nil, fmt.Errorf("no cluster references configured")
	}
	return r.getOpenSearchClientForRef(ctx, index.Spec.ClusterRefs[0])
}

// getOpenSearchClientForRef builds an HTTP adapter for the given cluster ref.
func (r *IndexReconciler) getOpenSearchClientForRef(ctx context.Context, ref wazuhv1.WazuhClusterRef) (*adapters.OpenSearchHTTPAdapter, error) {
	if r.ClientFactory == nil {
		return nil, fmt.Errorf("client factory not configured")
	}
	baseURL, username, password, caCert, err := r.ClientFactory.GetConnectionInfoForRef(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection info: %w", err)
	}
	return adapters.NewOpenSearchHTTPAdapter(adapters.OpenSearchConfig{
		BaseURL:  baseURL,
		Username: username,
		Password: password,
		CACert:   caCert,
		Insecure: false,
	})
}

// updateStatus updates the index status with retry on conflict
func (r *IndexReconciler) updateStatus(ctx context.Context, index *wazuhv1.OpenSearchIndex, phase wazuhv1.OpenSearchResourcePhase, message string, updateTimestamp ...bool) error {
	shouldUpdateTS := len(updateTimestamp) == 0 || updateTimestamp[0]

	if index.Status.Phase == phase && index.Status.Message == message &&
		index.Status.ObservedGeneration == index.Generation && !shouldUpdateTS {
		return nil
	}

	index.Status.Phase = phase
	index.Status.Message = message
	index.Status.ObservedGeneration = index.Generation
	if shouldUpdateTS {
		now := metav1.Now()
		index.Status.LastSyncTime = &now
	}

	metrics.SetResourceSyncStatus("OpenSearchIndex", index.Namespace, index.Name, phase == wazuhv1.OpenSearchResourcePhaseReady)

	desiredStatus := index.Status
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchIndex{}
		if err := r.Get(ctx, types.NamespacedName{Name: index.Name, Namespace: index.Namespace}, latest); err != nil {
			return err
		}
		latest.Status = desiredStatus
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		index.Status = latest.Status
		return nil
	})
}

// handleDeletion handles index cleanup on deletion
func (r *IndexReconciler) handleDeletion(ctx context.Context, index *wazuhv1.OpenSearchIndex) error {
	log := logf.FromContext(ctx)

	if err := r.Delete(ctx, index); err != nil {
		log.Error(err, "Failed to delete index from OpenSearch, proceeding with finalizer removal")
	}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchIndex{}
		if err := r.Get(ctx, types.NamespacedName{Name: index.Name, Namespace: index.Namespace}, latest); err != nil {
			return err
		}
		controllerutil.RemoveFinalizer(latest, constants.IndexFinalizer)
		return r.Client.Update(ctx, latest)
	})
}

// Delete handles cleanup when an index is deleted (across every target cluster).
func (r *IndexReconciler) Delete(ctx context.Context, index *wazuhv1.OpenSearchIndex) error {
	log := logf.FromContext(ctx)
	indexName := index.Name
	for _, ref := range index.Spec.ClusterRefs {
		osClient, err := r.getOpenSearchClientForRef(ctx, ref)
		if err != nil {
			r.recordEvent(index, corev1.EventTypeWarning, "DeleteFailed",
				fmt.Sprintf("Failed to connect to %s/%s for deletion: %v", ref.Namespace, ref.Name, err))
			continue
		}
		if err := osClient.DeleteIndex(ctx, indexName); err != nil {
			r.recordEvent(index, corev1.EventTypeWarning, "DeleteFailed",
				fmt.Sprintf("Failed to delete index from %s/%s: %v", ref.Namespace, ref.Name, err))
			continue
		}
		log.Info("Deleted OpenSearch index on cluster",
			"name", indexName, "cluster", ref.Name, "clusterNamespace", ref.Namespace)
	}
	r.recordEvent(index, corev1.EventTypeNormal, "Deleted", "Index deletion processed on all target clusters")
	return nil
}
