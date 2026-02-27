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
	retry "k8s.io/client-go/util/retry"
	"k8s.io/client-go/tools/record"
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

	// Get OpenSearch client
	osClient, err := r.getOpenSearchClient(ctx, index)
	if err != nil {
		r.recordEvent(index, corev1.EventTypeWarning, "ConnectionError", fmt.Sprintf("Failed to connect to OpenSearch: %v", err))
		return fmt.Errorf("failed to get OpenSearch client: %w", err)
	}

	// Use the resource name as the index name
	indexName := index.Name

	// Check if index exists
	exists, err := osClient.IndexExists(ctx, indexName)
	if err != nil {
		r.recordEvent(index, corev1.EventTypeWarning, "CheckFailed", fmt.Sprintf("Failed to check if index exists: %v", err))
		return fmt.Errorf("failed to check if index exists: %w", err)
	}

	if !exists {
		// Create the index
		settings := r.buildIndexSettings(index)
		if err := osClient.CreateIndex(ctx, indexName, settings); err != nil {
			r.recordEvent(index, corev1.EventTypeWarning, "CreateFailed", fmt.Sprintf("Failed to create index: %v", err))
			return fmt.Errorf("failed to create index: %w", err)
		}
		r.recordEvent(index, corev1.EventTypeNormal, "Created", "Index successfully created in OpenSearch")
		log.Info("Created OpenSearch index", "name", indexName)
	} else {
		// Update dynamic settings (number_of_replicas)
		dynamicSettings := r.buildDynamicSettings(index)
		if len(dynamicSettings) > 0 {
			if err := osClient.UpdateIndexSettings(ctx, indexName, dynamicSettings); err != nil {
				r.recordEvent(index, corev1.EventTypeWarning, "UpdateFailed", fmt.Sprintf("Failed to update index settings: %v", err))
				return fmt.Errorf("failed to update index settings: %w", err)
			}
			r.recordEvent(index, corev1.EventTypeNormal, "Updated", "Index settings updated in OpenSearch")
			log.Info("Updated OpenSearch index settings", "name", indexName)
		}
	}

	// Compute spec hash for drift detection
	specHash, hashErr := patch.ComputeSpecHash(index.Spec)
	if hashErr == nil && index.Status.LastAppliedHash != "" && index.Status.LastAppliedHash != specHash {
		index.Status.DriftDetected = true
		now := metav1.Now()
		index.Status.LastDriftTime = &now
		metrics.RecordDriftDetection("OpenSearchIndex", index.Namespace)
		log.Info("Drift detected on OpenSearchIndex", "name", index.Name)
	} else {
		index.Status.DriftDetected = false
	}
	if hashErr == nil {
		index.Status.LastAppliedHash = specHash
	}

	// Update status
	if err := r.updateStatus(ctx, index, wazuhv1.OpenSearchResourcePhaseReady, "Index reconciled successfully"); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
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

// getOpenSearchClient gets an OpenSearch HTTP adapter using dynamic client resolution
func (r *IndexReconciler) getOpenSearchClient(ctx context.Context, index *wazuhv1.OpenSearchIndex) (*adapters.OpenSearchHTTPAdapter, error) {
	if r.ClientFactory == nil {
		return nil, fmt.Errorf("client factory not configured")
	}

	baseURL, username, password, caCert, err := r.ClientFactory.GetConnectionInfo(ctx, index.Spec.ClusterRef, index.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection info: %w", err)
	}

	config := adapters.OpenSearchConfig{
		BaseURL:  baseURL,
		Username: username,
		Password: password,
		CACert:   caCert,
		Insecure: false,
	}

	return adapters.NewOpenSearchHTTPAdapter(config)
}

// updateStatus updates the index status with retry on conflict
func (r *IndexReconciler) updateStatus(ctx context.Context, index *wazuhv1.OpenSearchIndex, phase wazuhv1.OpenSearchResourcePhase, message string) error {
	index.Status.Phase = phase
	index.Status.Message = message
	now := metav1.Now()
	index.Status.LastSyncTime = &now

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

	controllerutil.RemoveFinalizer(index, constants.IndexFinalizer)
	return r.Update(ctx, index)
}

// Delete handles cleanup when an index is deleted
func (r *IndexReconciler) Delete(ctx context.Context, index *wazuhv1.OpenSearchIndex) error {
	log := logf.FromContext(ctx)

	osClient, err := r.getOpenSearchClient(ctx, index)
	if err != nil {
		r.recordEvent(index, corev1.EventTypeWarning, "DeleteFailed", fmt.Sprintf("Failed to connect to OpenSearch for deletion: %v", err))
		return fmt.Errorf("failed to get OpenSearch client: %w", err)
	}

	indexName := index.Name
	if err := osClient.DeleteIndex(ctx, indexName); err != nil {
		r.recordEvent(index, corev1.EventTypeWarning, "DeleteFailed", fmt.Sprintf("Failed to delete index from OpenSearch: %v", err))
		return fmt.Errorf("failed to delete index: %w", err)
	}

	r.recordEvent(index, corev1.EventTypeNormal, "Deleted", "Index deleted from OpenSearch")
	log.Info("Deleted OpenSearch index", "name", indexName)
	return nil
}
