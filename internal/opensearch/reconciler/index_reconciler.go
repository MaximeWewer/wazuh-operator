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

package reconciler

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
)

// IndexReconciler handles reconciliation of OpenSearch indices
type IndexReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	OpenSearchAddr string
	OpenSearchUser string
	OpenSearchPass string
}

// NewIndexReconciler creates a new IndexReconciler
func NewIndexReconciler(c client.Client, scheme *runtime.Scheme) *IndexReconciler {
	return &IndexReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// Reconcile reconciles an OpenSearch index
func (r *IndexReconciler) Reconcile(ctx context.Context, index *wazuhv1alpha1.OpenSearchIndex) error {
	log := logf.FromContext(ctx)

	// Get OpenSearch client
	osClient, err := r.getOpenSearchClient(ctx, index.Namespace)
	if err != nil {
		return fmt.Errorf("failed to get OpenSearch client: %w", err)
	}

	// Use the resource name as the index name
	indexName := index.Name

	// Check if index exists
	exists, err := osClient.IndexExists(ctx, indexName)
	if err != nil {
		return fmt.Errorf("failed to check if index exists: %w", err)
	}

	if !exists {
		// Create the index
		settings := r.buildIndexSettings(index)
		if err := osClient.CreateIndex(ctx, indexName, settings); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
		log.Info("Created OpenSearch index", "name", indexName)
	}

	// Update status
	if err := r.updateStatus(ctx, index, "Ready", "Index reconciled successfully"); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	log.Info("Index reconciliation completed", "name", index.Name)
	return nil
}

// buildIndexSettings builds index settings from spec
func (r *IndexReconciler) buildIndexSettings(index *wazuhv1alpha1.OpenSearchIndex) map[string]interface{} {
	settings := make(map[string]interface{})
	indexSettings := make(map[string]interface{})

	if index.Spec.Settings != nil {
		if index.Spec.Settings.NumberOfShards != nil {
			indexSettings["number_of_shards"] = *index.Spec.Settings.NumberOfShards
		}
		if index.Spec.Settings.NumberOfReplicas != nil {
			indexSettings["number_of_replicas"] = *index.Spec.Settings.NumberOfReplicas
		}
	}

	if len(indexSettings) > 0 {
		settings["settings"] = map[string]interface{}{
			"index": indexSettings,
		}
	}

	return settings
}

// getOpenSearchClient gets an OpenSearch HTTP adapter
func (r *IndexReconciler) getOpenSearchClient(ctx context.Context, namespace string) (*adapters.OpenSearchHTTPAdapter, error) {
	// In a real implementation, this would read credentials from secrets
	config := adapters.OpenSearchConfig{
		BaseURL:  r.OpenSearchAddr,
		Username: r.OpenSearchUser,
		Password: r.OpenSearchPass,
		Insecure: true,
	}

	return adapters.NewOpenSearchHTTPAdapter(config)
}

// updateStatus updates the index status
func (r *IndexReconciler) updateStatus(ctx context.Context, index *wazuhv1alpha1.OpenSearchIndex, phase, message string) error {
	index.Status.Phase = phase
	index.Status.Message = message
	now := metav1.Now()
	index.Status.LastSyncTime = &now

	return r.Status().Update(ctx, index)
}

// Delete handles cleanup when an index is deleted
func (r *IndexReconciler) Delete(ctx context.Context, index *wazuhv1alpha1.OpenSearchIndex) error {
	log := logf.FromContext(ctx)

	osClient, err := r.getOpenSearchClient(ctx, index.Namespace)
	if err != nil {
		return fmt.Errorf("failed to get OpenSearch client: %w", err)
	}

	indexName := index.Name
	if err := osClient.DeleteIndex(ctx, indexName); err != nil {
		return fmt.Errorf("failed to delete index: %w", err)
	}

	log.Info("Deleted OpenSearch index", "name", indexName)
	return nil
}
