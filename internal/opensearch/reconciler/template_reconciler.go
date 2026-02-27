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
	"encoding/json"
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
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/security"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/patch"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// TemplateReconciler handles reconciliation of OpenSearch index templates
type TemplateReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	ClientFactory *security.OpenSearchClientFactory
}

// NewTemplateReconciler creates a new TemplateReconciler
func NewTemplateReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *TemplateReconciler {
	return &TemplateReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: recorder,
	}
}

// WithClientFactory sets the OpenSearch client factory
func (r *TemplateReconciler) WithClientFactory(factory *security.OpenSearchClientFactory) *TemplateReconciler {
	r.ClientFactory = factory
	return r
}

// Reconcile reconciles an OpenSearch index template
func (r *TemplateReconciler) Reconcile(ctx context.Context, template *wazuhv1.OpenSearchIndexTemplate) (reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "TemplateReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", template.Name),
			attribute.String("resource.namespace", template.Namespace),
		))
	defer span.End()
	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	log := logf.FromContext(ctx)

	// Handle finalizer
	if !controllerutil.ContainsFinalizer(template, constants.IndexTemplateFinalizer) {
		controllerutil.AddFinalizer(template, constants.IndexTemplateFinalizer)
		if err := r.Update(ctx, template); err != nil {
			return fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	// Check if being deleted
	if !template.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, template)
	}

	if r.ClientFactory == nil {
		return r.updateStatus(ctx, template, wazuhv1.OpenSearchResourcePhasePending, "Waiting for OpenSearch client factory")
	}

	apiClient, err := r.ClientFactory.GetClientForRef(ctx, template.Spec.ClusterRef, template.Namespace)
	if err != nil {
		r.recordEvent(template, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Failed to get OpenSearch client: %v", err))
		return fmt.Errorf("failed to get OpenSearch client: %w", err)
	}

	// Create Templates API client
	templatesAPI := api.NewTemplatesAPI(apiClient)

	// Check if template exists
	exists, err := templatesAPI.IndexTemplateExists(ctx, template.Name)
	if err != nil {
		if updateErr := r.updateStatus(ctx, template, wazuhv1.OpenSearchResourcePhaseFailed, fmt.Sprintf("Failed to check template existence: %v", err)); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		r.recordEvent(template, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Failed to check index template existence: %v", err))
		return fmt.Errorf("failed to check template existence: %w", err)
	}

	// Build index template from spec
	indexTemplate := r.buildIndexTemplate(template)

	// Create or update index template (PUT is idempotent in OpenSearch)
	if exists {
		log.Info("Updating index template", "name", template.Name)
	} else {
		log.Info("Creating index template", "name", template.Name)
	}
	if err := templatesAPI.CreateIndexTemplate(ctx, template.Name, indexTemplate); err != nil {
		action := "create"
		if exists {
			action = "update"
		}
		if updateErr := r.updateStatus(ctx, template, wazuhv1.OpenSearchResourcePhaseFailed, fmt.Sprintf("Failed to %s template: %v", action, err)); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		r.recordEvent(template, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Failed to %s index template: %v", action, err))
		return fmt.Errorf("failed to %s index template: %w", action, err)
	}

	// Compute spec hash for drift detection
	specHash, hashErr := patch.ComputeSpecHash(template.Spec)
	if hashErr == nil && template.Status.LastAppliedHash != "" && template.Status.LastAppliedHash != specHash {
		template.Status.DriftDetected = true
		now := metav1.Now()
		template.Status.LastDriftTime = &now
		metrics.RecordDriftDetection("OpenSearchIndexTemplate", template.Namespace)
		log.Info("Drift detected on OpenSearchIndexTemplate", "name", template.Name)
	} else {
		template.Status.DriftDetected = false
	}
	if hashErr == nil {
		template.Status.LastAppliedHash = specHash
	}

	wasReady := template.Status.Phase == wazuhv1.OpenSearchResourcePhaseReady &&
		template.Status.ObservedGeneration == template.Generation
	if err := r.updateStatus(ctx, template, wazuhv1.OpenSearchResourcePhaseReady, "Index template reconciled successfully", !wasReady); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}
	if !wasReady {
		r.recordEvent(template, corev1.EventTypeNormal, "Synced", "Index template reconciled successfully")
	}

	log.Info("Index template reconciliation completed", "name", template.Name)
	return nil
}

// recordEvent emits an event if the recorder is available
func (r *TemplateReconciler) recordEvent(template *wazuhv1.OpenSearchIndexTemplate, eventType, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(template, eventType, reason, message)
	}
}

// buildIndexTemplate converts the CRD spec to an index template
func (r *TemplateReconciler) buildIndexTemplate(template *wazuhv1.OpenSearchIndexTemplate) api.IndexTemplate {
	indexTemplate := api.IndexTemplate{
		IndexPatterns: template.Spec.IndexPatterns,
		Priority:      int(template.Spec.Priority),
		ComposedOf:    template.Spec.ComposedOf,
	}

	if template.Spec.Template != nil {
		indexTemplate.Template = &api.TemplateSpec{}

		// Convert RawExtension to map[string]any and normalize camelCase keys
		if template.Spec.Template.Settings != nil && template.Spec.Template.Settings.Raw != nil {
			var settings map[string]any
			if err := json.Unmarshal(template.Spec.Template.Settings.Raw, &settings); err == nil {
				indexTemplate.Template.Settings = api.NormalizeIndexSettings(settings)
			}
		}

		if template.Spec.Template.Mappings != nil && template.Spec.Template.Mappings.Raw != nil {
			var mappings map[string]any
			if err := json.Unmarshal(template.Spec.Template.Mappings.Raw, &mappings); err == nil {
				indexTemplate.Template.Mappings = mappings
			}
		}

		// Convert aliases
		if template.Spec.Template.Aliases != nil {
			indexTemplate.Template.Aliases = make(map[string]api.AliasSpec)
			for name, alias := range template.Spec.Template.Aliases {
				aliasSpec := api.AliasSpec{
					IndexRouting:  alias.IndexRouting,
					SearchRouting: alias.SearchRouting,
					IsWriteIndex:  alias.IsWriteIndex,
				}
				if alias.Filter != nil && alias.Filter.Raw != nil {
					var filter map[string]any
					if err := json.Unmarshal(alias.Filter.Raw, &filter); err == nil {
						aliasSpec.Filter = filter
					}
				}
				indexTemplate.Template.Aliases[name] = aliasSpec
			}
		}
	}

	return indexTemplate
}

// updateStatus updates the template status with retry on conflict
func (r *TemplateReconciler) updateStatus(ctx context.Context, template *wazuhv1.OpenSearchIndexTemplate, phase wazuhv1.OpenSearchResourcePhase, message string, updateTimestamp ...bool) error {
	shouldUpdateTS := len(updateTimestamp) == 0 || updateTimestamp[0]

	if template.Status.Phase == phase && template.Status.Message == message &&
		template.Status.ObservedGeneration == template.Generation && !shouldUpdateTS {
		return nil
	}

	template.Status.Phase = phase
	template.Status.Message = message
	template.Status.ObservedGeneration = template.Generation
	if shouldUpdateTS {
		now := metav1.Now()
		template.Status.LastSyncTime = &now
	}

	metrics.SetResourceSyncStatus("OpenSearchIndexTemplate", template.Namespace, template.Name, phase == wazuhv1.OpenSearchResourcePhaseReady)

	desiredStatus := template.Status
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchIndexTemplate{}
		if err := r.Get(ctx, types.NamespacedName{Name: template.Name, Namespace: template.Namespace}, latest); err != nil {
			return err
		}
		latest.Status = desiredStatus
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		template.Status = latest.Status
		return nil
	})
}

// handleDeletion handles index template cleanup on deletion
func (r *TemplateReconciler) handleDeletion(ctx context.Context, template *wazuhv1.OpenSearchIndexTemplate) error {
	log := logf.FromContext(ctx)

	if err := r.Delete(ctx, template); err != nil {
		log.Error(err, "Failed to delete index template from OpenSearch, proceeding with finalizer removal")
	}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchIndexTemplate{}
		if err := r.Get(ctx, types.NamespacedName{Name: template.Name, Namespace: template.Namespace}, latest); err != nil {
			return err
		}
		controllerutil.RemoveFinalizer(latest, constants.IndexTemplateFinalizer)
		return r.Client.Update(ctx, latest)
	})
}

// Delete handles cleanup when a template is deleted
func (r *TemplateReconciler) Delete(ctx context.Context, template *wazuhv1.OpenSearchIndexTemplate) error {
	log := logf.FromContext(ctx)

	if r.ClientFactory == nil {
		log.Info("Skipping index template deletion - no client factory available")
		return nil
	}

	apiClient, err := r.ClientFactory.GetClientForRef(ctx, template.Spec.ClusterRef, template.Namespace)
	if err != nil {
		log.Info("Skipping index template deletion - failed to get OpenSearch client", "error", err)
		return nil
	}

	templatesAPI := api.NewTemplatesAPI(apiClient)
	if err := templatesAPI.DeleteIndexTemplate(ctx, template.Name); err != nil {
		r.recordEvent(template, corev1.EventTypeWarning, "DeleteFailed", fmt.Sprintf("Failed to delete index template: %v", err))
		return fmt.Errorf("failed to delete index template: %w", err)
	}

	r.recordEvent(template, corev1.EventTypeNormal, "Deleted", "Index template deleted from OpenSearch")
	log.Info("Deleted OpenSearch index template", "name", template.Name)
	return nil
}
