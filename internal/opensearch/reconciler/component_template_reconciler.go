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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/security"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// ComponentTemplateReconciler handles reconciliation of OpenSearch component templates
type ComponentTemplateReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	ClientFactory *security.OpenSearchClientFactory
}

// NewComponentTemplateReconciler creates a new ComponentTemplateReconciler
func NewComponentTemplateReconciler(c client.Client, scheme *runtime.Scheme) *ComponentTemplateReconciler {
	return &ComponentTemplateReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// WithClientFactory sets the OpenSearch client factory
func (r *ComponentTemplateReconciler) WithClientFactory(factory *security.OpenSearchClientFactory) *ComponentTemplateReconciler {
	r.ClientFactory = factory
	return r
}

// Reconcile reconciles an OpenSearch component template
func (r *ComponentTemplateReconciler) Reconcile(ctx context.Context, template *wazuhv1.OpenSearchComponentTemplate) error {
	log := logf.FromContext(ctx)

	// Handle finalizer
	if !controllerutil.ContainsFinalizer(template, constants.ComponentTemplateFinalizer) {
		controllerutil.AddFinalizer(template, constants.ComponentTemplateFinalizer)
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
		return fmt.Errorf("failed to get OpenSearch client: %w", err)
	}

	// Create Templates API client
	templatesAPI := api.NewTemplatesAPI(apiClient)

	// Check if component template exists
	exists, err := templatesAPI.ComponentTemplateExists(ctx, template.Name)
	if err != nil {
		if updateErr := r.updateStatus(ctx, template, wazuhv1.OpenSearchResourcePhaseFailed, fmt.Sprintf("Failed to check template existence: %v", err)); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		return fmt.Errorf("failed to check component template existence: %w", err)
	}

	// Build component template from spec
	componentTemplate := r.buildComponentTemplate(template)

	// Create or update component template (PUT is idempotent in OpenSearch)
	if exists {
		log.Info("Updating component template", "name", template.Name)
	} else {
		log.Info("Creating component template", "name", template.Name)
	}
	if err := templatesAPI.CreateComponentTemplate(ctx, template.Name, componentTemplate); err != nil {
		action := "create"
		if exists {
			action = "update"
		}
		if updateErr := r.updateStatus(ctx, template, wazuhv1.OpenSearchResourcePhaseFailed, fmt.Sprintf("Failed to %s template: %v", action, err)); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		return fmt.Errorf("failed to %s component template: %w", action, err)
	}

	// Update status
	if err := r.updateStatus(ctx, template, wazuhv1.OpenSearchResourcePhaseReady, "Component template reconciled successfully"); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	log.Info("Component template reconciliation completed", "name", template.Name)
	return nil
}

// buildComponentTemplate converts the CRD spec to a component template
func (r *ComponentTemplateReconciler) buildComponentTemplate(template *wazuhv1.OpenSearchComponentTemplate) api.ComponentTemplate {
	componentTemplate := api.ComponentTemplate{}

	// Convert RawExtension fields to map[string]any
	componentTemplate.Template = &api.ComponentTemplateSpec{}

	if template.Spec.Template.Settings != nil && template.Spec.Template.Settings.Raw != nil {
		componentTemplate.Template.SettingsRaw = template.Spec.Template.Settings.Raw
	}

	if template.Spec.Template.Mappings != nil && template.Spec.Template.Mappings.Raw != nil {
		componentTemplate.Template.MappingsRaw = template.Spec.Template.Mappings.Raw
	}

	return componentTemplate
}

// updateStatus updates the template status
func (r *ComponentTemplateReconciler) updateStatus(ctx context.Context, template *wazuhv1.OpenSearchComponentTemplate, phase wazuhv1.OpenSearchResourcePhase, message string) error {
	template.Status.Phase = phase
	template.Status.Message = message
	now := metav1.Now()
	template.Status.LastSyncTime = &now

	return r.Status().Update(ctx, template)
}

// handleDeletion handles component template cleanup on deletion
func (r *ComponentTemplateReconciler) handleDeletion(ctx context.Context, template *wazuhv1.OpenSearchComponentTemplate) error {
	log := logf.FromContext(ctx)

	if err := r.Delete(ctx, template); err != nil {
		log.Error(err, "Failed to delete component template from OpenSearch, proceeding with finalizer removal")
	}

	controllerutil.RemoveFinalizer(template, constants.ComponentTemplateFinalizer)
	return r.Update(ctx, template)
}

// Delete handles cleanup when a component template is deleted
func (r *ComponentTemplateReconciler) Delete(ctx context.Context, template *wazuhv1.OpenSearchComponentTemplate) error {
	log := logf.FromContext(ctx)

	if r.ClientFactory == nil {
		log.Info("Skipping component template deletion - no client factory available")
		return nil
	}

	apiClient, err := r.ClientFactory.GetClientForRef(ctx, template.Spec.ClusterRef, template.Namespace)
	if err != nil {
		log.Info("Skipping component template deletion - failed to get OpenSearch client", "error", err)
		return nil
	}

	templatesAPI := api.NewTemplatesAPI(apiClient)
	if err := templatesAPI.DeleteComponentTemplate(ctx, template.Name); err != nil {
		return fmt.Errorf("failed to delete component template: %w", err)
	}

	log.Info("Deleted OpenSearch component template", "name", template.Name)
	return nil
}
