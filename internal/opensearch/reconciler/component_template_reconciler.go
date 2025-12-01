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
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
)

// ComponentTemplateReconciler handles reconciliation of OpenSearch component templates
type ComponentTemplateReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	APIClient *api.Client
}

// NewComponentTemplateReconciler creates a new ComponentTemplateReconciler
func NewComponentTemplateReconciler(c client.Client, scheme *runtime.Scheme) *ComponentTemplateReconciler {
	return &ComponentTemplateReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// WithAPIClient sets the OpenSearch API client
func (r *ComponentTemplateReconciler) WithAPIClient(apiClient *api.Client) *ComponentTemplateReconciler {
	r.APIClient = apiClient
	return r
}

// Reconcile reconciles an OpenSearch component template
func (r *ComponentTemplateReconciler) Reconcile(ctx context.Context, template *wazuhv1alpha1.OpenSearchComponentTemplate) error {
	log := logf.FromContext(ctx)

	if r.APIClient == nil {
		return r.updateStatus(ctx, template, "Pending", "Waiting for OpenSearch API client")
	}

	// Create Templates API client
	templatesAPI := api.NewTemplatesAPI(r.APIClient)

	// Check if component template exists
	exists, err := templatesAPI.ComponentTemplateExists(ctx, template.Name)
	if err != nil {
		if updateErr := r.updateStatus(ctx, template, "Error", fmt.Sprintf("Failed to check template existence: %v", err)); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		return fmt.Errorf("failed to check component template existence: %w", err)
	}

	// Build component template from spec
	componentTemplate := r.buildComponentTemplate(template)

	if !exists {
		// Create new component template
		log.Info("Creating component template", "name", template.Name)
		if err := templatesAPI.CreateComponentTemplate(ctx, template.Name, componentTemplate); err != nil {
			if updateErr := r.updateStatus(ctx, template, "Error", fmt.Sprintf("Failed to create template: %v", err)); updateErr != nil {
				log.Error(updateErr, "Failed to update status")
			}
			return fmt.Errorf("failed to create component template: %w", err)
		}
	}

	// Update status
	if err := r.updateStatus(ctx, template, "Ready", "Component template reconciled successfully"); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	log.Info("Component template reconciliation completed", "name", template.Name)
	return nil
}

// buildComponentTemplate converts the CRD spec to a component template
func (r *ComponentTemplateReconciler) buildComponentTemplate(template *wazuhv1alpha1.OpenSearchComponentTemplate) api.ComponentTemplate {
	componentTemplate := api.ComponentTemplate{}

	// Convert RawExtension fields to map[string]interface{}
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
func (r *ComponentTemplateReconciler) updateStatus(ctx context.Context, template *wazuhv1alpha1.OpenSearchComponentTemplate, phase, message string) error {
	template.Status.Phase = phase
	template.Status.Message = message
	now := metav1.Now()
	template.Status.LastSyncTime = &now

	return r.Status().Update(ctx, template)
}

// Delete handles cleanup when a component template is deleted
func (r *ComponentTemplateReconciler) Delete(ctx context.Context, template *wazuhv1alpha1.OpenSearchComponentTemplate) error {
	log := logf.FromContext(ctx)

	if r.APIClient == nil {
		log.Info("Skipping component template deletion - no API client available")
		return nil
	}

	templatesAPI := api.NewTemplatesAPI(r.APIClient)
	if err := templatesAPI.DeleteComponentTemplate(ctx, template.Name); err != nil {
		return fmt.Errorf("failed to delete component template: %w", err)
	}

	log.Info("Deleted OpenSearch component template", "name", template.Name)
	return nil
}
