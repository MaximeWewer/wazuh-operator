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
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
)

// TemplateReconciler handles reconciliation of OpenSearch index templates
type TemplateReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	APIClient *api.Client
}

// NewTemplateReconciler creates a new TemplateReconciler
func NewTemplateReconciler(c client.Client, scheme *runtime.Scheme) *TemplateReconciler {
	return &TemplateReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// WithAPIClient sets the OpenSearch API client
func (r *TemplateReconciler) WithAPIClient(apiClient *api.Client) *TemplateReconciler {
	r.APIClient = apiClient
	return r
}

// Reconcile reconciles an OpenSearch index template
func (r *TemplateReconciler) Reconcile(ctx context.Context, template *wazuhv1alpha1.OpenSearchIndexTemplate) error {
	log := logf.FromContext(ctx)

	if r.APIClient == nil {
		return r.updateStatus(ctx, template, "Pending", "Waiting for OpenSearch API client")
	}

	// Create Templates API client
	templatesAPI := api.NewTemplatesAPI(r.APIClient)

	// Check if template exists
	exists, err := templatesAPI.IndexTemplateExists(ctx, template.Name)
	if err != nil {
		if updateErr := r.updateStatus(ctx, template, "Error", fmt.Sprintf("Failed to check template existence: %v", err)); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		return fmt.Errorf("failed to check template existence: %w", err)
	}

	// Build index template from spec
	indexTemplate := r.buildIndexTemplate(template)

	if !exists {
		// Create new template
		log.Info("Creating index template", "name", template.Name)
		if err := templatesAPI.CreateIndexTemplate(ctx, template.Name, indexTemplate); err != nil {
			if updateErr := r.updateStatus(ctx, template, "Error", fmt.Sprintf("Failed to create template: %v", err)); updateErr != nil {
				log.Error(updateErr, "Failed to update status")
			}
			return fmt.Errorf("failed to create index template: %w", err)
		}
	}

	// Update status
	if err := r.updateStatus(ctx, template, "Ready", "Index template reconciled successfully"); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	log.Info("Index template reconciliation completed", "name", template.Name)
	return nil
}

// buildIndexTemplate converts the CRD spec to an index template
func (r *TemplateReconciler) buildIndexTemplate(template *wazuhv1alpha1.OpenSearchIndexTemplate) api.IndexTemplate {
	indexTemplate := api.IndexTemplate{
		IndexPatterns: template.Spec.IndexPatterns,
		Priority:      int(template.Spec.Priority),
		ComposedOf:    template.Spec.ComposedOf,
	}

	if template.Spec.Template != nil {
		indexTemplate.Template = &api.TemplateSpec{}

		// Convert RawExtension to map[string]interface{}
		if template.Spec.Template.Settings != nil && template.Spec.Template.Settings.Raw != nil {
			var settings map[string]interface{}
			if err := json.Unmarshal(template.Spec.Template.Settings.Raw, &settings); err == nil {
				indexTemplate.Template.Settings = settings
			}
		}

		if template.Spec.Template.Mappings != nil && template.Spec.Template.Mappings.Raw != nil {
			var mappings map[string]interface{}
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
					var filter map[string]interface{}
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

// updateStatus updates the template status
func (r *TemplateReconciler) updateStatus(ctx context.Context, template *wazuhv1alpha1.OpenSearchIndexTemplate, phase, message string) error {
	template.Status.Phase = phase
	template.Status.Message = message
	now := metav1.Now()
	template.Status.LastSyncTime = &now

	return r.Status().Update(ctx, template)
}

// Delete handles cleanup when a template is deleted
func (r *TemplateReconciler) Delete(ctx context.Context, template *wazuhv1alpha1.OpenSearchIndexTemplate) error {
	log := logf.FromContext(ctx)

	if r.APIClient == nil {
		log.Info("Skipping index template deletion - no API client available")
		return nil
	}

	templatesAPI := api.NewTemplatesAPI(r.APIClient)
	if err := templatesAPI.DeleteIndexTemplate(ctx, template.Name); err != nil {
		return fmt.Errorf("failed to delete index template: %w", err)
	}

	log.Info("Deleted OpenSearch index template", "name", template.Name)
	return nil
}
