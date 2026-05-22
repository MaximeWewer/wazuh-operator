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
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/security"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/patch"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// ComponentTemplateReconciler handles reconciliation of OpenSearch component templates
type ComponentTemplateReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	ClientFactory *security.OpenSearchClientFactory
}

// NewComponentTemplateReconciler creates a new ComponentTemplateReconciler
func NewComponentTemplateReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *ComponentTemplateReconciler {
	return &ComponentTemplateReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: recorder,
	}
}

// WithClientFactory sets the OpenSearch client factory
func (r *ComponentTemplateReconciler) WithClientFactory(factory *security.OpenSearchClientFactory) *ComponentTemplateReconciler {
	r.ClientFactory = factory
	return r
}

// Reconcile reconciles an OpenSearch component template
func (r *ComponentTemplateReconciler) Reconcile(ctx context.Context, template *wazuhv1.OpenSearchComponentTemplate) (reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "ComponentTemplateReconciler.Reconcile",
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

	componentTemplate := r.buildComponentTemplate(template)
	specHash, _ := patch.ComputeSpecHash(template.Spec)

	res := ReconcileMultiCluster(ctx, template.Spec.ClusterRefs, r.ClientFactory, template.Status.ClusterStatuses,
		func(ctx context.Context, apiClient *api.Client, ref wazuhv1.WazuhClusterRef) (string, error) {
			templatesAPI := api.NewTemplatesAPI(apiClient)
			exists, err := templatesAPI.ComponentTemplateExists(ctx, template.Name)
			if err != nil {
				return "", fmt.Errorf("failed to check component template existence: %w", err)
			}
			if exists {
				log.Info("Updating component template", "name", template.Name, "cluster", ref.Name, "clusterNamespace", ref.Namespace)
			} else {
				log.Info("Creating component template", "name", template.Name, "cluster", ref.Name, "clusterNamespace", ref.Namespace)
			}
			if err := templatesAPI.CreateComponentTemplate(ctx, template.Name, componentTemplate); err != nil {
				return "", fmt.Errorf("failed to apply component template: %w", err)
			}
			return specHash, nil
		})
	template.Status.ClusterStatuses = res.Statuses

	if specHash != "" && template.Status.LastAppliedHash != "" && template.Status.LastAppliedHash != specHash {
		template.Status.DriftDetected = true
		now := metav1.Now()
		template.Status.LastDriftTime = &now
		metrics.RecordDriftDetection("OpenSearchComponentTemplate", template.Namespace)
		log.Info("Drift detected on OpenSearchComponentTemplate", "name", template.Name)
	} else {
		template.Status.DriftDetected = false
	}
	if specHash != "" {
		template.Status.LastAppliedHash = specHash
	}

	wasReady := template.Status.Phase == wazuhv1.OpenSearchResourcePhaseReady &&
		template.Status.ObservedGeneration == template.Generation
	phase := res.AggregatePhase()
	msg := res.AggregateMessage()
	if res.AnyFailed {
		r.recordEvent(template, corev1.EventTypeWarning, "SyncFailed", res.FirstError.Error())
	}
	if err := r.updateStatus(ctx, template, phase, msg, phase == wazuhv1.OpenSearchResourcePhaseReady && !wasReady); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}
	if phase == wazuhv1.OpenSearchResourcePhaseReady && !wasReady {
		r.recordEvent(template, corev1.EventTypeNormal, "Synced", "Component template synced on all target clusters")
	}

	if res.FirstError != nil {
		return res.FirstError
	}
	log.Info("Component template reconciliation completed", "name", template.Name)
	return nil
}

// recordEvent emits an event if the recorder is available
func (r *ComponentTemplateReconciler) recordEvent(template *wazuhv1.OpenSearchComponentTemplate, eventType, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(template, eventType, reason, message)
	}
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

// updateStatus updates the template status with retry on conflict
func (r *ComponentTemplateReconciler) updateStatus(ctx context.Context, template *wazuhv1.OpenSearchComponentTemplate, phase wazuhv1.OpenSearchResourcePhase, message string, updateTimestamp ...bool) error {
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

	metrics.SetResourceSyncStatus("OpenSearchComponentTemplate", template.Namespace, template.Name, phase == wazuhv1.OpenSearchResourcePhaseReady)

	desiredStatus := template.Status
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchComponentTemplate{}
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

// handleDeletion handles component template cleanup on deletion
func (r *ComponentTemplateReconciler) handleDeletion(ctx context.Context, template *wazuhv1.OpenSearchComponentTemplate) error {
	log := logf.FromContext(ctx)

	if err := r.Delete(ctx, template); err != nil {
		log.Error(err, "Failed to delete component template from OpenSearch, proceeding with finalizer removal")
	}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchComponentTemplate{}
		if err := r.Get(ctx, types.NamespacedName{Name: template.Name, Namespace: template.Namespace}, latest); err != nil {
			return err
		}
		controllerutil.RemoveFinalizer(latest, constants.ComponentTemplateFinalizer)
		return r.Client.Update(ctx, latest)
	})
}

// Delete handles cleanup when a component template is deleted
func (r *ComponentTemplateReconciler) Delete(ctx context.Context, template *wazuhv1.OpenSearchComponentTemplate) error {
	log := logf.FromContext(ctx)

	if r.ClientFactory == nil {
		log.Info("Skipping component template deletion - no client factory available")
		return nil
	}

	for _, ref := range template.Spec.ClusterRefs {
		apiClient, err := r.ClientFactory.GetClientForClusterRef(ctx, ref)
		if err != nil {
			log.Info("Skipping component template deletion on cluster - failed to get client",
				"cluster", ref.Name, "clusterNamespace", ref.Namespace, "error", err)
			continue
		}
		templatesAPI := api.NewTemplatesAPI(apiClient)
		if err := templatesAPI.DeleteComponentTemplate(ctx, template.Name); err != nil {
			r.recordEvent(template, corev1.EventTypeWarning, "DeleteFailed",
				fmt.Sprintf("Failed to delete component template from %s/%s: %v", ref.Namespace, ref.Name, err))
			continue
		}
		log.Info("Deleted OpenSearch component template on cluster",
			"name", template.Name, "cluster", ref.Name, "clusterNamespace", ref.Namespace)
	}
	r.recordEvent(template, corev1.EventTypeNormal, "Deleted", "Component template deletion processed on all target clusters")
	return nil
}
