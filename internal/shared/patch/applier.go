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

package patch

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// Applier applies resource updates to the cluster
type Applier struct {
	client client.Client
}

// NewApplier creates a new Applier
func NewApplier(c client.Client) *Applier {
	return &Applier{client: c}
}

// ApplyStatefulSet creates or updates a StatefulSet based on the change result
// If immutable fields have changed, it will delete and recreate the StatefulSet
func (a *Applier) ApplyStatefulSet(ctx context.Context, desired *appsv1.StatefulSet, result *ChangeResult, specHash string) error {
	logger := log.FromContext(ctx).WithValues(
		"statefulset", desired.Name,
		"namespace", desired.Namespace,
	)

	if result.NeedsCreate {
		logger.Info("Creating StatefulSet", "reason", result.Reason)
		// Set spec hash annotation before creation
		if specHash != "" {
			if desired.Annotations == nil {
				desired.Annotations = make(map[string]string)
			}
			desired.Annotations[constants.AnnotationSpecHash] = specHash
		}
		if err := a.client.Create(ctx, desired); err != nil {
			return NewUpdateFailedError("StatefulSet", desired.Name, err)
		}
		return nil
	}

	if !result.NeedsUpdate {
		logger.V(1).Info("No update needed for StatefulSet")
		return nil
	}

	// Get current resource to preserve ResourceVersion
	current := &appsv1.StatefulSet{}
	if err := a.client.Get(ctx, types.NamespacedName{
		Name:      desired.Name,
		Namespace: desired.Namespace,
	}, current); err != nil {
		return fmt.Errorf("failed to get current StatefulSet: %w", err)
	}

	// Check if recreation is needed due to immutable field changes
	needsRecreation, recreationReason := NeedsStatefulSetRecreation(current, desired)
	if needsRecreation {
		logger.Info("StatefulSet requires recreation due to immutable field change",
			"reason", recreationReason,
			"statefulset", desired.Name,
		)
		return a.RecreateStatefulSet(ctx, current, desired, specHash)
	}

	// Check truly immutable fields (selector, serviceName, volumeClaimTemplates)
	if err := CheckStatefulSetImmutableFields(current, desired); err != nil {
		return err
	}

	// Preserve ResourceVersion for update
	desired.ResourceVersion = current.ResourceVersion

	// Set spec hash annotation
	if specHash != "" {
		if desired.Annotations == nil {
			desired.Annotations = make(map[string]string)
		}
		desired.Annotations[constants.AnnotationSpecHash] = specHash
	}

	logger.Info("Updating StatefulSet",
		"reason", result.Reason,
		"message", result.Message,
		"changedFields", result.ChangedFields,
	)

	if err := a.client.Update(ctx, desired); err != nil {
		return NewUpdateFailedError("StatefulSet", desired.Name, err)
	}

	return nil
}

// RecreateStatefulSet deletes and recreates a StatefulSet
// This is used when immutable fields need to change (e.g., PodManagementPolicy, SecurityContext)
// The PVCs are preserved (orphaned) so data is not lost
func (a *Applier) RecreateStatefulSet(ctx context.Context, current, desired *appsv1.StatefulSet, specHash string) error {
	logger := log.FromContext(ctx).WithValues(
		"statefulset", desired.Name,
		"namespace", desired.Namespace,
	)

	// Delete the current StatefulSet with orphan policy to preserve pods temporarily
	// This allows the new StatefulSet to adopt the existing PVCs
	logger.Info("Deleting StatefulSet for recreation (preserving PVCs)")

	// Use default delete (cascade) - pods will be deleted but PVCs preserved
	if err := a.client.Delete(ctx, current); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete StatefulSet for recreation: %w", err)
	}

	// Set spec hash annotation before creation
	if specHash != "" {
		if desired.Annotations == nil {
			desired.Annotations = make(map[string]string)
		}
		desired.Annotations[constants.AnnotationSpecHash] = specHash
	}

	// Clear ResourceVersion for creation
	desired.ResourceVersion = ""

	logger.Info("Creating new StatefulSet after recreation")
	if err := a.client.Create(ctx, desired); err != nil {
		return NewUpdateFailedError("StatefulSet", desired.Name, err)
	}

	return nil
}

// ApplyDeployment creates or updates a Deployment based on the change result
func (a *Applier) ApplyDeployment(ctx context.Context, desired *appsv1.Deployment, result *ChangeResult, specHash string) error {
	logger := log.FromContext(ctx).WithValues(
		"deployment", desired.Name,
		"namespace", desired.Namespace,
	)

	if result.NeedsCreate {
		logger.Info("Creating Deployment", "reason", result.Reason)
		// Set spec hash annotation before creation
		if specHash != "" {
			if desired.Annotations == nil {
				desired.Annotations = make(map[string]string)
			}
			desired.Annotations[constants.AnnotationSpecHash] = specHash
		}
		if err := a.client.Create(ctx, desired); err != nil {
			return NewUpdateFailedError("Deployment", desired.Name, err)
		}
		return nil
	}

	if !result.NeedsUpdate {
		logger.V(1).Info("No update needed for Deployment")
		return nil
	}

	// Get current resource to preserve ResourceVersion
	current := &appsv1.Deployment{}
	if err := a.client.Get(ctx, types.NamespacedName{
		Name:      desired.Name,
		Namespace: desired.Namespace,
	}, current); err != nil {
		return fmt.Errorf("failed to get current Deployment: %w", err)
	}

	// Check immutable fields before applying
	if err := CheckDeploymentImmutableFields(current, desired); err != nil {
		return err
	}

	// Preserve ResourceVersion for update
	desired.ResourceVersion = current.ResourceVersion

	// Set spec hash annotation
	if specHash != "" {
		if desired.Annotations == nil {
			desired.Annotations = make(map[string]string)
		}
		desired.Annotations[constants.AnnotationSpecHash] = specHash
	}

	logger.Info("Updating Deployment",
		"reason", result.Reason,
		"message", result.Message,
	)

	if err := a.client.Update(ctx, desired); err != nil {
		return NewUpdateFailedError("Deployment", desired.Name, err)
	}

	return nil
}

// ApplyConfigMap creates or updates a ConfigMap
func (a *Applier) ApplyConfigMap(ctx context.Context, desired *corev1.ConfigMap) error {
	logger := log.FromContext(ctx).WithValues(
		"configmap", desired.Name,
		"namespace", desired.Namespace,
	)

	current := &corev1.ConfigMap{}
	err := a.client.Get(ctx, types.NamespacedName{
		Name:      desired.Name,
		Namespace: desired.Namespace,
	}, current)

	if errors.IsNotFound(err) {
		logger.Info("Creating ConfigMap")
		if err := a.client.Create(ctx, desired); err != nil {
			return NewUpdateFailedError("ConfigMap", desired.Name, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get current ConfigMap: %w", err)
	}

	// Preserve ResourceVersion for update
	desired.ResourceVersion = current.ResourceVersion

	logger.V(1).Info("Updating ConfigMap")
	if err := a.client.Update(ctx, desired); err != nil {
		return NewUpdateFailedError("ConfigMap", desired.Name, err)
	}

	return nil
}

// ApplyService creates or updates a Service
func (a *Applier) ApplyService(ctx context.Context, desired *corev1.Service) error {
	logger := log.FromContext(ctx).WithValues(
		"service", desired.Name,
		"namespace", desired.Namespace,
	)

	current := &corev1.Service{}
	err := a.client.Get(ctx, types.NamespacedName{
		Name:      desired.Name,
		Namespace: desired.Namespace,
	}, current)

	if errors.IsNotFound(err) {
		logger.Info("Creating Service")
		if err := a.client.Create(ctx, desired); err != nil {
			return NewUpdateFailedError("Service", desired.Name, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get current Service: %w", err)
	}

	// Preserve ResourceVersion and ClusterIP for update
	desired.ResourceVersion = current.ResourceVersion
	if desired.Spec.ClusterIP == "" {
		desired.Spec.ClusterIP = current.Spec.ClusterIP
	}

	logger.V(1).Info("Updating Service")
	if err := a.client.Update(ctx, desired); err != nil {
		return NewUpdateFailedError("Service", desired.Name, err)
	}

	return nil
}

// SetPodAnnotation sets an annotation on the pod template spec
func SetPodAnnotation(podSpec *corev1.PodTemplateSpec, key, value string) {
	if podSpec.Annotations == nil {
		podSpec.Annotations = make(map[string]string)
	}
	podSpec.Annotations[key] = value
}

// SetResourceAnnotation sets an annotation on a resource's metadata
func SetResourceAnnotation(annotations *map[string]string, key, value string) {
	if *annotations == nil {
		*annotations = make(map[string]string)
	}
	(*annotations)[key] = value
}
