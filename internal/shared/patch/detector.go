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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// Detector detects changes between desired and current resource states
type Detector struct {
	client client.Client
}

// NewDetector creates a new Detector
func NewDetector(c client.Client) *Detector {
	return &Detector{client: c}
}

// DetectStatefulSetChanges compares desired StatefulSet against current cluster state
func (d *Detector) DetectStatefulSetChanges(ctx context.Context, desired *appsv1.StatefulSet, specHash string) (*ChangeResult, error) {
	current := &appsv1.StatefulSet{}
	err := d.client.Get(ctx, types.NamespacedName{
		Name:      desired.Name,
		Namespace: desired.Namespace,
	}, current)

	if errors.IsNotFound(err) {
		return CreateResult(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get current StatefulSet: %w", err)
	}

	// Check for immutable field changes first
	if err := CheckStatefulSetImmutableFields(current, desired); err != nil {
		return nil, err
	}

	// Get current hashes from annotations
	currentSpecHash := getAnnotation(current.Annotations, constants.AnnotationSpecHash)
	currentConfigHash := getAnnotation(current.Spec.Template.Annotations, constants.AnnotationConfigHash)
	currentCertHash := getAnnotation(current.Spec.Template.Annotations, constants.AnnotationCertHash)

	// Get desired hashes from annotations
	desiredConfigHash := getAnnotation(desired.Spec.Template.Annotations, constants.AnnotationConfigHash)
	desiredCertHash := getAnnotation(desired.Spec.Template.Annotations, constants.AnnotationCertHash)

	// Check spec hash (version, resources, replicas, etc.)
	if specHash != "" && specHash != currentSpecHash {
		changedFields := detectChangedFields(current, desired)
		return UpdateResult(
			ReasonSpecChange,
			changedFields,
			currentSpecHash,
			specHash,
			fmt.Sprintf("Spec changed: %v", changedFields),
		), nil
	}

	// Check config hash (requires pod restart)
	if desiredConfigHash != "" && desiredConfigHash != currentConfigHash {
		return RestartResult(
			ReasonConfigChange,
			currentConfigHash,
			desiredConfigHash,
			"ConfigMap content changed, pod restart required",
		), nil
	}

	// Check cert hash (requires pod restart)
	if desiredCertHash != "" && desiredCertHash != currentCertHash {
		return RestartResult(
			ReasonCertChange,
			currentCertHash,
			desiredCertHash,
			"Certificate content changed, pod restart required",
		), nil
	}

	// Check replica count specifically (doesn't require pod restart)
	if current.Spec.Replicas != nil && desired.Spec.Replicas != nil {
		if *current.Spec.Replicas != *desired.Spec.Replicas {
			return UpdateResult(
				ReasonReplicaChange,
				[]string{"replicas"},
				fmt.Sprintf("%d", *current.Spec.Replicas),
				fmt.Sprintf("%d", *desired.Spec.Replicas),
				fmt.Sprintf("Replica count changed from %d to %d", *current.Spec.Replicas, *desired.Spec.Replicas),
			), nil
		}
	}

	return NoChangeResult(), nil
}

// DetectDeploymentChanges compares desired Deployment against current cluster state
func (d *Detector) DetectDeploymentChanges(ctx context.Context, desired *appsv1.Deployment, specHash string) (*ChangeResult, error) {
	current := &appsv1.Deployment{}
	err := d.client.Get(ctx, types.NamespacedName{
		Name:      desired.Name,
		Namespace: desired.Namespace,
	}, current)

	if errors.IsNotFound(err) {
		return CreateResult(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get current Deployment: %w", err)
	}

	// Check for immutable field changes first
	if err := CheckDeploymentImmutableFields(current, desired); err != nil {
		return nil, err
	}

	// Get current hashes from annotations
	currentSpecHash := getAnnotation(current.Annotations, constants.AnnotationSpecHash)
	currentConfigHash := getAnnotation(current.Spec.Template.Annotations, constants.AnnotationConfigHash)
	currentCertHash := getAnnotation(current.Spec.Template.Annotations, constants.AnnotationCertHash)

	// Get desired hashes from annotations
	desiredConfigHash := getAnnotation(desired.Spec.Template.Annotations, constants.AnnotationConfigHash)
	desiredCertHash := getAnnotation(desired.Spec.Template.Annotations, constants.AnnotationCertHash)

	// Check spec hash (version, resources, replicas, etc.)
	if specHash != "" && specHash != currentSpecHash {
		return UpdateResult(
			ReasonSpecChange,
			[]string{"spec"},
			currentSpecHash,
			specHash,
			"Deployment spec changed",
		), nil
	}

	// Check config hash (requires pod restart)
	if desiredConfigHash != "" && desiredConfigHash != currentConfigHash {
		return RestartResult(
			ReasonConfigChange,
			currentConfigHash,
			desiredConfigHash,
			"ConfigMap content changed, pod restart required",
		), nil
	}

	// Check cert hash (requires pod restart)
	if desiredCertHash != "" && desiredCertHash != currentCertHash {
		return RestartResult(
			ReasonCertChange,
			currentCertHash,
			desiredCertHash,
			"Certificate content changed, pod restart required",
		), nil
	}

	// Check replica count specifically (doesn't require pod restart)
	if current.Spec.Replicas != nil && desired.Spec.Replicas != nil {
		if *current.Spec.Replicas != *desired.Spec.Replicas {
			return UpdateResult(
				ReasonReplicaChange,
				[]string{"replicas"},
				fmt.Sprintf("%d", *current.Spec.Replicas),
				fmt.Sprintf("%d", *desired.Spec.Replicas),
				fmt.Sprintf("Replica count changed from %d to %d", *current.Spec.Replicas, *desired.Spec.Replicas),
			), nil
		}
	}

	return NoChangeResult(), nil
}

// CompareReplicas compares replica counts and returns a ChangeResult if different
func CompareReplicas(current, desired *int32) *ChangeResult {
	if current == nil || desired == nil {
		return NoChangeResult()
	}
	if *current != *desired {
		return UpdateResult(
			ReasonReplicaChange,
			[]string{"replicas"},
			fmt.Sprintf("%d", *current),
			fmt.Sprintf("%d", *desired),
			fmt.Sprintf("Replica count changed from %d to %d", *current, *desired),
		)
	}
	return NoChangeResult()
}

// CompareGeneration checks if CRD generation has changed
func CompareGeneration(current, desired int64) *ChangeResult {
	if current != desired {
		return UpdateResult(
			ReasonGenerationChange,
			[]string{"generation"},
			fmt.Sprintf("%d", current),
			fmt.Sprintf("%d", desired),
			fmt.Sprintf("CRD generation changed from %d to %d", current, desired),
		)
	}
	return NoChangeResult()
}

// detectChangedFields identifies which fields changed between current and desired StatefulSet
func detectChangedFields(current, desired *appsv1.StatefulSet) []string {
	var changed []string

	// Check replicas
	if current.Spec.Replicas != nil && desired.Spec.Replicas != nil {
		if *current.Spec.Replicas != *desired.Spec.Replicas {
			changed = append(changed, "replicas")
		}
	}

	// Check container image
	if len(current.Spec.Template.Spec.Containers) > 0 && len(desired.Spec.Template.Spec.Containers) > 0 {
		if current.Spec.Template.Spec.Containers[0].Image != desired.Spec.Template.Spec.Containers[0].Image {
			changed = append(changed, "image")
		}
		// Check resources
		currentRes := current.Spec.Template.Spec.Containers[0].Resources
		desiredRes := desired.Spec.Template.Spec.Containers[0].Resources
		if !resourcesEqual(currentRes, desiredRes) {
			changed = append(changed, "resources")
		}
	}

	if len(changed) == 0 {
		changed = append(changed, "spec")
	}

	return changed
}

// resourcesEqual compares two ResourceRequirements
func resourcesEqual(a, b corev1.ResourceRequirements) bool {
	// Compare requests
	if !resourceListEqual(a.Requests, b.Requests) {
		return false
	}
	// Compare limits
	if !resourceListEqual(a.Limits, b.Limits) {
		return false
	}
	return true
}

// resourceListEqual compares two ResourceLists
func resourceListEqual(a, b corev1.ResourceList) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || !v.Equal(bv) {
			return false
		}
	}
	return true
}

// getAnnotation safely gets an annotation value
func getAnnotation(annotations map[string]string, key string) string {
	if annotations == nil {
		return ""
	}
	return annotations[key]
}

// GetAnnotationFromMeta gets an annotation from ObjectMeta
func GetAnnotationFromMeta(meta metav1.ObjectMeta, key string) string {
	return getAnnotation(meta.Annotations, key)
}
