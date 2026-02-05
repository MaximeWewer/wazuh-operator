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

package utils //nolint:revive // utils is a common package name

import (
	"context"
	"fmt"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestIsStatefulSetImmutableError(t *testing.T) {
	err := apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "statefulsets"}, "test",
		fmt.Errorf("StatefulSet.apps \"x\" is invalid: spec: Forbidden: updates to statefulset spec for fields other than 'replicas' are forbidden"))

	if !IsStatefulSetImmutableError(err) {
		t.Fatal("expected immutable error to be detected")
	}
}

func TestIsStatefulSetImmutableError_NilError(t *testing.T) {
	if IsStatefulSetImmutableError(nil) {
		t.Fatal("expected nil error to return false")
	}
}

func TestIsStatefulSetImmutableError_NonImmutable(t *testing.T) {
	// A generic Forbidden error that is NOT about immutable fields
	err := apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "statefulsets"}, "test",
		fmt.Errorf("User \"system:serviceaccount:foo:bar\" cannot update resource \"statefulsets\" in API group \"apps\""))

	if IsStatefulSetImmutableError(err) {
		t.Fatal("expected generic forbidden error to NOT match as immutable")
	}
}

func TestIsStatefulSetImmutableError_VolumeClaimTemplates(t *testing.T) {
	err := apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "statefulsets"}, "test",
		fmt.Errorf("StatefulSet.apps \"x\" is invalid: spec: Forbidden: updates to statefulset spec for fields other than 'replicas', 'ordinals', 'template', 'updateStrategy', 'persistentVolumeClaimRetentionPolicy' and 'minReadySeconds' are forbidden, including volumeClaimTemplates"))

	if !IsStatefulSetImmutableError(err) {
		t.Fatal("expected volumeClaimTemplates error to be detected as immutable")
	}
}

func TestIsDeploymentImmutableError(t *testing.T) {
	err := apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "deployments"}, "test",
		fmt.Errorf("Deployment.apps \"x\" is invalid: spec.selector: Invalid value: ... field is immutable"))

	if !IsDeploymentImmutableError(err) {
		t.Fatal("expected immutable error to be detected")
	}
}

func TestIsDeploymentImmutableError_NilError(t *testing.T) {
	if IsDeploymentImmutableError(nil) {
		t.Fatal("expected nil error to return false")
	}
}

func TestIsDeploymentImmutableError_NonSelector(t *testing.T) {
	// An immutable field error but NOT about spec.selector
	err := apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "deployments"}, "test",
		fmt.Errorf("Deployment.apps \"x\" is invalid: spec.template.spec.nodeSelector: field is immutable"))

	if IsDeploymentImmutableError(err) {
		t.Fatal("expected non-selector immutable error to NOT match")
	}
}

func TestRecreateStatefulSetOnError(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	existing := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sts",
			Namespace: "ns",
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: int32Ptr(1),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "x"}},
			},
		},
	}

	desired := existing.DeepCopy()
	desired.Spec.Replicas = int32Ptr(2)

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()

	err := apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "statefulsets"}, "sts",
		fmt.Errorf("StatefulSet.apps \"sts\" is invalid: spec: Forbidden: updates to statefulset spec for fields other than 'replicas' are forbidden"))

	recreated, recErr := RecreateStatefulSetOnError(context.Background(), cl, desired, existing, err)
	if recErr != nil {
		t.Fatalf("unexpected error: %v", recErr)
	}
	if !recreated {
		t.Fatal("expected recreation to occur")
	}

	// Verify the StatefulSet was deleted (Get should return NotFound)
	got := &appsv1.StatefulSet{}
	getErr := cl.Get(context.Background(), types.NamespacedName{Name: "sts", Namespace: "ns"}, got)
	if !apierrors.IsNotFound(getErr) {
		t.Fatalf("expected NotFound after deletion, got: %v", getErr)
	}
}

func TestRecreateDeploymentOnError(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	existing := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dep",
			Namespace: "ns",
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "x"}},
			},
		},
	}

	desired := existing.DeepCopy()

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()

	err := apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "deployments"}, "dep",
		fmt.Errorf("Deployment.apps \"dep\" is invalid: spec.selector: Invalid value: ... field is immutable"))

	recreated, recErr := RecreateDeploymentOnError(context.Background(), cl, desired, existing, err)
	if recErr != nil {
		t.Fatalf("unexpected error: %v", recErr)
	}
	if !recreated {
		t.Fatal("expected recreation to occur")
	}

	// Verify the Deployment was deleted (Get should return NotFound)
	got := &appsv1.Deployment{}
	getErr := cl.Get(context.Background(), types.NamespacedName{Name: "dep", Namespace: "ns"}, got)
	if !apierrors.IsNotFound(getErr) {
		t.Fatalf("expected NotFound after deletion, got: %v", getErr)
	}
}

func TestRecreateStatefulSetOnError_NonImmutablePassThrough(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	existing := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sts",
			Namespace: "ns",
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: int32Ptr(1),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "x"}},
			},
		},
	}

	desired := existing.DeepCopy()
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()

	// Use a generic error that is NOT an immutable field error
	originalErr := fmt.Errorf("some random update error")

	recreated, recErr := RecreateStatefulSetOnError(context.Background(), cl, desired, existing, originalErr)
	if recreated {
		t.Fatal("expected recreated to be false for non-immutable error")
	}
	if recErr != originalErr {
		t.Fatalf("expected original error to be passed through, got: %v", recErr)
	}

	// Verify the StatefulSet was NOT deleted
	got := &appsv1.StatefulSet{}
	getErr := cl.Get(context.Background(), types.NamespacedName{Name: "sts", Namespace: "ns"}, got)
	if getErr != nil {
		t.Fatalf("expected StatefulSet to still exist, got error: %v", getErr)
	}
}

func TestRecreateStatefulSetOnError_DeleteOnly(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	existing := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sts",
			Namespace: "ns",
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: int32Ptr(1),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "x"}},
			},
		},
	}

	desired := existing.DeepCopy()
	desired.Spec.Replicas = int32Ptr(2)

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()

	err := apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "statefulsets"}, "sts",
		fmt.Errorf("StatefulSet.apps \"sts\" is invalid: spec: Forbidden: updates to statefulset spec for fields other than 'replicas' are forbidden"))

	recreated, recErr := RecreateStatefulSetOnError(context.Background(), cl, desired, existing, err)
	if recErr != nil {
		t.Fatalf("unexpected error: %v", recErr)
	}
	if !recreated {
		t.Fatal("expected recreated to be true")
	}

	// Verify resource is gone (delete-only, no create)
	got := &appsv1.StatefulSet{}
	getErr := cl.Get(context.Background(), types.NamespacedName{Name: "sts", Namespace: "ns"}, got)
	if !apierrors.IsNotFound(getErr) {
		t.Fatalf("expected NotFound (delete-only, no create), got: %v", getErr)
	}
}

func TestRecreateStatefulSetOnError_AlreadyGone(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	// Do NOT register the StatefulSet as an existing object - it's already gone
	existing := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sts",
			Namespace: "ns",
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: int32Ptr(1),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "x"}},
			},
		},
	}

	desired := existing.DeepCopy()

	// Build client WITHOUT the existing object (simulates already deleted)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	err := apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "statefulsets"}, "sts",
		fmt.Errorf("StatefulSet.apps \"sts\" is invalid: spec: Forbidden: updates to statefulset spec for fields other than 'replicas' are forbidden"))

	recreated, recErr := RecreateStatefulSetOnError(context.Background(), cl, desired, existing, err)
	if recErr != nil {
		t.Fatalf("expected no error when resource already gone, got: %v", recErr)
	}
	if !recreated {
		t.Fatal("expected recreated to be true even when resource already gone")
	}
}

func int32Ptr(i int32) *int32 {
	return &i
}
