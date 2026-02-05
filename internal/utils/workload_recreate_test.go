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
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestIsStatefulSetImmutableError(t *testing.T) {
	err := apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "statefulsets"}, "test",
		fmt.Errorf("StatefulSet.apps \"x\" is invalid: spec: Forbidden: updates to statefulset spec for fields other than 'replicas' are forbidden"))

	if !IsStatefulSetImmutableError(err) {
		t.Fatal("expected immutable error to be detected")
	}
}

func TestIsDeploymentImmutableError(t *testing.T) {
	err := apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "deployments"}, "test",
		fmt.Errorf("Deployment.apps \"x\" is invalid: spec.selector: Invalid value: ... field is immutable"))

	if !IsDeploymentImmutableError(err) {
		t.Fatal("expected immutable error to be detected")
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

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()

	err := apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "statefulsets"}, "sts",
		fmt.Errorf("StatefulSet.apps \"sts\" is invalid: spec: Forbidden: updates to statefulset spec for fields other than 'replicas' are forbidden"))

	recreated, recErr := RecreateStatefulSetOnError(context.Background(), client, desired, existing, err)
	if recErr != nil {
		t.Fatalf("unexpected error: %v", recErr)
	}
	if !recreated {
		t.Fatal("expected recreation to occur")
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

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()

	err := apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "deployments"}, "dep",
		fmt.Errorf("Deployment.apps \"dep\" is invalid: spec.selector: Invalid value: ... field is immutable"))

	recreated, recErr := RecreateDeploymentOnError(context.Background(), client, desired, existing, err)
	if recErr != nil {
		t.Fatalf("unexpected error: %v", recErr)
	}
	if !recreated {
		t.Fatal("expected recreation to occur")
	}
}

func int32Ptr(i int32) *int32 {
	return &i
}
