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

package patch

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func TestMergeStatefulSetUpdate(t *testing.T) {
	t.Run("preserves immutable fields from current", func(t *testing.T) {
		current := &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "test-sts",
				Namespace:       "default",
				ResourceVersion: "12345",
				Annotations: map[string]string{
					"spec-hash": "old-hash",
				},
			},
			Spec: appsv1.StatefulSetSpec{
				ServiceName: "test-svc",
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "test"},
				},
				VolumeClaimTemplates: []corev1.PersistentVolumeClaim{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "data"},
						Spec: corev1.PersistentVolumeClaimSpec{
							Resources: corev1.VolumeResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceStorage: resource.MustParse("50Gi"),
								},
							},
							// Server-added default
							VolumeMode: ptr.To(corev1.PersistentVolumeFilesystem),
						},
					},
				},
				Replicas: ptr.To(int32(3)),
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "old", Image: "old:v1"}},
					},
				},
			},
		}

		desired := &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-sts",
				Namespace: "default",
				Annotations: map[string]string{
					"spec-hash": "new-hash",
				},
			},
			Spec: appsv1.StatefulSetSpec{
				ServiceName: "test-svc",
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "test"},
				},
				// Desired has VolumeClaimTemplates WITHOUT server defaults
				VolumeClaimTemplates: []corev1.PersistentVolumeClaim{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "data"},
						Spec: corev1.PersistentVolumeClaimSpec{
							Resources: corev1.VolumeResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceStorage: resource.MustParse("50Gi"),
								},
							},
							// No VolumeMode set - server would reject this
						},
					},
				},
				Replicas: ptr.To(int32(5)),
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "new", Image: "new:v2"}},
					},
				},
			},
		}

		MergeStatefulSetUpdate(current, desired)

		// ResourceVersion should be preserved (not overwritten)
		if current.ResourceVersion != "12345" {
			t.Errorf("ResourceVersion should be preserved, got %s", current.ResourceVersion)
		}

		// Annotations should be merged (new-hash from desired)
		if current.Annotations["spec-hash"] != "new-hash" {
			t.Errorf("Annotations should have new-hash, got %s", current.Annotations["spec-hash"])
		}

		// Replicas should be updated
		if *current.Spec.Replicas != 5 {
			t.Errorf("Replicas should be 5, got %d", *current.Spec.Replicas)
		}

		// Template should be updated
		if current.Spec.Template.Spec.Containers[0].Image != "new:v2" {
			t.Errorf("Container image should be new:v2, got %s", current.Spec.Template.Spec.Containers[0].Image)
		}

		// VolumeClaimTemplates should be preserved from current (with server defaults)
		if current.Spec.VolumeClaimTemplates[0].Spec.VolumeMode == nil {
			t.Error("VolumeClaimTemplates VolumeMode should be preserved from current")
		}
	})

	t.Run("preserves server-added annotations", func(t *testing.T) {
		current := &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"kubectl.kubernetes.io/last-applied": "something",
					"spec-hash":                          "old",
				},
			},
			Spec: appsv1.StatefulSetSpec{},
		}

		desired := &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"spec-hash": "new",
				},
			},
			Spec: appsv1.StatefulSetSpec{},
		}

		MergeStatefulSetUpdate(current, desired)

		if current.Annotations["kubectl.kubernetes.io/last-applied"] != "something" {
			t.Error("Server-added annotations should be preserved")
		}
		if current.Annotations["spec-hash"] != "new" {
			t.Error("Operator annotations should be updated")
		}
	})

	t.Run("handles nil desired annotations", func(t *testing.T) {
		current := &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"existing": "value",
				},
			},
			Spec: appsv1.StatefulSetSpec{},
		}

		desired := &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{},
			Spec:       appsv1.StatefulSetSpec{},
		}

		MergeStatefulSetUpdate(current, desired)

		// Original annotations should be preserved when desired has none
		if current.Annotations["existing"] != "value" {
			t.Error("Existing annotations should be preserved when desired has none")
		}
	})
}

func TestMergeDeploymentUpdate(t *testing.T) {
	t.Run("merges mutable fields from desired into current", func(t *testing.T) {
		current := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "test-deploy",
				ResourceVersion: "99999",
				Annotations: map[string]string{
					"spec-hash":      "old-hash",
					"server-managed": "keep-me",
				},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: ptr.To(int32(2)),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "test"},
				},
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "old", Image: "old:v1"}},
					},
				},
			},
		}

		desired := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-deploy",
				Annotations: map[string]string{
					"spec-hash": "new-hash",
				},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: ptr.To(int32(4)),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "test"},
				},
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "new", Image: "new:v2"}},
					},
				},
			},
		}

		MergeDeploymentUpdate(current, desired)

		if current.ResourceVersion != "99999" {
			t.Error("ResourceVersion should be preserved")
		}
		if current.Annotations["spec-hash"] != "new-hash" {
			t.Error("Annotations should be updated")
		}
		if current.Annotations["server-managed"] != "keep-me" {
			t.Error("Server-managed annotations should be preserved")
		}
		if *current.Spec.Replicas != 4 {
			t.Errorf("Replicas should be 4, got %d", *current.Spec.Replicas)
		}
		if current.Spec.Template.Spec.Containers[0].Image != "new:v2" {
			t.Error("Container image should be updated")
		}
	})
}
