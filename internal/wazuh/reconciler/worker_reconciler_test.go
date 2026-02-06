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
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

func TestWorkerReconciler_ReconcileStandalone_TolerationsAffinity(t *testing.T) {
	dns.Initialize()
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)

	tol1 := []corev1.Toleration{{Key: "pool", Operator: corev1.TolerationOpEqual, Value: "worker", Effect: corev1.TaintEffectNoSchedule}}
	tol2 := []corev1.Toleration{{Key: "pool", Operator: corev1.TolerationOpEqual, Value: "worker-updated", Effect: corev1.TaintEffectNoSchedule}}

	aff1 := &corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "node_pool", Operator: corev1.NodeSelectorOpIn, Values: []string{"worker"}}}},
				},
			},
		},
	}
	aff2 := &corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "node_pool", Operator: corev1.NodeSelectorOpIn, Values: []string{"worker-updated"}}}},
				},
			},
		},
	}

	worker := &wazuhv1.WazuhWorker{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "wazuh-worker",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhWorkerCRDSpec{
			Replicas:    1,
			ManagerRef:  "wazuh-cluster",
			Tolerations: tol1,
			Affinity:    aff1,
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(worker).Build()
	reconciler := NewWorkerReconciler(client, scheme)

	ctx := context.Background()
	if err := reconciler.ReconcileStandalone(ctx, worker); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	sts := &appsv1.StatefulSet{}
	if err := client.Get(ctx, types.NamespacedName{Name: "wazuh-worker-manager-worker", Namespace: "default"}, sts); err != nil {
		t.Fatalf("failed to get worker statefulset: %v", err)
	}
	if !reflect.DeepEqual(sts.Spec.Template.Spec.Tolerations, tol1) {
		t.Fatalf("tolerations not applied, got %#v", sts.Spec.Template.Spec.Tolerations)
	}
	if !reflect.DeepEqual(sts.Spec.Template.Spec.Affinity, aff1) {
		t.Fatalf("affinity not applied, got %#v", sts.Spec.Template.Spec.Affinity)
	}

	worker.Spec.Tolerations = tol2
	worker.Spec.Affinity = aff2
	if err := client.Update(ctx, worker); err != nil {
		t.Fatalf("failed to update worker: %v", err)
	}

	if err := reconciler.ReconcileStandalone(ctx, worker); err != nil {
		t.Fatalf("reconcile after update failed: %v", err)
	}

	if err := client.Get(ctx, types.NamespacedName{Name: "wazuh-worker-manager-worker", Namespace: "default"}, sts); err != nil {
		t.Fatalf("failed to get worker statefulset after update: %v", err)
	}
	if !reflect.DeepEqual(sts.Spec.Template.Spec.Tolerations, tol2) {
		t.Fatalf("tolerations not updated, got %#v", sts.Spec.Template.Spec.Tolerations)
	}
	if !reflect.DeepEqual(sts.Spec.Template.Spec.Affinity, aff2) {
		t.Fatalf("affinity not updated, got %#v", sts.Spec.Template.Spec.Affinity)
	}
}
