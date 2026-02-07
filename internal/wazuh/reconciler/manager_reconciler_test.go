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

func TestManagerReconciler_ReconcileStandalone_TolerationsAffinity(t *testing.T) {
	dns.Initialize()
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)

	masterTol1 := []corev1.Toleration{{Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "wazuh", Effect: corev1.TaintEffectNoSchedule}}
	masterTol2 := []corev1.Toleration{{Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "wazuh-updated", Effect: corev1.TaintEffectNoSchedule}}
	workerTol1 := []corev1.Toleration{{Key: "pool", Operator: corev1.TolerationOpEqual, Value: "workers", Effect: corev1.TaintEffectNoExecute}}
	workerTol2 := []corev1.Toleration{{Key: "pool", Operator: corev1.TolerationOpEqual, Value: "workers-updated", Effect: corev1.TaintEffectNoExecute}}

	masterAffinity1 := &corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "node_pool", Operator: corev1.NodeSelectorOpIn, Values: []string{"master"}}}},
				},
			},
		},
	}
	masterAffinity2 := &corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "node_pool", Operator: corev1.NodeSelectorOpIn, Values: []string{"master-updated"}}}},
				},
			},
		},
	}

	workerAffinity1 := &corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "node_pool", Operator: corev1.NodeSelectorOpIn, Values: []string{"worker"}}}},
				},
			},
		},
	}
	workerAffinity2 := &corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "node_pool", Operator: corev1.NodeSelectorOpIn, Values: []string{"worker-updated"}}}},
				},
			},
		},
	}

	manager := &wazuhv1.WazuhManager{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "wazuh-manager",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhManagerSpec{
			Version: "4.14.0",
			Master: wazuhv1.WazuhMasterSpec{
				Tolerations: masterTol1,
				Affinity:    masterAffinity1,
			},
			Workers: wazuhv1.WazuhWorkerSpec{
				Replicas:    int32Ptr(1),
				Tolerations: workerTol1,
				Affinity:    workerAffinity1,
			},
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(manager).Build()
	reconciler := NewManagerReconciler(client, scheme)

	ctx := context.Background()
	if err := reconciler.ReconcileStandalone(ctx, manager); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	masterSts := &appsv1.StatefulSet{}
	if err := client.Get(ctx, types.NamespacedName{Name: "wazuh-manager-manager-master", Namespace: "default"}, masterSts); err != nil {
		t.Fatalf("failed to get master statefulset: %v", err)
	}
	if !reflect.DeepEqual(masterSts.Spec.Template.Spec.Tolerations, masterTol1) {
		t.Fatalf("master tolerations not applied, got %#v", masterSts.Spec.Template.Spec.Tolerations)
	}
	if !reflect.DeepEqual(masterSts.Spec.Template.Spec.Affinity, masterAffinity1) {
		t.Fatalf("master affinity not applied, got %#v", masterSts.Spec.Template.Spec.Affinity)
	}

	workerSts := &appsv1.StatefulSet{}
	if err := client.Get(ctx, types.NamespacedName{Name: "wazuh-manager-manager-worker", Namespace: "default"}, workerSts); err != nil {
		t.Fatalf("failed to get worker statefulset: %v", err)
	}
	if !reflect.DeepEqual(workerSts.Spec.Template.Spec.Tolerations, workerTol1) {
		t.Fatalf("worker tolerations not applied, got %#v", workerSts.Spec.Template.Spec.Tolerations)
	}
	if !reflect.DeepEqual(workerSts.Spec.Template.Spec.Affinity, workerAffinity1) {
		t.Fatalf("worker affinity not applied, got %#v", workerSts.Spec.Template.Spec.Affinity)
	}

	manager.Spec.Master.Tolerations = masterTol2
	manager.Spec.Master.Affinity = masterAffinity2
	manager.Spec.Workers.Tolerations = workerTol2
	manager.Spec.Workers.Affinity = workerAffinity2
	if err := client.Update(ctx, manager); err != nil {
		t.Fatalf("failed to update manager: %v", err)
	}

	if err := reconciler.ReconcileStandalone(ctx, manager); err != nil {
		t.Fatalf("reconcile after update failed: %v", err)
	}

	if err := client.Get(ctx, types.NamespacedName{Name: "wazuh-manager-manager-master", Namespace: "default"}, masterSts); err != nil {
		t.Fatalf("failed to get master statefulset after update: %v", err)
	}
	if !reflect.DeepEqual(masterSts.Spec.Template.Spec.Tolerations, masterTol2) {
		t.Fatalf("master tolerations not updated, got %#v", masterSts.Spec.Template.Spec.Tolerations)
	}
	if !reflect.DeepEqual(masterSts.Spec.Template.Spec.Affinity, masterAffinity2) {
		t.Fatalf("master affinity not updated, got %#v", masterSts.Spec.Template.Spec.Affinity)
	}

	if err := client.Get(ctx, types.NamespacedName{Name: "wazuh-manager-manager-worker", Namespace: "default"}, workerSts); err != nil {
		t.Fatalf("failed to get worker statefulset after update: %v", err)
	}
	if !reflect.DeepEqual(workerSts.Spec.Template.Spec.Tolerations, workerTol2) {
		t.Fatalf("worker tolerations not updated, got %#v", workerSts.Spec.Template.Spec.Tolerations)
	}
	if !reflect.DeepEqual(workerSts.Spec.Template.Spec.Affinity, workerAffinity2) {
		t.Fatalf("worker affinity not updated, got %#v", workerSts.Spec.Template.Spec.Affinity)
	}
}
