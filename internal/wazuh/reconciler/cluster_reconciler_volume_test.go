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
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

func TestReconcileMasterVolumeExpansion_NoPVCs(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			Manager: &wazuhv1.WazuhManagerClusterSpec{
				Master: wazuhv1.WazuhMasterSpec{
					StorageSize: "50Gi",
				},
				Workers: wazuhv1.WazuhWorkerSpec{
					Replicas: int32Ptr(2),
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster).
		Build()

	reconciler := NewClusterReconciler(client, scheme)

	err := reconciler.reconcileMasterVolumeExpansion(context.Background(), cluster)
	if err != nil {
		t.Fatalf("Expected no error for empty PVC list, got: %v", err)
	}

	// No expansion status should be set
	if cluster.Status.VolumeExpansion != nil && cluster.Status.VolumeExpansion.ManagerMasterExpansion != nil {
		t.Error("Expected nil expansion status when no PVCs exist")
	}
}

func TestReconcileWorkerVolumeExpansion_NoPVCs(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			Manager: &wazuhv1.WazuhManagerClusterSpec{
				Master: wazuhv1.WazuhMasterSpec{},
				Workers: wazuhv1.WazuhWorkerSpec{
					Replicas:    int32Ptr(2),
					StorageSize: "50Gi",
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster).
		Build()

	reconciler := NewClusterReconciler(client, scheme)

	err := reconciler.reconcileWorkerVolumeExpansion(context.Background(), cluster)
	if err != nil {
		t.Fatalf("Expected no error for empty PVC list, got: %v", err)
	}
}

func TestGetManagerMasterPVCs(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
	}

	// Create PVCs with correct labels
	masterPVC := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "data-test-cluster-manager-master-0",
			Namespace: "default",
			Labels: map[string]string{
				constants.LabelInstance:        "test-cluster",
				constants.LabelManagerNodeType: constants.NodeRoleMaster,
			},
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse("10Gi"),
				},
			},
		},
	}

	// A worker PVC that should NOT be returned
	workerPVC := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "data-test-cluster-manager-workers-0",
			Namespace: "default",
			Labels: map[string]string{
				constants.LabelInstance:        "test-cluster",
				constants.LabelManagerNodeType: constants.NodeRoleWorker,
			},
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse("10Gi"),
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(masterPVC, workerPVC).
		Build()

	reconciler := NewClusterReconciler(client, scheme)

	pvcList, err := reconciler.getManagerMasterPVCs(context.Background(), cluster)
	if err != nil {
		t.Fatalf("getManagerMasterPVCs failed: %v", err)
	}

	if len(pvcList.Items) != 1 {
		t.Errorf("Expected 1 master PVC, got %d", len(pvcList.Items))
	}

	if len(pvcList.Items) > 0 && pvcList.Items[0].Name != "data-test-cluster-manager-master-0" {
		t.Errorf("Expected master PVC, got %s", pvcList.Items[0].Name)
	}
}

func TestGetManagerWorkerPVCs(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
	}

	workerPVC1 := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "data-test-cluster-manager-workers-0",
			Namespace: "default",
			Labels: map[string]string{
				constants.LabelInstance:        "test-cluster",
				constants.LabelManagerNodeType: constants.NodeRoleWorker,
			},
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse("10Gi"),
				},
			},
		},
	}

	workerPVC2 := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "data-test-cluster-manager-workers-1",
			Namespace: "default",
			Labels: map[string]string{
				constants.LabelInstance:        "test-cluster",
				constants.LabelManagerNodeType: constants.NodeRoleWorker,
			},
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse("10Gi"),
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(workerPVC1, workerPVC2).
		Build()

	reconciler := NewClusterReconciler(client, scheme)

	pvcList, err := reconciler.getManagerWorkerPVCs(context.Background(), cluster)
	if err != nil {
		t.Fatalf("getManagerWorkerPVCs failed: %v", err)
	}

	if len(pvcList.Items) != 2 {
		t.Errorf("Expected 2 worker PVCs, got %d", len(pvcList.Items))
	}
}

func TestUpdateManagerMasterExpansionStatus_Completed(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	reconciler := NewClusterReconciler(client, scheme)
	recorder := record.NewFakeRecorder(10)
	reconciler.Recorder = recorder

	pvcsExpanded := []string{"data-test-cluster-manager-master-0"}
	reconciler.updateManagerMasterExpansionStatus(context.Background(), cluster, "50Gi", pvcsExpanded, nil, nil)

	if cluster.Status.VolumeExpansion == nil {
		t.Fatal("Expected VolumeExpansion status to be set")
	}

	if cluster.Status.VolumeExpansion.ManagerMasterExpansion == nil {
		t.Fatal("Expected ManagerMasterExpansion status to be set")
	}

	if cluster.Status.VolumeExpansion.ManagerMasterExpansion.Phase != wazuhv1.ExpansionPhaseCompleted {
		t.Errorf("Expected phase Completed, got %s", cluster.Status.VolumeExpansion.ManagerMasterExpansion.Phase)
	}
}

func TestUpdateManagerWorkerExpansionStatus_Failed(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	reconciler := NewClusterReconciler(client, scheme)
	recorder := record.NewFakeRecorder(10)
	reconciler.Recorder = recorder

	pvcsPending := []string{"data-test-cluster-manager-workers-0"}
	testErr := fmt.Errorf("storage class does not support expansion")
	reconciler.updateManagerWorkerExpansionStatus(context.Background(), cluster, "50Gi", nil, pvcsPending, testErr)

	if cluster.Status.VolumeExpansion == nil {
		t.Fatal("Expected VolumeExpansion status to be set")
	}

	if cluster.Status.VolumeExpansion.ManagerWorkersExpansion == nil {
		t.Fatal("Expected ManagerWorkersExpansion status to be set")
	}

	if cluster.Status.VolumeExpansion.ManagerWorkersExpansion.Phase != wazuhv1.ExpansionPhaseFailed {
		t.Errorf("Expected phase Failed, got %s", cluster.Status.VolumeExpansion.ManagerWorkersExpansion.Phase)
	}
}
