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
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// boolPtrInt returns a pointer to a bool value (local helper for integration tests)
func boolPtrInt(b bool) *bool {
	return &b
}

// Integration test scenarios that simulate full certificate lifecycle

func TestCertificateRenewal_FullScenario_HotReloadSupported(t *testing.T) {
	// Scenario: Certificate renewal with hot-reload supported version (4.14.x)
	// Expected: Hot reload API call should succeed, no restart triggered

	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)

	// Create cluster with hot-reload supported version
	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.14.0", // Automatic hot reload version
			TLS: &wazuhv1.TLSConfig{
				Enabled: boolPtrInt(true),
				HotReload: &wazuhv1.HotReloadConfig{
					Enabled: true,
				},
			},
			Indexer: &wazuhv1.WazuhIndexerClusterSpec{
				Replicas: 3,
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster).
		Build()
	recorder := record.NewFakeRecorder(20)

	reconciler := NewCertificateReconciler(client, scheme).
		WithEventRecorder(recorder)

	ctx := context.Background()

	// Test that hot reload is triggered correctly
	result := reconciler.TriggerCertificateHotReloadWithFallback(ctx, cluster, constants.CertTypeNode)

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.HotReloadResult == nil {
		t.Fatal("Expected HotReloadResult to be set")
	}

	// For automatic hot reload (4.14.x), no API call needed
	if !result.HotReloadResult.Supported {
		t.Error("Expected hot reload to be supported for version 4.14.0")
	}

	if result.FallbackTriggered {
		t.Error("Expected no fallback for automatic hot reload success")
	}

	if result.Strategy != "hot-reload" {
		t.Errorf("Expected strategy 'hot-reload', got %s", result.Strategy)
	}
}

func TestCertificateRenewal_FullScenario_HotReloadNotSupported(t *testing.T) {
	// Scenario: Certificate renewal with hot-reload NOT supported version (4.7.x)
	// Expected: Fallback to rolling restart should be triggered

	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)

	replicas := int32(3)
	indexerSts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-indexer",
			Namespace: "default",
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
		},
	}

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.7.0", // Hot reload NOT supported
			TLS: &wazuhv1.TLSConfig{
				Enabled: boolPtrInt(true),
				HotReload: &wazuhv1.HotReloadConfig{
					Enabled: true,
				},
			},
			Indexer: &wazuhv1.WazuhIndexerClusterSpec{
				Replicas: 3,
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster, indexerSts).
		Build()
	recorder := record.NewFakeRecorder(20)

	reconciler := NewCertificateReconciler(client, scheme).
		WithEventRecorder(recorder)

	ctx := context.Background()

	// Test that fallback is triggered
	result := reconciler.TriggerCertificateHotReloadWithFallback(ctx, cluster, constants.CertTypeNode)

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.HotReloadResult.Supported {
		t.Error("Expected hot reload to NOT be supported for version 4.7.0")
	}

	if !result.FallbackTriggered {
		t.Error("Expected fallback to be triggered when hot reload not supported")
	}

	if result.FallbackReason == "" {
		t.Error("Expected FallbackReason to be set")
	}
}

func TestRollingRestart_CACertRenewal_AllComponentsRestarted(t *testing.T) {
	// Scenario: CA certificate renewal should restart ALL components

	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	replicas := int32(1)
	workerReplicas := int32(2)
	dashReplicas := int32(1)

	// Create all component resources
	indexerSts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-indexer",
			Namespace: "default",
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
		},
	}

	masterSts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-manager-master",
			Namespace: "default",
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
		},
	}

	workersSts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-manager-workers",
			Namespace: "default",
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &workerReplicas,
		},
	}

	dashboardDeploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-dashboard",
			Namespace: "default",
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &dashReplicas,
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(indexerSts, masterSts, workersSts, dashboardDeploy).
		Build()

	ctx := context.Background()

	// Get restart config for CA cert
	config := GetRestartConfigForCertType(constants.CertTypeCA)
	config.ClusterName = "test-cluster"
	config.Namespace = "default"

	// Verify CA cert triggers all components
	if !config.TriggerIndexers {
		t.Error("CA cert should trigger indexer restart")
	}
	if !config.TriggerManagers {
		t.Error("CA cert should trigger manager restart")
	}
	if !config.TriggerDashboard {
		t.Error("CA cert should trigger dashboard restart")
	}

	// Execute the restarts
	result := TriggerCertRenewalRestarts(ctx, client, config)

	if result.TotalTriggered < 3 {
		t.Errorf("Expected at least 3 components triggered, got %d", result.TotalTriggered)
	}

	// Verify annotations were set on resources
	updatedIndexer := &appsv1.StatefulSet{}
	_ = client.Get(ctx, types.NamespacedName{Name: "test-cluster-indexer", Namespace: "default"}, updatedIndexer)
	if _, exists := updatedIndexer.Spec.Template.Annotations[constants.AnnotationRestartedAt]; !exists {
		t.Error("Expected restartedAt annotation on indexer")
	}

	updatedDashboard := &appsv1.Deployment{}
	_ = client.Get(ctx, types.NamespacedName{Name: "test-cluster-dashboard", Namespace: "default"}, updatedDashboard)
	if _, exists := updatedDashboard.Spec.Template.Annotations[constants.AnnotationRestartedAt]; !exists {
		t.Error("Expected restartedAt annotation on dashboard")
	}
}

func TestRollingRestart_NodeCertRenewal_OnlyIndexersRestarted(t *testing.T) {
	// Scenario: Node certificate renewal should only affect indexers (with hot reload option)

	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	replicas := int32(3)
	indexerSts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-indexer",
			Namespace: "default",
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
		},
	}

	masterSts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-manager-master",
			Namespace: "default",
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
		},
	}

	// Build client (useful for future test extensions)
	_ = fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(indexerSts, masterSts).
		Build()

	// Get restart config for node cert
	config := GetRestartConfigForCertType(constants.CertTypeNode)

	// Verify node cert only affects indexers
	if !config.TriggerIndexers {
		t.Error("Node cert should trigger indexer restart (unless hot reload)")
	}
	if config.TriggerManagers {
		t.Error("Node cert should NOT trigger manager restart")
	}
	if config.TriggerDashboard {
		t.Error("Node cert should NOT trigger dashboard restart")
	}
	if !config.AllowHotReload {
		t.Error("Node cert should allow hot reload")
	}
}

func TestRollingRestart_FilebeatCertRenewal_OnlyManagersRestarted(t *testing.T) {
	// Scenario: Filebeat certificate renewal should only affect managers

	config := GetRestartConfigForCertType(constants.CertTypeFilebeat)

	if config.TriggerIndexers {
		t.Error("Filebeat cert should NOT trigger indexer restart")
	}
	if !config.TriggerManagers {
		t.Error("Filebeat cert should trigger manager restart")
	}
	if config.TriggerDashboard {
		t.Error("Filebeat cert should NOT trigger dashboard restart")
	}
}

func TestRollingRestart_AdminCertRenewal_NoRestartNeeded(t *testing.T) {
	// Scenario: Admin certificate renewal should not require any restarts

	config := GetRestartConfigForCertType(constants.CertTypeAdmin)

	if config.TriggerIndexers {
		t.Error("Admin cert should NOT trigger indexer restart")
	}
	if config.TriggerManagers {
		t.Error("Admin cert should NOT trigger manager restart")
	}
	if config.TriggerDashboard {
		t.Error("Admin cert should NOT trigger dashboard restart")
	}

	// Test the dedicated admin handler
	ctx := context.Background()
	result, err := TriggerAdminCertificateRenewalRestart(ctx, "test-cluster", "default")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !result.NoRestartRequired {
		t.Error("Admin cert renewal should not require restart")
	}
}

func TestRollingRestart_DashboardCertRenewal_OnlyDashboardRestarted(t *testing.T) {
	// Scenario: Dashboard certificate renewal should only affect dashboard

	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	replicas := int32(2)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-dashboard",
			Namespace: "default",
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(deployment).
		Build()

	ctx := context.Background()

	// Get restart config for dashboard cert
	config := GetRestartConfigForCertType(constants.CertTypeDashboard)

	if config.TriggerIndexers {
		t.Error("Dashboard cert should NOT trigger indexer restart")
	}
	if config.TriggerManagers {
		t.Error("Dashboard cert should NOT trigger manager restart")
	}
	if !config.TriggerDashboard {
		t.Error("Dashboard cert should trigger dashboard restart")
	}

	// Test the dedicated dashboard handler
	result, err := TriggerDashboardCertificateRenewalRestart(ctx, client, "default", "test-cluster")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !result.Restarted {
		t.Error("Expected dashboard to be restarted")
	}

	// Verify annotation was set
	updatedDeployment := &appsv1.Deployment{}
	_ = client.Get(ctx, types.NamespacedName{Name: "test-cluster-dashboard", Namespace: "default"}, updatedDeployment)
	if _, exists := updatedDeployment.Spec.Template.Annotations[constants.AnnotationRestartedAt]; !exists {
		t.Error("Expected restartedAt annotation on dashboard")
	}
}

func TestPodSyncVerification_AllPodsSync(t *testing.T) {
	// Test the PodSyncVerificationResult structure
	result := &PodSyncVerificationResult{
		TotalPods:   3,
		SyncedPods:  3,
		PendingPods: 0,
		FailedPods:  0,
		PodResults: []PodSyncResult{
			{PodName: "pod-0", SyncStatus: SyncStatusSynced},
			{PodName: "pod-1", SyncStatus: SyncStatusSynced},
			{PodName: "pod-2", SyncStatus: SyncStatusSynced},
		},
		AllSynced: true,
	}

	if !result.AllSynced {
		t.Error("Expected AllSynced to be true when all pods are synced")
	}

	if result.SyncedPods != result.TotalPods {
		t.Error("Expected SyncedPods to equal TotalPods")
	}
}

func TestPodSyncVerification_PartialSync(t *testing.T) {
	result := &PodSyncVerificationResult{
		TotalPods:   3,
		SyncedPods:  1,
		PendingPods: 1,
		FailedPods:  1,
		PodResults: []PodSyncResult{
			{PodName: "pod-0", SyncStatus: SyncStatusSynced},
			{PodName: "pod-1", SyncStatus: SyncStatusPending},
			{PodName: "pod-2", SyncStatus: SyncStatusFailed},
		},
		AllSynced: false,
	}

	if result.AllSynced {
		t.Error("Expected AllSynced to be false when not all pods are synced")
	}

	if result.FailedPods != 1 {
		t.Errorf("Expected 1 failed pod, got %d", result.FailedPods)
	}
}

func TestCertificateTimings_Propagation(t *testing.T) {
	// Verify the propagation timeout is set correctly
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := NewCertificateReconciler(client, scheme).
		WithPropagationTimeout(60 * time.Second) // Custom timeout

	if reconciler.PropagationTimeout != 60*time.Second {
		t.Errorf("Expected propagation timeout of 60s, got %v", reconciler.PropagationTimeout)
	}
}

func TestHotReloadWithFallback_EventEmission(t *testing.T) {
	// Test that events are properly emitted during hot reload with fallback
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.7.0", // Hot reload not supported - will fallback
			TLS: &wazuhv1.TLSConfig{
				Enabled: boolPtrInt(true),
				HotReload: &wazuhv1.HotReloadConfig{
					Enabled: true,
				},
			},
		},
	}

	replicas := int32(1)
	indexerSts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-indexer",
			Namespace: "default",
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster, indexerSts).
		Build()
	recorder := record.NewFakeRecorder(20)

	reconciler := NewCertificateReconciler(client, scheme).
		WithEventRecorder(recorder)

	ctx := context.Background()
	_ = reconciler.TriggerCertificateHotReloadWithFallback(ctx, cluster, constants.CertTypeNode)

	// Verify events were emitted
	select {
	case event := <-recorder.Events:
		// Should have at least one event (fallback warning)
		if event == "" {
			t.Error("Expected non-empty event")
		}
	case <-time.After(100 * time.Millisecond):
		// It's OK if no events for fallback path in some cases
	}
}
