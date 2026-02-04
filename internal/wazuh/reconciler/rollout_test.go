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

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

func TestTriggerDeploymentRollingRestart(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	replicas := int32(2)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-deployment",
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
	config := &RollingRestartConfig{
		Component:    "dashboard",
		CertType:     "dashboard-cert",
		RestartOrder: RestartOrderParallel,
		Reason:       "certificate renewed",
	}

	result, err := TriggerDeploymentRollingRestart(ctx, client, "default", "test-deployment", config)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !result.Triggered {
		t.Error("Expected Triggered to be true")
	}

	if result.Component != "dashboard" {
		t.Errorf("Expected component 'dashboard', got %s", result.Component)
	}

	if result.Reason != "certificate renewed" {
		t.Errorf("Expected reason 'certificate renewed', got %s", result.Reason)
	}

	// Verify annotations were set
	updatedDeployment := &appsv1.Deployment{}
	_ = client.Get(ctx, types.NamespacedName{Name: deployment.Name, Namespace: deployment.Namespace}, updatedDeployment)

	if _, exists := updatedDeployment.Spec.Template.Annotations[constants.AnnotationRestartedAt]; !exists {
		t.Error("Expected restartedAt annotation to be set")
	}

	if updatedDeployment.Spec.Template.Annotations[constants.AnnotationRollingRestartTriggered] != "true" {
		t.Error("Expected rollingRestartTriggered annotation to be 'true'")
	}

	if updatedDeployment.Spec.Template.Annotations[constants.AnnotationConfigChangeDetected] != "dashboard-cert" {
		t.Errorf("Expected configChangeDetected annotation to be 'dashboard-cert', got %s",
			updatedDeployment.Spec.Template.Annotations[constants.AnnotationConfigChangeDetected])
	}
}

func TestTriggerDeploymentRollingRestart_ZeroReplicas(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	replicas := int32(0)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-deployment",
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
	config := &RollingRestartConfig{
		Component: "dashboard",
		Reason:    "certificate renewed",
	}

	result, err := TriggerDeploymentRollingRestart(ctx, client, "default", "test-deployment", config)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Triggered {
		t.Error("Expected Triggered to be false for 0 replicas")
	}

	if result.Reason != "deployment has 0 replicas" {
		t.Errorf("Expected reason to be 'deployment has 0 replicas', got %s", result.Reason)
	}
}

func TestTriggerDeploymentRollingRestart_NotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	ctx := context.Background()
	config := &RollingRestartConfig{
		Component: "dashboard",
		Reason:    "certificate renewed",
	}

	result, err := TriggerDeploymentRollingRestart(ctx, client, "default", "nonexistent", config)

	if err == nil {
		t.Error("Expected error for non-existent deployment")
	}

	if result.Error == nil {
		t.Error("Expected result.Error to be set")
	}
}

func TestTriggerStatefulSetRollingRestart(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	replicas := int32(3)
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sts",
			Namespace: "default",
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sts).
		Build()

	ctx := context.Background()
	config := &RollingRestartConfig{
		Component:    "indexer",
		CertType:     "node-cert",
		RestartOrder: RestartOrderSequential,
		WaitForReady: true,
		Reason:       "certificate renewed",
	}

	result, err := TriggerStatefulSetRollingRestart(ctx, client, "default", "test-sts", config)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !result.Triggered {
		t.Error("Expected Triggered to be true")
	}

	if result.Component != "indexer" {
		t.Errorf("Expected component 'indexer', got %s", result.Component)
	}

	// Verify annotations were set
	updatedSts := &appsv1.StatefulSet{}
	_ = client.Get(ctx, types.NamespacedName{Name: sts.Name, Namespace: sts.Namespace}, updatedSts)

	if _, exists := updatedSts.Spec.Template.Annotations[constants.AnnotationRestartedAt]; !exists {
		t.Error("Expected restartedAt annotation to be set")
	}

	if updatedSts.Spec.Template.Annotations[constants.AnnotationConfigChangeDetected] != "node-cert" {
		t.Errorf("Expected configChangeDetected annotation to be 'node-cert', got %s",
			updatedSts.Spec.Template.Annotations[constants.AnnotationConfigChangeDetected])
	}
}

func TestTriggerStatefulSetRollingRestart_ZeroReplicas(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	replicas := int32(0)
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sts",
			Namespace: "default",
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sts).
		Build()

	ctx := context.Background()
	config := &RollingRestartConfig{
		Component: "indexer",
		Reason:    "certificate renewed",
	}

	result, err := TriggerStatefulSetRollingRestart(ctx, client, "default", "test-sts", config)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Triggered {
		t.Error("Expected Triggered to be false for 0 replicas")
	}
}

func TestGetRestartConfigForCertType(t *testing.T) {
	tests := []struct {
		name               string
		certType           string
		wantIndexers       bool
		wantManagers       bool
		wantDashboard      bool
		wantAllowHotReload bool
	}{
		{
			name:               "CA cert - triggers all",
			certType:           constants.CertTypeCA,
			wantIndexers:       true,
			wantManagers:       true,
			wantDashboard:      true,
			wantAllowHotReload: false,
		},
		{
			name:               "Node cert - triggers indexers with hot reload",
			certType:           constants.CertTypeNode,
			wantIndexers:       true,
			wantManagers:       false,
			wantDashboard:      false,
			wantAllowHotReload: true,
		},
		{
			name:               "Filebeat cert - triggers managers",
			certType:           constants.CertTypeFilebeat,
			wantIndexers:       false,
			wantManagers:       true,
			wantDashboard:      false,
			wantAllowHotReload: false,
		},
		{
			name:               "Dashboard cert - triggers dashboard",
			certType:           constants.CertTypeDashboard,
			wantIndexers:       false,
			wantManagers:       false,
			wantDashboard:      true,
			wantAllowHotReload: false,
		},
		{
			name:               "Admin cert - triggers nothing",
			certType:           constants.CertTypeAdmin,
			wantIndexers:       false,
			wantManagers:       false,
			wantDashboard:      false,
			wantAllowHotReload: false,
		},
		{
			name:               "Unknown cert - triggers all (safe default)",
			certType:           "unknown",
			wantIndexers:       true,
			wantManagers:       true,
			wantDashboard:      true,
			wantAllowHotReload: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := GetRestartConfigForCertType(tt.certType)

			if config.TriggerIndexers != tt.wantIndexers {
				t.Errorf("TriggerIndexers = %v, want %v", config.TriggerIndexers, tt.wantIndexers)
			}
			if config.TriggerManagers != tt.wantManagers {
				t.Errorf("TriggerManagers = %v, want %v", config.TriggerManagers, tt.wantManagers)
			}
			if config.TriggerDashboard != tt.wantDashboard {
				t.Errorf("TriggerDashboard = %v, want %v", config.TriggerDashboard, tt.wantDashboard)
			}
			if config.AllowHotReload != tt.wantAllowHotReload {
				t.Errorf("AllowHotReload = %v, want %v", config.AllowHotReload, tt.wantAllowHotReload)
			}
			if config.CertType != tt.certType {
				t.Errorf("CertType = %s, want %s", config.CertType, tt.certType)
			}
		})
	}
}

func TestRollingRestartConfig_Fields(t *testing.T) {
	config := RollingRestartConfig{
		Component:    "indexer",
		CertType:     "node-cert",
		RestartOrder: RestartOrderSequential,
		WaitForReady: true,
		Reason:       "test reason",
	}

	if config.Component != "indexer" {
		t.Errorf("Expected component 'indexer', got %s", config.Component)
	}

	if config.CertType != "node-cert" {
		t.Errorf("Expected cert type 'node-cert', got %s", config.CertType)
	}

	if config.RestartOrder != RestartOrderSequential {
		t.Errorf("Expected restart order 'sequential', got %s", config.RestartOrder)
	}

	if !config.WaitForReady {
		t.Error("Expected WaitForReady to be true")
	}
}

func TestRestartOrderStrategy_Constants(t *testing.T) {
	if RestartOrderSequential != "sequential" {
		t.Errorf("RestartOrderSequential = %s, want 'sequential'", RestartOrderSequential)
	}

	if RestartOrderParallel != "parallel" {
		t.Errorf("RestartOrderParallel = %s, want 'parallel'", RestartOrderParallel)
	}

	if RestartOrderWorkersFirst != "workers-first" {
		t.Errorf("RestartOrderWorkersFirst = %s, want 'workers-first'", RestartOrderWorkersFirst)
	}
}

func TestTriggerFilebeatCertificateRenewalRestart(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	replicas := int32(1)
	masterSts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-manager-master",
			Namespace: "default",
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
		},
	}

	workerReplicas := int32(2)
	workerSts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-manager-workers",
			Namespace: "default",
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &workerReplicas,
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(masterSts, workerSts).
		Build()

	ctx := context.Background()
	result, err := TriggerFilebeatCertificateRenewalRestart(ctx, client, "default", "test-cluster")

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !result.MasterRestarted {
		t.Error("Expected master to be restarted")
	}

	if !result.WorkersRestarted {
		t.Error("Expected workers to be restarted")
	}

	if result.TotalRestarted != 2 {
		t.Errorf("Expected 2 components restarted, got %d", result.TotalRestarted)
	}
}

func TestTriggerAdminCertificateRenewalRestart(t *testing.T) {
	ctx := context.Background()
	result, err := TriggerAdminCertificateRenewalRestart(ctx, "test-cluster", "default")

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !result.NoRestartRequired {
		t.Error("Expected NoRestartRequired to be true for admin certs")
	}

	if !result.Updated {
		t.Error("Expected Updated to be true")
	}

	if result.Message == "" {
		t.Error("Expected Message to be set")
	}
}

func TestTriggerDashboardCertificateRenewalRestart(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	replicas := int32(1)
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
	result, err := TriggerDashboardCertificateRenewalRestart(ctx, client, "default", "test-cluster")

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !result.Restarted {
		t.Error("Expected dashboard to be restarted")
	}
}

func TestFilebeatCertRenewalResult_Fields(t *testing.T) {
	result := FilebeatCertRenewalResult{
		MasterRestarted:  true,
		WorkersRestarted: true,
		TotalRestarted:   2,
		Error:            nil,
	}

	if !result.MasterRestarted {
		t.Error("Expected MasterRestarted to be true")
	}

	if !result.WorkersRestarted {
		t.Error("Expected WorkersRestarted to be true")
	}

	if result.TotalRestarted != 2 {
		t.Errorf("Expected TotalRestarted 2, got %d", result.TotalRestarted)
	}
}

func TestAdminCertRenewalResult_Fields(t *testing.T) {
	result := AdminCertRenewalResult{
		Updated:           true,
		NoRestartRequired: true,
		Message:           "test message",
	}

	if !result.Updated {
		t.Error("Expected Updated to be true")
	}

	if !result.NoRestartRequired {
		t.Error("Expected NoRestartRequired to be true")
	}

	if result.Message != "test message" {
		t.Errorf("Expected Message 'test message', got %s", result.Message)
	}
}

func TestDashboardCertRenewalResult_Fields(t *testing.T) {
	result := DashboardCertRenewalResult{
		Restarted: true,
		Error:     nil,
	}

	if !result.Restarted {
		t.Error("Expected Restarted to be true")
	}

	if result.Error != nil {
		t.Error("Expected Error to be nil")
	}
}
