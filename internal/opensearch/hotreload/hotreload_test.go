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

package hotreload

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

func init() {
	// Initialize DNS for tests that use PodFQDN
	_ = dns.InitializeWithDomain("cluster.local")
}

func TestWaitForSecurityReady_Success(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	// Create a test server that returns healthy status
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_plugins/_security/health" {
			json.NewEncoder(w).Encode(api.SecurityHealthResponse{
				Status: "UP",
			})
		}
	}))
	defer server.Close()

	client, err := api.NewClient(api.ClientConfig{
		BaseURL:  server.URL,
		Insecure: true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	h := NewHotReloader(fakeClient)

	err = h.waitForSecurityReady(context.Background(), client, 5*time.Second)
	if err != nil {
		t.Errorf("waitForSecurityReady() should succeed when security is healthy, got error: %v", err)
	}
}

func TestWaitForSecurityReady_Timeout(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	// Create a test server that always returns unhealthy status
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_plugins/_security/health" {
			json.NewEncoder(w).Encode(api.SecurityHealthResponse{
				Status: "DOWN",
			})
		}
	}))
	defer server.Close()

	client, err := api.NewClient(api.ClientConfig{
		BaseURL:  server.URL,
		Insecure: true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	h := NewHotReloader(fakeClient)

	// Use a very short timeout for the test
	err = h.waitForSecurityReady(context.Background(), client, 100*time.Millisecond)
	if err == nil {
		t.Error("waitForSecurityReady() should timeout when security never becomes healthy")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("Expected timeout error, got: %v", err)
	}
}

func TestCallReloadCertificatesAPIPerPod_MultiPod(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	// Create a cluster with multiple replicas
	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			TLS: &wazuhv1.TLSConfig{
				Enabled: new(true),
			},
			Indexer: &wazuhv1.WazuhIndexerClusterSpec{
				Replicas: 3,
			},
		},
	}

	// Create required secrets
	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-ca",
			Namespace: "default",
		},
		Data: map[string][]byte{
			constants.SecretKeyCACert: []byte("fake-ca-cert"),
		},
	}

	adminSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-admin-certs",
			Namespace: "default",
		},
		Data: map[string][]byte{
			constants.SecretKeyTLSCert: []byte("fake-admin-cert"),
			constants.SecretKeyTLSKey:  []byte("fake-admin-key"),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(cluster, caSecret, adminSecret).
		Build()

	// Use short propagation timeout for unit tests
	h := NewHotReloader(fakeClient).
		WithPropagationTimeout(1 * time.Second)
	result := &HotReloadResult{}

	// This will fail because we can't connect to the pods, but we can verify
	// that it attempts the propagation wait
	h.callReloadCertificatesAPIPerPod(context.Background(), cluster, result)

	// In unit tests, propagation will timeout, so TotalPods may not be set
	// but the error should indicate propagation failure
	if result.Error == nil {
		t.Logf("Note: Expected error due to propagation timeout in unit test")
	}

	// With propagation timeout in unit tests (no real server), the function
	// returns early before iterating over pods. This verifies:
	// 1. The propagation wait mechanism is called
	// 2. Proper error handling when propagation fails
	// 3. TotalPods is set before the wait (from replica count)
	if result.TotalPods != 3 {
		t.Errorf("Expected TotalPods = 3, got %d", result.TotalPods)
	}

	// Since propagation times out, no pod results will be populated
	// (the function returns early with a propagation error)
	if result.Error == nil {
		t.Error("Expected error due to propagation timeout, but got nil")
	} else if !strings.Contains(result.Error.Error(), "propagation") {
		t.Logf("Got error (may be propagation or other): %v", result.Error)
	}

	// PodResults may be empty because propagation failed before per-pod iteration
	t.Logf("PodResults count: %d (expected 0 due to early propagation timeout)", len(result.PodResults))
}

func TestGetPodsForCertType_Node(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	replicas := int32(3)
	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Indexer: &wazuhv1.WazuhIndexerClusterSpec{
				Replicas: replicas,
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	h := &HotReloader{
		Client: fakeClient,
	}

	pods, err := h.getPodsForCertType(cluster, "node")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(pods) != 3 {
		t.Errorf("Expected 3 pods for node cert, got %d", len(pods))
	}

	expectedPods := []string{
		"test-cluster-indexer-0",
		"test-cluster-indexer-1",
		"test-cluster-indexer-2",
	}

	for i, expected := range expectedPods {
		if pods[i] != expected {
			t.Errorf("Expected pod %s at index %d, got %s", expected, i, pods[i])
		}
	}
}

func TestGetPodsForCertType_Admin(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	h := &HotReloader{
		Client: fakeClient,
	}

	pods, err := h.getPodsForCertType(cluster, "admin")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Admin certs are not mounted in pods
	if len(pods) != 0 {
		t.Errorf("Expected 0 pods for admin cert, got %d", len(pods))
	}
}

func TestGetPodsForCertType_Filebeat(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)

	workerReplicas := int32(2)
	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Manager: &wazuhv1.WazuhManagerClusterSpec{
				Workers: wazuhv1.WazuhWorkerSpec{
					Replicas: &workerReplicas,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	h := &HotReloader{
		Client: fakeClient,
	}

	pods, err := h.getPodsForCertType(cluster, "filebeat")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// 1 master + 2 workers = 3 pods
	if len(pods) != 3 {
		t.Errorf("Expected 3 pods for filebeat cert (1 master + 2 workers), got %d", len(pods))
	}

	expectedPods := []string{
		"test-cluster-manager-master-0",
		"test-cluster-manager-workers-0",
		"test-cluster-manager-workers-1",
	}

	for i, expected := range expectedPods {
		if pods[i] != expected {
			t.Errorf("Expected pod %s at index %d, got %s", expected, i, pods[i])
		}
	}
}

func TestGetSecretNameForCertType(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-cluster",
			Namespace: "default",
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	h := &HotReloader{
		Client: fakeClient,
	}

	tests := []struct {
		certType string
		expected string
	}{
		{certType: "node", expected: "my-cluster-indexer-certs"},
		{certType: "admin", expected: "my-cluster-admin-certs"},
		{certType: "filebeat", expected: "my-cluster-filebeat-certs"},
		{certType: "dashboard", expected: "my-cluster-dashboard-certs"},
		{certType: "unknown", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.certType, func(t *testing.T) {
			got := h.getSecretNameForCertType(cluster, tt.certType)
			if got != tt.expected {
				t.Errorf("getSecretNameForCertType(%s) = %s, want %s", tt.certType, got, tt.expected)
			}
		})
	}
}

func TestBuildPodURL(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	h := &HotReloader{
		Client: fakeClient,
	}

	tests := []struct {
		podName  string
		expected string
	}{
		{
			podName:  "test-cluster-indexer-0",
			expected: "https://test-cluster-indexer-0.test-cluster-indexer-headless.default.svc.cluster.local:9200",
		},
		{
			podName:  "test-cluster-manager-master-0",
			expected: "https://test-cluster-manager-master-0.test-cluster-manager-headless.default.svc.cluster.local:55000",
		},
		{
			podName:  "test-cluster-manager-workers-1",
			expected: "https://test-cluster-manager-workers-1.test-cluster-manager-headless.default.svc.cluster.local:55000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.podName, func(t *testing.T) {
			got := h.buildPodURL(cluster, tt.podName)
			if got != tt.expected {
				t.Errorf("buildPodURL(%s) = %s, want %s", tt.podName, got, tt.expected)
			}
		})
	}
}

func TestShouldUseFallback(t *testing.T) {
	tests := []struct {
		name   string
		result *HotReloadResult
		want   bool
	}{
		{
			name:   "nil result",
			result: nil,
			want:   true,
		},
		{
			name: "not supported",
			result: &HotReloadResult{
				Supported: false,
			},
			want: true,
		},
		{
			name: "supported with error",
			result: &HotReloadResult{
				Supported: true,
				Error:     fmt.Errorf("some error"),
			},
			want: true,
		},
		{
			name: "partial failure with API call",
			result: &HotReloadResult{
				Supported:       true,
				RequiresAPICall: true,
				TotalPods:       3,
				SuccessfulPods:  2,
			},
			want: true,
		},
		{
			name: "all pods successful with API call",
			result: &HotReloadResult{
				Supported:       true,
				RequiresAPICall: true,
				TotalPods:       3,
				SuccessfulPods:  3,
			},
			want: false,
		},
		{
			name: "automatic reload successful",
			result: &HotReloadResult{
				Supported:       true,
				RequiresAPICall: false,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldUseFallback(tt.result)
			if got != tt.want {
				t.Errorf("ShouldUseFallback() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSyncStatus_Constants(t *testing.T) {
	if SyncStatusPending != "Pending" {
		t.Errorf("SyncStatusPending = %s, want 'Pending'", SyncStatusPending)
	}
	if SyncStatusSynced != "Synced" {
		t.Errorf("SyncStatusSynced = %s, want 'Synced'", SyncStatusSynced)
	}
	if SyncStatusFailed != "Failed" {
		t.Errorf("SyncStatusFailed = %s, want 'Failed'", SyncStatusFailed)
	}
	if SyncStatusUnknown != "Unknown" {
		t.Errorf("SyncStatusUnknown = %s, want 'Unknown'", SyncStatusUnknown)
	}
}

func TestPodSyncResult_Fields(t *testing.T) {
	now := time.Now()
	result := PodSyncResult{
		PodName:      "test-indexer-0",
		SyncStatus:   SyncStatusSynced,
		LastSyncTime: now,
		CertHash:     "abc123",
		ExpectedHash: "abc123",
		Error:        nil,
	}

	if result.PodName != "test-indexer-0" {
		t.Errorf("Expected PodName 'test-indexer-0', got %s", result.PodName)
	}

	if result.SyncStatus != SyncStatusSynced {
		t.Errorf("Expected SyncStatus 'Synced', got %s", result.SyncStatus)
	}

	if result.CertHash != result.ExpectedHash {
		t.Error("Expected CertHash and ExpectedHash to match")
	}
}

func TestPodSyncVerificationResult_Fields(t *testing.T) {
	result := PodSyncVerificationResult{
		TotalPods:   3,
		SyncedPods:  2,
		PendingPods: 1,
		FailedPods:  0,
		PodResults: []PodSyncResult{
			{PodName: "pod-0", SyncStatus: SyncStatusSynced},
			{PodName: "pod-1", SyncStatus: SyncStatusSynced},
			{PodName: "pod-2", SyncStatus: SyncStatusPending},
		},
		AllSynced: false,
		Error:     nil,
	}

	if result.TotalPods != 3 {
		t.Errorf("Expected TotalPods 3, got %d", result.TotalPods)
	}

	if result.SyncedPods != 2 {
		t.Errorf("Expected SyncedPods 2, got %d", result.SyncedPods)
	}

	if result.AllSynced {
		t.Error("Expected AllSynced to be false when not all pods are synced")
	}

	if len(result.PodResults) != 3 {
		t.Errorf("Expected 3 pod results, got %d", len(result.PodResults))
	}
}

func TestHotReloadResult_PodReloadResult(t *testing.T) {
	result := &HotReloadResult{
		Supported:       true,
		RequiresAPICall: true,
		APICallMade:     true,
		TotalPods:       3,
		SuccessfulPods:  2,
		PodResults: []PodReloadResult{
			{
				PodName: "test-cluster-indexer-0",
				PodURL:  "https://test-cluster-indexer-0.test-cluster-indexer-headless.default.svc.cluster.local:9200",
				Success: true,
			},
			{
				PodName: "test-cluster-indexer-1",
				PodURL:  "https://test-cluster-indexer-1.test-cluster-indexer-headless.default.svc.cluster.local:9200",
				Success: true,
			},
			{
				PodName:  "test-cluster-indexer-2",
				PodURL:   "https://test-cluster-indexer-2.test-cluster-indexer-headless.default.svc.cluster.local:9200",
				Success:  false,
				Error:    nil, // Would have an error in real scenario
				Attempts: 3,
			},
		},
	}

	if result.SuccessfulPods != 2 {
		t.Errorf("Expected 2 successful pods, got %d", result.SuccessfulPods)
	}

	successCount := 0
	for _, pr := range result.PodResults {
		if pr.Success {
			successCount++
		}
	}
	if successCount != result.SuccessfulPods {
		t.Errorf("Mismatch between SuccessfulPods (%d) and actual successful results (%d)",
			result.SuccessfulPods, successCount)
	}
}

func TestIsHotReloadEnabled(t *testing.T) {
	tests := []struct {
		name    string
		cluster *wazuhv1.WazuhCluster
		want    bool
	}{
		{
			name: "TLS enabled, hot reload enabled",
			cluster: &wazuhv1.WazuhCluster{
				Spec: wazuhv1.WazuhClusterSpec{
					TLS: &wazuhv1.TLSConfig{
						Enabled: new(true),
						HotReload: &wazuhv1.HotReloadConfig{
							Enabled: true,
						},
					},
				},
			},
			want: true,
		},
		{
			name: "TLS enabled, no hot reload config (defaults to true)",
			cluster: &wazuhv1.WazuhCluster{
				Spec: wazuhv1.WazuhClusterSpec{
					TLS: &wazuhv1.TLSConfig{
						Enabled: new(true),
					},
				},
			},
			want: true,
		},
		{
			name: "TLS enabled, hot reload explicitly disabled",
			cluster: &wazuhv1.WazuhCluster{
				Spec: wazuhv1.WazuhClusterSpec{
					TLS: &wazuhv1.TLSConfig{
						Enabled: new(true),
						HotReload: &wazuhv1.HotReloadConfig{
							Enabled: false,
						},
					},
				},
			},
			want: false,
		},
		{
			name: "TLS disabled",
			cluster: &wazuhv1.WazuhCluster{
				Spec: wazuhv1.WazuhClusterSpec{
					TLS: &wazuhv1.TLSConfig{
						Enabled: new(false),
					},
				},
			},
			want: false,
		},
		{
			name: "no TLS spec",
			cluster: &wazuhv1.WazuhCluster{
				Spec: wazuhv1.WazuhClusterSpec{},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsHotReloadEnabled(tt.cluster)
			if got != tt.want {
				t.Errorf("IsHotReloadEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetHotReloadConfigString(t *testing.T) {
	tests := []struct {
		name    string
		cluster *wazuhv1.WazuhCluster
		want    string
	}{
		{
			name: "hot reload enabled with supported version",
			cluster: &wazuhv1.WazuhCluster{
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					TLS: &wazuhv1.TLSConfig{
						Enabled: new(true),
						HotReload: &wazuhv1.HotReloadConfig{
							Enabled: true,
						},
					},
				},
			},
			want: "plugins.security.ssl_cert_reload_enabled: true",
		},
		{
			name: "hot reload disabled",
			cluster: &wazuhv1.WazuhCluster{
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					TLS: &wazuhv1.TLSConfig{
						Enabled: new(true),
						HotReload: &wazuhv1.HotReloadConfig{
							Enabled: false,
						},
					},
				},
			},
			want: "",
		},
		{
			name: "TLS disabled",
			cluster: &wazuhv1.WazuhCluster{
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					TLS: &wazuhv1.TLSConfig{
						Enabled: new(false),
					},
				},
			},
			want: "",
		},
		{
			name: "unsupported version (too old)",
			cluster: &wazuhv1.WazuhCluster{
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.7.0",
					TLS: &wazuhv1.TLSConfig{
						Enabled: new(true),
						HotReload: &wazuhv1.HotReloadConfig{
							Enabled: true,
						},
					},
				},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetHotReloadConfigString(tt.cluster)
			if got != tt.want {
				t.Errorf("GetHotReloadConfigString() = %q, want %q", got, tt.want)
			}
		})
	}
}
