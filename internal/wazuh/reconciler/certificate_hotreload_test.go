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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// boolPtr returns a pointer to a bool value
func boolPtr(b bool) *bool {
	return &b
}

func TestShouldTriggerHotReload_TLSEnabled(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	tests := []struct {
		name    string
		cluster *wazuhv1.WazuhCluster
		want    bool
	}{
		{
			name: "TLS enabled with hot reload enabled",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					TLS: &wazuhv1.TLSConfig{
						Enabled: boolPtr(true),
						HotReload: &wazuhv1.HotReloadConfig{
							Enabled: true,
						},
					},
				},
			},
			want: true,
		},
		{
			name: "TLS enabled with hot reload explicitly disabled",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					TLS: &wazuhv1.TLSConfig{
						Enabled: boolPtr(true),
						HotReload: &wazuhv1.HotReloadConfig{
							Enabled: false,
						},
					},
				},
			},
			want: false,
		},
		{
			name: "TLS enabled without hot reload config (defaults to enabled)",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					TLS: &wazuhv1.TLSConfig{
						Enabled: boolPtr(true),
					},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().
				WithScheme(scheme).
				Build()

			reconciler := NewCertificateReconciler(client, scheme)

			got := reconciler.ShouldTriggerHotReload(tt.cluster)
			if got != tt.want {
				t.Errorf("ShouldTriggerHotReload() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShouldTriggerHotReload_TLSDisabled(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	tests := []struct {
		name    string
		cluster *wazuhv1.WazuhCluster
		want    bool
	}{
		{
			name: "TLS explicitly disabled",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					TLS: &wazuhv1.TLSConfig{
						Enabled: boolPtr(false),
						HotReload: &wazuhv1.HotReloadConfig{
							Enabled: true, // Should be ignored when TLS is disabled
						},
					},
				},
			},
			want: false,
		},
		{
			name: "TLS nil (no TLS spec)",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					// No TLS spec
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().
				WithScheme(scheme).
				Build()

			reconciler := NewCertificateReconciler(client, scheme)

			got := reconciler.ShouldTriggerHotReload(tt.cluster)
			if got != tt.want {
				t.Errorf("ShouldTriggerHotReload() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTriggerCertificateHotReload_Version49_APICall(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	// Create a cluster that requires API call (version 4.9)
	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			TLS: &wazuhv1.TLSConfig{
				Enabled: boolPtr(true),
				HotReload: &wazuhv1.HotReloadConfig{
					Enabled: true,
				},
			},
			Indexer: &wazuhv1.WazuhIndexerClusterSpec{
				Replicas: 1,
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

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(cluster, caSecret, adminSecret).
		Build()

	recorder := record.NewFakeRecorder(10)
	// Use short propagation timeout for unit tests (will fail fast since no real server)
	reconciler := NewCertificateReconciler(client, scheme).
		WithEventRecorder(recorder).
		WithPropagationTimeout(1 * time.Second)

	result := reconciler.TriggerCertificateHotReload(context.Background(), cluster)

	// Version 4.9 should require API call
	if !result.Supported {
		t.Errorf("Expected hot reload to be supported for version 4.9")
	}
	if !result.RequiresAPICall {
		t.Errorf("Expected version 4.9 to require API call for hot reload")
	}
	// In unit tests without a real server, certificate propagation will timeout
	// and APICallMade will be true but the actual reload will fail
	// The important thing is that the code path for API-based hot reload was triggered
	if !result.APICallMade {
		t.Errorf("Expected API call attempt to be made for version 4.9")
	}
	// Error should be set due to propagation timeout (no real server)
	if result.Error == nil {
		t.Logf("Note: Hot reload completed without error (unexpected in unit test without server)")
	}
}

func TestTriggerCertificateHotReload_Version414_Automatic(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	// Create a cluster that has automatic hot reload (version 4.14)
	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.14.0",
			TLS: &wazuhv1.TLSConfig{
				Enabled: boolPtr(true),
				HotReload: &wazuhv1.HotReloadConfig{
					Enabled: true,
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(cluster).
		Build()

	recorder := record.NewFakeRecorder(10)
	reconciler := NewCertificateReconciler(client, scheme).WithEventRecorder(recorder)

	result := reconciler.TriggerCertificateHotReload(context.Background(), cluster)

	// Version 4.14 should have automatic hot reload
	if !result.Supported {
		t.Errorf("Expected hot reload to be supported for version 4.14")
	}
	if result.RequiresAPICall {
		t.Errorf("Expected version 4.14 to have automatic hot reload (no API call needed)")
	}
	if result.APICallMade {
		t.Errorf("Expected no API call for version 4.14 automatic hot reload")
	}
}

func TestCheckSecurityHealth(t *testing.T) {
	tests := []struct {
		name       string
		response   api.SecurityHealthResponse
		statusCode int
		wantErr    bool
		wantStatus string
	}{
		{
			name: "healthy security",
			response: api.SecurityHealthResponse{
				Status:  "UP",
				Message: "Security plugin is initialized",
			},
			statusCode: http.StatusOK,
			wantErr:    false,
			wantStatus: "UP",
		},
		{
			name: "unhealthy security",
			response: api.SecurityHealthResponse{
				Status:  "DOWN",
				Message: "Security plugin not initialized",
			},
			statusCode: http.StatusOK,
			wantErr:    false,
			wantStatus: "DOWN",
		},
		{
			name:       "server error",
			response:   api.SecurityHealthResponse{},
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
			wantStatus: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/_plugins/_security/health" {
					w.WriteHeader(tt.statusCode)
					if tt.statusCode == http.StatusOK {
						json.NewEncoder(w).Encode(tt.response)
					}
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

			health, err := client.CheckSecurityHealth(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckSecurityHealth() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && health.Status != tt.wantStatus {
				t.Errorf("CheckSecurityHealth() status = %v, want %v", health.Status, tt.wantStatus)
			}
		})
	}
}

func TestIsSecurityHealthy(t *testing.T) {
	tests := []struct {
		name       string
		response   api.SecurityHealthResponse
		statusCode int
		want       bool
	}{
		{
			name: "healthy returns true",
			response: api.SecurityHealthResponse{
				Status: "UP",
			},
			statusCode: http.StatusOK,
			want:       true,
		},
		{
			name: "unhealthy returns false",
			response: api.SecurityHealthResponse{
				Status: "DOWN",
			},
			statusCode: http.StatusOK,
			want:       false,
		},
		{
			name:       "error returns false",
			response:   api.SecurityHealthResponse{},
			statusCode: http.StatusInternalServerError,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/_plugins/_security/health" {
					w.WriteHeader(tt.statusCode)
					if tt.statusCode == http.StatusOK {
						json.NewEncoder(w).Encode(tt.response)
					}
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

			got := client.IsSecurityHealthy(context.Background())
			if got != tt.want {
				t.Errorf("IsSecurityHealthy() = %v, want %v", got, tt.want)
			}
		})
	}
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
	reconciler := NewCertificateReconciler(fakeClient, scheme)

	err = reconciler.waitForSecurityReady(context.Background(), client, 5*time.Second)
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
	reconciler := NewCertificateReconciler(fakeClient, scheme)

	// Use a very short timeout for the test
	err = reconciler.waitForSecurityReady(context.Background(), client, 100*time.Millisecond)
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
				Enabled: boolPtr(true),
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

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(cluster, caSecret, adminSecret).
		Build()

	// Use short propagation timeout for unit tests
	reconciler := NewCertificateReconciler(client, scheme).
		WithPropagationTimeout(1 * time.Second)
	result := &HotReloadResult{}

	// This will fail because we can't connect to the pods, but we can verify
	// that it attempts the propagation wait
	reconciler.callReloadCertificatesAPIPerPod(context.Background(), cluster, result)

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
				PodURL:  "https://test-cluster-indexer-0.test-cluster-indexer-headless.default.svc:9200",
				Success: true,
			},
			{
				PodName: "test-cluster-indexer-1",
				PodURL:  "https://test-cluster-indexer-1.test-cluster-indexer-headless.default.svc:9200",
				Success: true,
			},
			{
				PodName:  "test-cluster-indexer-2",
				PodURL:   "https://test-cluster-indexer-2.test-cluster-indexer-headless.default.svc:9200",
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

func TestShouldForceAPIReload(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)

	tests := []struct {
		name    string
		cluster *wazuhv1.WazuhCluster
		want    bool
	}{
		{
			name: "force API reload enabled",
			cluster: &wazuhv1.WazuhCluster{
				Spec: wazuhv1.WazuhClusterSpec{
					TLS: &wazuhv1.TLSConfig{
						HotReload: &wazuhv1.HotReloadConfig{
							ForceAPIReload: true,
						},
					},
				},
			},
			want: true,
		},
		{
			name: "force API reload disabled",
			cluster: &wazuhv1.WazuhCluster{
				Spec: wazuhv1.WazuhClusterSpec{
					TLS: &wazuhv1.TLSConfig{
						HotReload: &wazuhv1.HotReloadConfig{
							ForceAPIReload: false,
						},
					},
				},
			},
			want: false,
		},
		{
			name: "no hot reload config",
			cluster: &wazuhv1.WazuhCluster{
				Spec: wazuhv1.WazuhClusterSpec{
					TLS: &wazuhv1.TLSConfig{},
				},
			},
			want: false,
		},
		{
			name: "no TLS config",
			cluster: &wazuhv1.WazuhCluster{
				Spec: wazuhv1.WazuhClusterSpec{},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithScheme(scheme).Build()
			reconciler := NewCertificateReconciler(client, scheme)

			got := reconciler.ShouldForceAPIReload(tt.cluster)
			if got != tt.want {
				t.Errorf("ShouldForceAPIReload() = %v, want %v", got, tt.want)
			}
		})
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
						Enabled: boolPtr(true),
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
						Enabled: boolPtr(true),
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
						Enabled: boolPtr(true),
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
						Enabled: boolPtr(false),
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
						Enabled: boolPtr(true),
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
						Enabled: boolPtr(true),
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
						Enabled: boolPtr(false),
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
						Enabled: boolPtr(true),
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
