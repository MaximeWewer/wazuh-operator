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
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

func init() {
	// Initialize DNS for tests that use PodFQDN via HotReloader
	_ = dns.InitializeWithDomain("cluster.local")
}

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

func TestHotReloadWithFallbackResult_Fields(t *testing.T) {
	result := HotReloadWithFallbackResult{
		HotReloadResult: &HotReloadResult{
			Supported:       true,
			RequiresAPICall: true,
			TotalPods:       3,
			SuccessfulPods:  1,
		},
		FallbackTriggered: true,
		FallbackReason:    "hot reload partially failed: 1/3 pods succeeded",
		RollingRestartResult: &RollingRestartResult{
			Triggered: true,
			Component: "indexer",
		},
		FinalSuccess: true,
		Strategy:     "rolling-restart",
	}

	if !result.FallbackTriggered {
		t.Error("Expected FallbackTriggered to be true")
	}

	if result.Strategy != "rolling-restart" {
		t.Errorf("Expected Strategy 'rolling-restart', got %s", result.Strategy)
	}

	if !result.FinalSuccess {
		t.Error("Expected FinalSuccess to be true")
	}

	if result.FallbackReason == "" {
		t.Error("Expected FallbackReason to be set")
	}
}

func TestTriggerCertificateHotReloadWithFallback_NotSupported(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.7.0", // Version that doesn't support hot reload
			TLS: &wazuhv1.TLSConfig{
				Enabled: boolPtr(true),
				HotReload: &wazuhv1.HotReloadConfig{
					Enabled: true,
				},
			},
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := record.NewFakeRecorder(10)

	reconciler := NewCertificateReconciler(client, scheme).
		WithEventRecorder(recorder)

	ctx := context.Background()
	result := reconciler.TriggerCertificateHotReloadWithFallback(ctx, cluster, constants.CertTypeNode)

	// Hot reload not supported, should trigger fallback
	if result.HotReloadResult == nil {
		t.Fatal("Expected HotReloadResult to be set")
	}

	if result.HotReloadResult.Supported {
		t.Error("Expected hot reload to not be supported for version 4.7.0")
	}

	// Fallback should have been considered
	if result.FallbackReason == "" {
		t.Error("Expected FallbackReason to be set when hot reload not supported")
	}
}

func TestTriggerCertificateHotReloadWithFallback_AutomaticSuccess(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.14.0", // Version with automatic hot reload
			TLS: &wazuhv1.TLSConfig{
				Enabled: boolPtr(true),
				HotReload: &wazuhv1.HotReloadConfig{
					Enabled: true,
				},
			},
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := record.NewFakeRecorder(10)

	reconciler := NewCertificateReconciler(client, scheme).
		WithEventRecorder(recorder)

	ctx := context.Background()
	result := reconciler.TriggerCertificateHotReloadWithFallback(ctx, cluster, constants.CertTypeNode)

	// Hot reload should succeed (automatic mode)
	if result.HotReloadResult == nil {
		t.Fatal("Expected HotReloadResult to be set")
	}

	if !result.HotReloadResult.Supported {
		t.Error("Expected hot reload to be supported for version 4.14.0")
	}

	if result.FallbackTriggered {
		t.Error("Expected no fallback for automatic hot reload success")
	}

	if result.Strategy != "hot-reload" {
		t.Errorf("Expected Strategy 'hot-reload', got %s", result.Strategy)
	}

	if !result.FinalSuccess {
		t.Error("Expected FinalSuccess to be true")
	}
}
