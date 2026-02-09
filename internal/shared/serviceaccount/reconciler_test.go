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

package serviceaccount

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

func TestResolveServiceAccountName(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *wazuhv1.ServiceAccountConfig
		clusterName string
		component   string
		want        string
	}{
		{
			name:        "nil config returns empty",
			cfg:         nil,
			clusterName: "my-cluster",
			component:   "indexer",
			want:        "",
		},
		{
			name:        "explicit name is returned",
			cfg:         &wazuhv1.ServiceAccountConfig{Name: "my-sa"},
			clusterName: "my-cluster",
			component:   "indexer",
			want:        "my-sa",
		},
		{
			name:        "explicit name with create=true still uses explicit name",
			cfg:         &wazuhv1.ServiceAccountConfig{Create: true, Name: "custom-sa"},
			clusterName: "my-cluster",
			component:   "indexer",
			want:        "custom-sa",
		},
		{
			name:        "create=true without name auto-generates",
			cfg:         &wazuhv1.ServiceAccountConfig{Create: true},
			clusterName: "my-cluster",
			component:   "indexer",
			want:        "my-cluster-indexer",
		},
		{
			name:        "create=false without name returns empty",
			cfg:         &wazuhv1.ServiceAccountConfig{Create: false},
			clusterName: "my-cluster",
			component:   "indexer",
			want:        "",
		},
		{
			name:        "create=false with name returns the name",
			cfg:         &wazuhv1.ServiceAccountConfig{Create: false, Name: "external-sa"},
			clusterName: "my-cluster",
			component:   "dashboard",
			want:        "external-sa",
		},
		{
			name:        "different components generate different names",
			cfg:         &wazuhv1.ServiceAccountConfig{Create: true},
			clusterName: "prod",
			component:   "master",
			want:        "prod-master",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveServiceAccountName(tt.cfg, tt.clusterName, tt.component)
			if got != tt.want {
				t.Errorf("ResolveServiceAccountName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMapsEqual(t *testing.T) {
	tests := []struct {
		name string
		a    map[string]string
		b    map[string]string
		want bool
	}{
		{
			name: "both nil",
			a:    nil,
			b:    nil,
			want: true,
		},
		{
			name: "both empty",
			a:    map[string]string{},
			b:    map[string]string{},
			want: true,
		},
		{
			name: "nil and empty are equal",
			a:    nil,
			b:    map[string]string{},
			want: true,
		},
		{
			name: "same keys and values",
			a:    map[string]string{"k1": "v1", "k2": "v2"},
			b:    map[string]string{"k1": "v1", "k2": "v2"},
			want: true,
		},
		{
			name: "different values",
			a:    map[string]string{"k1": "v1"},
			b:    map[string]string{"k1": "v2"},
			want: false,
		},
		{
			name: "different keys",
			a:    map[string]string{"k1": "v1"},
			b:    map[string]string{"k2": "v1"},
			want: false,
		},
		{
			name: "different lengths",
			a:    map[string]string{"k1": "v1"},
			b:    map[string]string{"k1": "v1", "k2": "v2"},
			want: false,
		},
		{
			name: "one nil one with data",
			a:    nil,
			b:    map[string]string{"k1": "v1"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapsEqual(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("mapsEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReconcileServiceAccount(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = wazuhv1.AddToScheme(scheme)

	owner := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-cluster",
			Namespace: "wazuh",
			UID:       types.UID("test-uid"),
		},
	}

	t.Run("nil config returns empty name", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		name, err := ReconcileServiceAccount(context.Background(), c, scheme, owner, nil, "my-cluster", "wazuh", "indexer")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if name != "" {
			t.Errorf("expected empty name, got %q", name)
		}
	})

	t.Run("create=false returns name without creating SA", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		cfg := &wazuhv1.ServiceAccountConfig{Name: "external-sa"}
		name, err := ReconcileServiceAccount(context.Background(), c, scheme, owner, cfg, "my-cluster", "wazuh", "indexer")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if name != "external-sa" {
			t.Errorf("expected 'external-sa', got %q", name)
		}
		// Verify SA was NOT created
		sa := &corev1.ServiceAccount{}
		err = c.Get(context.Background(), types.NamespacedName{Name: "external-sa", Namespace: "wazuh"}, sa)
		if err == nil {
			t.Error("expected SA to not exist, but it was found")
		}
	})

	t.Run("create=true creates SA with annotations and labels", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		cfg := &wazuhv1.ServiceAccountConfig{
			Create: true,
			Annotations: map[string]string{
				"iam.gke.io/gcp-service-account": "test@project.iam.gserviceaccount.com",
			},
			Labels: map[string]string{
				"azure.workload.identity/use": "true",
			},
		}
		name, err := ReconcileServiceAccount(context.Background(), c, scheme, owner, cfg, "my-cluster", "wazuh", "indexer")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if name != "my-cluster-indexer" {
			t.Errorf("expected 'my-cluster-indexer', got %q", name)
		}
		// Verify SA was created with correct annotations and labels
		sa := &corev1.ServiceAccount{}
		err = c.Get(context.Background(), types.NamespacedName{Name: "my-cluster-indexer", Namespace: "wazuh"}, sa)
		if err != nil {
			t.Fatalf("expected SA to exist: %v", err)
		}
		if sa.Annotations["iam.gke.io/gcp-service-account"] != "test@project.iam.gserviceaccount.com" {
			t.Errorf("annotation mismatch: %v", sa.Annotations)
		}
		if sa.Labels["azure.workload.identity/use"] != "true" {
			t.Errorf("label mismatch: %v", sa.Labels)
		}
	})

	t.Run("create=true updates existing SA annotations", func(t *testing.T) {
		existingSA := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-cluster-dashboard",
				Namespace: "wazuh",
				Annotations: map[string]string{
					"old-annotation": "old-value",
				},
			},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingSA).Build()
		cfg := &wazuhv1.ServiceAccountConfig{
			Create: true,
			Annotations: map[string]string{
				"eks.amazonaws.com/role-arn": "arn:aws:iam::role/new-role",
			},
		}
		name, err := ReconcileServiceAccount(context.Background(), c, scheme, owner, cfg, "my-cluster", "wazuh", "dashboard")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if name != "my-cluster-dashboard" {
			t.Errorf("expected 'my-cluster-dashboard', got %q", name)
		}
		// Verify SA was updated with new annotations
		sa := &corev1.ServiceAccount{}
		err = c.Get(context.Background(), types.NamespacedName{Name: "my-cluster-dashboard", Namespace: "wazuh"}, sa)
		if err != nil {
			t.Fatalf("expected SA to exist: %v", err)
		}
		if sa.Annotations["eks.amazonaws.com/role-arn"] != "arn:aws:iam::role/new-role" {
			t.Errorf("annotation not updated: %v", sa.Annotations)
		}
		// Old annotation should be gone (replaced, not merged)
		if _, ok := sa.Annotations["old-annotation"]; ok {
			t.Error("old annotation should have been removed")
		}
	})

	t.Run("create=true with explicit name uses it", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		cfg := &wazuhv1.ServiceAccountConfig{
			Create: true,
			Name:   "custom-name",
		}
		name, err := ReconcileServiceAccount(context.Background(), c, scheme, owner, cfg, "my-cluster", "wazuh", "worker")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if name != "custom-name" {
			t.Errorf("expected 'custom-name', got %q", name)
		}
		sa := &corev1.ServiceAccount{}
		err = c.Get(context.Background(), types.NamespacedName{Name: "custom-name", Namespace: "wazuh"}, sa)
		if err != nil {
			t.Fatalf("expected SA to exist: %v", err)
		}
	})

	t.Run("existing SA with same annotations is not updated", func(t *testing.T) {
		existingSA := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-cluster-master",
				Namespace: "wazuh",
				Annotations: map[string]string{
					"iam.gke.io/gcp-service-account": "same@project.iam.gserviceaccount.com",
				},
			},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingSA).Build()
		cfg := &wazuhv1.ServiceAccountConfig{
			Create: true,
			Annotations: map[string]string{
				"iam.gke.io/gcp-service-account": "same@project.iam.gserviceaccount.com",
			},
		}
		name, err := ReconcileServiceAccount(context.Background(), c, scheme, owner, cfg, "my-cluster", "wazuh", "master")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if name != "my-cluster-master" {
			t.Errorf("expected 'my-cluster-master', got %q", name)
		}
	})
}
