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
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

func TestRoleMappingReconciler_buildRoleMapping(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := NewRoleMappingReconciler(client, scheme)

	tests := []struct {
		name                string
		mapping             *wazuhv1.OpenSearchRoleMapping
		wantDesc            string
		wantBackendRolesLen int
		wantHostsLen        int
		wantUsersLen        int
		wantAndBRLen        int
	}{
		{
			name: "description only",
			mapping: &wazuhv1.OpenSearchRoleMapping{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-mapping",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchRoleMappingSpec{
					Description: "Test mapping",
				},
			},
			wantDesc:            "Test mapping",
			wantBackendRolesLen: 0,
			wantHostsLen:        0,
			wantUsersLen:        0,
			wantAndBRLen:        0,
		},
		{
			name: "with backend roles",
			mapping: &wazuhv1.OpenSearchRoleMapping{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "backend-mapping",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchRoleMappingSpec{
					Description:  "Backend role mapping",
					BackendRoles: []string{"admin", "dev"},
				},
			},
			wantDesc:            "Backend role mapping",
			wantBackendRolesLen: 2,
			wantHostsLen:        0,
			wantUsersLen:        0,
			wantAndBRLen:        0,
		},
		{
			name: "with hosts",
			mapping: &wazuhv1.OpenSearchRoleMapping{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "host-mapping",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchRoleMappingSpec{
					Hosts: []string{"host1.example.com", "host2.example.com"},
				},
			},
			wantHostsLen: 2,
		},
		{
			name: "with users",
			mapping: &wazuhv1.OpenSearchRoleMapping{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "user-mapping",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchRoleMappingSpec{
					Users: []string{"user1", "user2", "user3"},
				},
			},
			wantUsersLen: 3,
		},
		{
			name: "with and_backend_roles",
			mapping: &wazuhv1.OpenSearchRoleMapping{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "and-mapping",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchRoleMappingSpec{
					AndBackendRoles: []string{"role1"},
				},
			},
			wantAndBRLen: 1,
		},
		{
			name: "full mapping with all fields",
			mapping: &wazuhv1.OpenSearchRoleMapping{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "full-mapping",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchRoleMappingSpec{
					Description:     "Full mapping",
					BackendRoles:    []string{"admin"},
					Hosts:           []string{"*.example.com"},
					Users:           []string{"admin-user"},
					AndBackendRoles: []string{"security"},
				},
			},
			wantDesc:            "Full mapping",
			wantBackendRolesLen: 1,
			wantHostsLen:        1,
			wantUsersLen:        1,
			wantAndBRLen:        1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.buildRoleMapping(tt.mapping)
			if got.Description != tt.wantDesc {
				t.Errorf("buildRoleMapping() Description = %v, want %v", got.Description, tt.wantDesc)
			}
			if len(got.BackendRoles) != tt.wantBackendRolesLen {
				t.Errorf("buildRoleMapping() BackendRoles length = %v, want %v", len(got.BackendRoles), tt.wantBackendRolesLen)
			}
			if len(got.Hosts) != tt.wantHostsLen {
				t.Errorf("buildRoleMapping() Hosts length = %v, want %v", len(got.Hosts), tt.wantHostsLen)
			}
			if len(got.Users) != tt.wantUsersLen {
				t.Errorf("buildRoleMapping() Users length = %v, want %v", len(got.Users), tt.wantUsersLen)
			}
			if len(got.AndBackendRoles) != tt.wantAndBRLen {
				t.Errorf("buildRoleMapping() AndBackendRoles length = %v, want %v", len(got.AndBackendRoles), tt.wantAndBRLen)
			}
		})
	}
}

func TestRoleMappingReconciler_buildRoleMapping_Values(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := NewRoleMappingReconciler(client, scheme)

	mapping := &wazuhv1.OpenSearchRoleMapping{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "detailed-mapping",
			Namespace: "default",
		},
		Spec: wazuhv1.OpenSearchRoleMappingSpec{
			Description:     "Detailed test",
			BackendRoles:    []string{"admin", "dev"},
			Hosts:           []string{"host1", "host2"},
			Users:           []string{"user1"},
			AndBackendRoles: []string{"security", "audit"},
		},
	}

	got := r.buildRoleMapping(mapping)

	// Verify exact values
	expectedBackendRoles := map[string]bool{"admin": true, "dev": true}
	for _, role := range got.BackendRoles {
		if !expectedBackendRoles[role] {
			t.Errorf("Unexpected backend role: %s", role)
		}
	}

	expectedHosts := map[string]bool{"host1": true, "host2": true}
	for _, host := range got.Hosts {
		if !expectedHosts[host] {
			t.Errorf("Unexpected host: %s", host)
		}
	}

	if got.Users[0] != "user1" {
		t.Errorf("Expected user 'user1', got %s", got.Users[0])
	}

	expectedAndBR := map[string]bool{"security": true, "audit": true}
	for _, role := range got.AndBackendRoles {
		if !expectedAndBR[role] {
			t.Errorf("Unexpected and_backend_role: %s", role)
		}
	}
}
