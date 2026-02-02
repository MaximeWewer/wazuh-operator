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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

func TestRoleReconciler_buildRole(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := record.NewFakeRecorder(10)
	r := NewRoleReconciler(client, scheme, recorder)

	tests := []struct {
		name           string
		role           *wazuhv1.OpenSearchRole
		wantDesc       string
		wantClusterLen int
		wantIndexLen   int
		wantTenantLen  int
	}{
		{
			name: "role with description only",
			role: &wazuhv1.OpenSearchRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchRoleSpec{
					Description: "Test role description",
				},
			},
			wantDesc:       "Test role description",
			wantClusterLen: 0,
			wantIndexLen:   0,
			wantTenantLen:  0,
		},
		{
			name: "role with cluster permissions",
			role: &wazuhv1.OpenSearchRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cluster-admin",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchRoleSpec{
					Description:        "Cluster admin role",
					ClusterPermissions: []string{"cluster:admin/all", "indices:admin/all"},
				},
			},
			wantDesc:       "Cluster admin role",
			wantClusterLen: 2,
			wantIndexLen:   0,
			wantTenantLen:  0,
		},
		{
			name: "role with index permissions",
			role: &wazuhv1.OpenSearchRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "logs-reader",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchRoleSpec{
					Description: "Logs reader role",
					IndexPermissions: []wazuhv1.IndexPermission{
						{
							IndexPatterns:  []string{"logs-*"},
							AllowedActions: []string{"read"},
						},
						{
							IndexPatterns:  []string{"metrics-*"},
							AllowedActions: []string{"read", "search"},
						},
					},
				},
			},
			wantDesc:       "Logs reader role",
			wantClusterLen: 0,
			wantIndexLen:   2,
			wantTenantLen:  0,
		},
		{
			name: "role with tenant permissions",
			role: &wazuhv1.OpenSearchRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenant-user",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchRoleSpec{
					Description: "Tenant user role",
					TenantPermissions: []wazuhv1.TenantPermission{
						{
							TenantPatterns: []string{"tenant1", "tenant2"},
							AllowedActions: []string{"kibana_all_read", "kibana_all_write"},
						},
					},
				},
			},
			wantDesc:       "Tenant user role",
			wantClusterLen: 0,
			wantIndexLen:   0,
			wantTenantLen:  1,
		},
		{
			name: "full role with all permissions",
			role: &wazuhv1.OpenSearchRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "full-role",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchRoleSpec{
					Description:        "Full role with all permissions",
					ClusterPermissions: []string{"cluster:monitor"},
					IndexPermissions: []wazuhv1.IndexPermission{
						{
							IndexPatterns:  []string{"*"},
							AllowedActions: []string{"read"},
						},
					},
					TenantPermissions: []wazuhv1.TenantPermission{
						{
							TenantPatterns: []string{"*"},
							AllowedActions: []string{"kibana_all_read"},
						},
					},
				},
			},
			wantDesc:       "Full role with all permissions",
			wantClusterLen: 1,
			wantIndexLen:   1,
			wantTenantLen:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.buildRole(tt.role)
			if got.Description != tt.wantDesc {
				t.Errorf("buildRole() Description = %v, want %v", got.Description, tt.wantDesc)
			}
			if len(got.ClusterPermissions) != tt.wantClusterLen {
				t.Errorf("buildRole() ClusterPermissions length = %v, want %v", len(got.ClusterPermissions), tt.wantClusterLen)
			}
			if len(got.IndexPermissions) != tt.wantIndexLen {
				t.Errorf("buildRole() IndexPermissions length = %v, want %v", len(got.IndexPermissions), tt.wantIndexLen)
			}
			if len(got.TenantPermissions) != tt.wantTenantLen {
				t.Errorf("buildRole() TenantPermissions length = %v, want %v", len(got.TenantPermissions), tt.wantTenantLen)
			}
		})
	}
}

func TestRoleReconciler_buildRole_IndexPermissionDetails(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := record.NewFakeRecorder(10)
	r := NewRoleReconciler(client, scheme, recorder)

	role := &wazuhv1.OpenSearchRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "detailed-role",
			Namespace: "default",
		},
		Spec: wazuhv1.OpenSearchRoleSpec{
			IndexPermissions: []wazuhv1.IndexPermission{
				{
					IndexPatterns:  []string{"logs-*", "alerts-*"},
					AllowedActions: []string{"read", "search", "get"},
				},
			},
		},
	}

	got := r.buildRole(role)

	if len(got.IndexPermissions) != 1 {
		t.Fatalf("Expected 1 index permission, got %d", len(got.IndexPermissions))
	}

	perm := got.IndexPermissions[0]
	if len(perm.IndexPatterns) != 2 {
		t.Errorf("Expected 2 index patterns, got %d", len(perm.IndexPatterns))
	}
	if len(perm.AllowedActions) != 3 {
		t.Errorf("Expected 3 allowed actions, got %d", len(perm.AllowedActions))
	}

	// Verify the index patterns
	expectedPatterns := map[string]bool{"logs-*": true, "alerts-*": true}
	for _, pattern := range perm.IndexPatterns {
		if !expectedPatterns[pattern] {
			t.Errorf("Unexpected index pattern: %s", pattern)
		}
	}

	// Verify the allowed actions
	expectedActions := map[string]bool{"read": true, "search": true, "get": true}
	for _, action := range perm.AllowedActions {
		if !expectedActions[action] {
			t.Errorf("Unexpected action: %s", action)
		}
	}
}

func TestRoleReconciler_recordEvent(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)

	tests := []struct {
		name         string
		recorder     record.EventRecorder
		role         *wazuhv1.OpenSearchRole
		eventType    string
		reason       string
		message      string
		expectEvents int
	}{
		{
			name:     "records event when recorder is available",
			recorder: record.NewFakeRecorder(10),
			role: &wazuhv1.OpenSearchRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
			},
			eventType:    corev1.EventTypeNormal,
			reason:       "Synced",
			message:      "Role synchronized",
			expectEvents: 1,
		},
		{
			name:     "no panic when recorder is nil",
			recorder: nil,
			role: &wazuhv1.OpenSearchRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
			},
			eventType:    corev1.EventTypeNormal,
			reason:       "Synced",
			message:      "Role synchronized",
			expectEvents: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithScheme(scheme).Build()
			r := NewRoleReconciler(client, scheme, tt.recorder)

			// Should not panic
			r.recordEvent(tt.role, tt.eventType, tt.reason, tt.message)

			// Verify event was recorded if recorder was provided
			if fakeRecorder, ok := tt.recorder.(*record.FakeRecorder); ok && tt.expectEvents > 0 {
				select {
				case event := <-fakeRecorder.Events:
					if event == "" {
						t.Error("Expected event to be recorded, but got empty event")
					}
				default:
					t.Error("Expected event to be recorded, but none was")
				}
			}
		})
	}
}
