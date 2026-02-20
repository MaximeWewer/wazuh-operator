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

func TestActionGroupReconciler_buildActionGroup(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := NewActionGroupReconciler(client, scheme, nil)

	tests := []struct {
		name           string
		ag             *wazuhv1.OpenSearchActionGroup
		wantDesc       string
		wantType       string
		wantActionsLen int
	}{
		{
			name: "action group with description only",
			ag: &wazuhv1.OpenSearchActionGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-ag",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchActionGroupSpec{
					Description: "Test action group",
				},
			},
			wantDesc:       "Test action group",
			wantActionsLen: 0,
		},
		{
			name: "action group with allowed actions",
			ag: &wazuhv1.OpenSearchActionGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "read-ag",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchActionGroupSpec{
					Description:    "Read actions",
					AllowedActions: []string{"indices:data/read/*", "indices:admin/mappings/get"},
				},
			},
			wantDesc:       "Read actions",
			wantActionsLen: 2,
		},
		{
			name: "action group with type",
			ag: &wazuhv1.OpenSearchActionGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "typed-ag",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchActionGroupSpec{
					Description:    "Typed action group",
					AllowedActions: []string{"cluster:monitor"},
					Type:           "cluster",
				},
			},
			wantDesc:       "Typed action group",
			wantType:       "cluster",
			wantActionsLen: 1,
		},
		{
			name: "full action group",
			ag: &wazuhv1.OpenSearchActionGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "full-ag",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchActionGroupSpec{
					Description:    "Full action group with all fields",
					AllowedActions: []string{"indices:data/read/*", "indices:data/write/*", "indices:admin/*"},
					Type:           "index",
				},
			},
			wantDesc:       "Full action group with all fields",
			wantType:       "index",
			wantActionsLen: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.buildActionGroup(tt.ag)
			if got.Description != tt.wantDesc {
				t.Errorf("buildActionGroup() Description = %v, want %v", got.Description, tt.wantDesc)
			}
			if got.Type != tt.wantType {
				t.Errorf("buildActionGroup() Type = %v, want %v", got.Type, tt.wantType)
			}
			if len(got.AllowedActions) != tt.wantActionsLen {
				t.Errorf("buildActionGroup() AllowedActions length = %v, want %v", len(got.AllowedActions), tt.wantActionsLen)
			}
		})
	}
}

func TestActionGroupReconciler_buildActionGroup_Values(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := NewActionGroupReconciler(client, scheme, nil)

	ag := &wazuhv1.OpenSearchActionGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "detailed-ag",
			Namespace: "default",
		},
		Spec: wazuhv1.OpenSearchActionGroupSpec{
			AllowedActions: []string{"read", "search", "get"},
			Type:           "index",
		},
	}

	got := r.buildActionGroup(ag)

	expectedActions := map[string]bool{"read": true, "search": true, "get": true}
	for _, action := range got.AllowedActions {
		if !expectedActions[action] {
			t.Errorf("Unexpected allowed action: %s", action)
		}
	}
}
