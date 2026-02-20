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

func TestTenantReconciler_buildTenant(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := NewTenantReconciler(client, scheme)

	tests := []struct {
		name     string
		tenant   *wazuhv1.OpenSearchTenant
		wantDesc string
	}{
		{
			name: "tenant with description",
			tenant: &wazuhv1.OpenSearchTenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-tenant",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchTenantSpec{
					Description: "Test tenant description",
				},
			},
			wantDesc: "Test tenant description",
		},
		{
			name: "tenant with empty description",
			tenant: &wazuhv1.OpenSearchTenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "empty-tenant",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchTenantSpec{
					Description: "",
				},
			},
			wantDesc: "",
		},
		{
			name: "tenant with long description",
			tenant: &wazuhv1.OpenSearchTenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "verbose-tenant",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchTenantSpec{
					Description: "This is a very detailed description for the tenant used by the security team for dashboards",
				},
			},
			wantDesc: "This is a very detailed description for the tenant used by the security team for dashboards",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.buildTenant(tt.tenant)
			if got.Description != tt.wantDesc {
				t.Errorf("buildTenant() Description = %v, want %v", got.Description, tt.wantDesc)
			}
		})
	}
}
