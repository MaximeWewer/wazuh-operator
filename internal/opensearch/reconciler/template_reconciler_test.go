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

func TestTemplateReconciler_buildIndexTemplate(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := NewTemplateReconciler(client, scheme)

	tests := []struct {
		name            string
		template        *wazuhv1.OpenSearchIndexTemplate
		wantPatternsLen int
		wantPriority    int
		wantComposedLen int
		wantTemplate    bool
	}{
		{
			name: "minimal template with index patterns",
			template: &wazuhv1.OpenSearchIndexTemplate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-template",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchIndexTemplateSpec{
					IndexPatterns: []string{"logs-*"},
				},
			},
			wantPatternsLen: 1,
			wantPriority:    0,
			wantComposedLen: 0,
			wantTemplate:    false,
		},
		{
			name: "template with priority and composed_of",
			template: &wazuhv1.OpenSearchIndexTemplate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "priority-template",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchIndexTemplateSpec{
					IndexPatterns: []string{"logs-*", "metrics-*"},
					Priority:      200,
					ComposedOf:    []string{"component1", "component2"},
				},
			},
			wantPatternsLen: 2,
			wantPriority:    200,
			wantComposedLen: 2,
			wantTemplate:    false,
		},
		{
			name: "template with settings and mappings",
			template: &wazuhv1.OpenSearchIndexTemplate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "settings-template",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchIndexTemplateSpec{
					IndexPatterns: []string{"data-*"},
					Template: &wazuhv1.IndexTemplate{
						Settings: &runtime.RawExtension{
							Raw: []byte(`{"number_of_shards":3,"number_of_replicas":1}`),
						},
						Mappings: &runtime.RawExtension{
							Raw: []byte(`{"properties":{"timestamp":{"type":"date"}}}`),
						},
					},
				},
			},
			wantPatternsLen: 1,
			wantTemplate:    true,
		},
		{
			name: "template with aliases",
			template: &wazuhv1.OpenSearchIndexTemplate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "alias-template",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchIndexTemplateSpec{
					IndexPatterns: []string{"app-*"},
					Template: &wazuhv1.IndexTemplate{
						Aliases: map[string]wazuhv1.IndexAlias{
							"app-all": {
								IndexRouting:  "shard1",
								SearchRouting: "shard1",
								IsWriteIndex:  boolPtr(true),
							},
							"app-read": {
								Filter: &runtime.RawExtension{
									Raw: []byte(`{"term":{"status":"active"}}`),
								},
							},
						},
					},
				},
			},
			wantPatternsLen: 1,
			wantTemplate:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.buildIndexTemplate(tt.template)
			if len(got.IndexPatterns) != tt.wantPatternsLen {
				t.Errorf("buildIndexTemplate() IndexPatterns length = %v, want %v", len(got.IndexPatterns), tt.wantPatternsLen)
			}
			if got.Priority != tt.wantPriority {
				t.Errorf("buildIndexTemplate() Priority = %v, want %v", got.Priority, tt.wantPriority)
			}
			if len(got.ComposedOf) != tt.wantComposedLen {
				t.Errorf("buildIndexTemplate() ComposedOf length = %v, want %v", len(got.ComposedOf), tt.wantComposedLen)
			}
			if tt.wantTemplate && got.Template == nil {
				t.Error("buildIndexTemplate() expected Template to be set, got nil")
			}
			if !tt.wantTemplate && got.Template != nil {
				t.Error("buildIndexTemplate() expected Template to be nil, got non-nil")
			}
		})
	}
}

func TestTemplateReconciler_buildIndexTemplate_TemplateDetails(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := NewTemplateReconciler(client, scheme)

	template := &wazuhv1.OpenSearchIndexTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "detailed-template",
			Namespace: "default",
		},
		Spec: wazuhv1.OpenSearchIndexTemplateSpec{
			IndexPatterns: []string{"logs-*"},
			Priority:      100,
			Template: &wazuhv1.IndexTemplate{
				Settings: &runtime.RawExtension{
					Raw: []byte(`{"number_of_shards":5}`),
				},
				Mappings: &runtime.RawExtension{
					Raw: []byte(`{"properties":{"message":{"type":"text"}}}`),
				},
				Aliases: map[string]wazuhv1.IndexAlias{
					"logs": {
						IndexRouting:  "r1",
						SearchRouting: "r2",
						IsWriteIndex:  boolPtr(true),
						Filter: &runtime.RawExtension{
							Raw: []byte(`{"term":{"env":"prod"}}`),
						},
					},
				},
			},
		},
	}

	got := r.buildIndexTemplate(template)

	if got.Template == nil {
		t.Fatal("Expected Template to be set")
	}

	// Verify settings were parsed
	if got.Template.Settings == nil {
		t.Fatal("Expected Settings to be set")
	}

	// Verify mappings were parsed
	if got.Template.Mappings == nil {
		t.Fatal("Expected Mappings to be set")
	}
	if _, ok := got.Template.Mappings["properties"]; !ok {
		t.Error("Expected 'properties' key in mappings")
	}

	// Verify aliases
	if len(got.Template.Aliases) != 1 {
		t.Fatalf("Expected 1 alias, got %d", len(got.Template.Aliases))
	}
	alias, ok := got.Template.Aliases["logs"]
	if !ok {
		t.Fatal("Expected 'logs' alias to exist")
	}
	if alias.IndexRouting != "r1" {
		t.Errorf("Expected IndexRouting 'r1', got %s", alias.IndexRouting)
	}
	if alias.SearchRouting != "r2" {
		t.Errorf("Expected SearchRouting 'r2', got %s", alias.SearchRouting)
	}
	if alias.IsWriteIndex == nil || !*alias.IsWriteIndex {
		t.Error("Expected IsWriteIndex to be true")
	}
	if alias.Filter == nil {
		t.Error("Expected alias Filter to be set")
	}
}

func TestTemplateReconciler_buildIndexTemplate_NilTemplate(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := NewTemplateReconciler(client, scheme)

	template := &wazuhv1.OpenSearchIndexTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "no-template",
			Namespace: "default",
		},
		Spec: wazuhv1.OpenSearchIndexTemplateSpec{
			IndexPatterns: []string{"*"},
		},
	}

	got := r.buildIndexTemplate(template)
	if got.Template != nil {
		t.Error("Expected Template to be nil when spec.Template is nil")
	}
}

func boolPtr(b bool) *bool { return &b }
