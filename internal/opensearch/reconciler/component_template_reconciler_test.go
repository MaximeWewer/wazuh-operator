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

func TestComponentTemplateReconciler_buildComponentTemplate(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := NewComponentTemplateReconciler(client, scheme)

	tests := []struct {
		name         string
		template     *wazuhv1.OpenSearchComponentTemplate
		wantSettings bool
		wantMappings bool
	}{
		{
			name: "component template with settings only",
			template: &wazuhv1.OpenSearchComponentTemplate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "settings-ct",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchComponentTemplateSpec{
					Template: wazuhv1.ComponentTemplate{
						Settings: &runtime.RawExtension{
							Raw: []byte(`{"index":{"number_of_shards":3}}`),
						},
					},
				},
			},
			wantSettings: true,
			wantMappings: false,
		},
		{
			name: "component template with mappings only",
			template: &wazuhv1.OpenSearchComponentTemplate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "mappings-ct",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchComponentTemplateSpec{
					Template: wazuhv1.ComponentTemplate{
						Mappings: &runtime.RawExtension{
							Raw: []byte(`{"properties":{"timestamp":{"type":"date"}}}`),
						},
					},
				},
			},
			wantSettings: false,
			wantMappings: true,
		},
		{
			name: "component template with both settings and mappings",
			template: &wazuhv1.OpenSearchComponentTemplate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "full-ct",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchComponentTemplateSpec{
					Template: wazuhv1.ComponentTemplate{
						Settings: &runtime.RawExtension{
							Raw: []byte(`{"index":{"number_of_replicas":2}}`),
						},
						Mappings: &runtime.RawExtension{
							Raw: []byte(`{"properties":{"message":{"type":"text"}}}`),
						},
					},
				},
			},
			wantSettings: true,
			wantMappings: true,
		},
		{
			name: "component template with nil settings and mappings",
			template: &wazuhv1.OpenSearchComponentTemplate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "empty-ct",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchComponentTemplateSpec{
					Template: wazuhv1.ComponentTemplate{},
				},
			},
			wantSettings: false,
			wantMappings: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.buildComponentTemplate(tt.template)

			if got.Template == nil {
				t.Fatal("Expected Template to always be set")
			}

			hasSettings := len(got.Template.SettingsRaw) > 0
			if hasSettings != tt.wantSettings {
				t.Errorf("buildComponentTemplate() has SettingsRaw = %v, want %v", hasSettings, tt.wantSettings)
			}

			hasMappings := len(got.Template.MappingsRaw) > 0
			if hasMappings != tt.wantMappings {
				t.Errorf("buildComponentTemplate() has MappingsRaw = %v, want %v", hasMappings, tt.wantMappings)
			}
		})
	}
}

func TestComponentTemplateReconciler_buildComponentTemplate_RawPassthrough(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := NewComponentTemplateReconciler(client, scheme)

	settingsJSON := []byte(`{"index":{"number_of_shards":5,"number_of_replicas":2}}`)
	mappingsJSON := []byte(`{"properties":{"@timestamp":{"type":"date"},"message":{"type":"text"}}}`)

	template := &wazuhv1.OpenSearchComponentTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "passthrough-ct",
			Namespace: "default",
		},
		Spec: wazuhv1.OpenSearchComponentTemplateSpec{
			Template: wazuhv1.ComponentTemplate{
				Settings: &runtime.RawExtension{Raw: settingsJSON},
				Mappings: &runtime.RawExtension{Raw: mappingsJSON},
			},
		},
	}

	got := r.buildComponentTemplate(template)

	// Verify raw bytes are passed through unchanged
	if string(got.Template.SettingsRaw) != string(settingsJSON) {
		t.Errorf("SettingsRaw not passed through correctly\ngot:  %s\nwant: %s", got.Template.SettingsRaw, settingsJSON)
	}
	if string(got.Template.MappingsRaw) != string(mappingsJSON) {
		t.Errorf("MappingsRaw not passed through correctly\ngot:  %s\nwant: %s", got.Template.MappingsRaw, mappingsJSON)
	}
}
