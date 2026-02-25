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

package v1

import "testing"

func TestImageSpec_ResolveImage(t *testing.T) {
	tests := []struct {
		name       string
		spec       *ImageSpec
		defaultImg string
		defaultTag string
		want       string
	}{
		{
			name:       "nil spec uses defaults",
			spec:       nil,
			defaultImg: "wazuh/wazuh-indexer",
			defaultTag: "4.9.0",
			want:       "wazuh/wazuh-indexer:4.9.0",
		},
		{
			name:       "empty spec uses defaults",
			spec:       &ImageSpec{},
			defaultImg: "wazuh/wazuh-indexer",
			defaultTag: "4.9.0",
			want:       "wazuh/wazuh-indexer:4.9.0",
		},
		{
			name:       "custom repository overrides default",
			spec:       &ImageSpec{Repository: "custom/indexer"},
			defaultImg: "wazuh/wazuh-indexer",
			defaultTag: "4.9.0",
			want:       "custom/indexer:4.9.0",
		},
		{
			name:       "custom tag overrides default",
			spec:       &ImageSpec{Tag: "latest"},
			defaultImg: "wazuh/wazuh-indexer",
			defaultTag: "4.9.0",
			want:       "wazuh/wazuh-indexer:latest",
		},
		{
			name:       "both custom repository and tag",
			spec:       &ImageSpec{Repository: "myrepo/indexer", Tag: "v2"},
			defaultImg: "wazuh/wazuh-indexer",
			defaultTag: "4.9.0",
			want:       "myrepo/indexer:v2",
		},
		{
			name:       "empty default tag",
			spec:       nil,
			defaultImg: "wazuh/wazuh-indexer",
			defaultTag: "",
			want:       "wazuh/wazuh-indexer",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.spec.ResolveImage(tt.defaultImg, tt.defaultTag)
			if got != tt.want {
				t.Errorf("ResolveImage() = %q, want %q", got, tt.want)
			}
		})
	}
}
