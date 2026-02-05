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

package constants

import "testing"

func TestIndexerPathsByVersion(t *testing.T) {
	tests := []struct {
		name         string
		version      string
		expectConfig bool
	}{
		{
			name:         "Wazuh 4.13.0 uses legacy paths",
			version:      "4.13.0",
			expectConfig: false,
		},
		{
			name:         "Wazuh 4.14.0 uses config paths",
			version:      "4.14.0",
			expectConfig: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if UsesIndexerConfigDir(tt.version) != tt.expectConfig {
				t.Fatalf("UsesIndexerConfigDir(%s) expected %v", tt.version, tt.expectConfig)
			}
		})
	}
}
