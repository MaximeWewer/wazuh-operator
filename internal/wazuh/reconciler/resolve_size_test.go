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

import "testing"

func TestResolveSizeForPVC(t *testing.T) {
	sizeByVCT := map[string]string{
		"wazuh-data":          "50Gi",
		"wazuh-data-queue-db": "5Gi",
	}
	sts := "wazuh-cluster-manager-master"
	tests := []struct {
		pvc  string
		want string
	}{
		// Default PVC -> default size.
		{"wazuh-data-" + sts + "-0", "50Gi"},
		// Split PVC -> its own size (longest-prefix wins over "wazuh-data").
		{"wazuh-data-queue-db-" + sts + "-0", "5Gi"},
		// Unknown PVC -> empty (left untouched).
		{"some-other-pvc-0", ""},
	}
	for _, tt := range tests {
		if got := resolveSizeForPVC(tt.pvc, sizeByVCT); got != tt.want {
			t.Errorf("resolveSizeForPVC(%q) = %q, want %q", tt.pvc, got, tt.want)
		}
	}
}
