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

package deployments

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

func TestIndexerStatefulSetBuilder_VersionAwarePaths(t *testing.T) {
	tests := []struct {
		name              string
		version           string
		expectedMounts    []string
		notExpectedMounts []string
	}{
		{
			name:    "Wazuh 4.13.0 uses legacy indexer paths",
			version: "4.13.0",
			expectedMounts: []string{
				constants.PathIndexerBase + "/opensearch.yml",
				constants.PathIndexerLegacySecurityConfig + "/internal_users.yml",
				constants.PathIndexerLegacySecurityConfig + "/roles_mapping.yml",
				constants.PathIndexerLegacyCerts,
			},
			notExpectedMounts: []string{
				constants.PathIndexerConfig + "/opensearch.yml",
				constants.PathIndexerSecurityConfig + "/internal_users.yml",
				constants.PathIndexerSecurityConfig + "/roles_mapping.yml",
				constants.PathIndexerCerts,
			},
		},
		{
			name:    "Wazuh 4.14.0 uses config dir indexer paths",
			version: "4.14.0",
			expectedMounts: []string{
				constants.PathIndexerConfig + "/opensearch.yml",
				constants.PathIndexerSecurityConfig + "/internal_users.yml",
				constants.PathIndexerSecurityConfig + "/roles_mapping.yml",
				constants.PathIndexerCerts,
			},
			notExpectedMounts: []string{
				constants.PathIndexerBase + "/opensearch.yml",
				constants.PathIndexerLegacySecurityConfig + "/internal_users.yml",
				constants.PathIndexerLegacySecurityConfig + "/roles_mapping.yml",
				constants.PathIndexerLegacyCerts,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewIndexerStatefulSetBuilder("cluster", "ns").WithVersion(tt.version)
			sts := builder.Build()

			if len(sts.Spec.Template.Spec.Containers) == 0 {
				t.Fatal("expected at least one container in StatefulSet")
			}

			mounts := sts.Spec.Template.Spec.Containers[0].VolumeMounts
			for _, path := range tt.expectedMounts {
				if !hasMountPath(mounts, path) {
					t.Fatalf("expected mount path %s, but it was not found", path)
				}
			}
			for _, path := range tt.notExpectedMounts {
				if hasMountPath(mounts, path) {
					t.Fatalf("did not expect mount path %s, but it was found", path)
				}
			}
		})
	}
}

func hasMountPath(mounts []corev1.VolumeMount, path string) bool {
	for _, mount := range mounts {
		if mount.MountPath == path {
			return true
		}
	}
	return false
}
