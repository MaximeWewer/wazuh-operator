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
				constants.PathIndexerLegacySecurityConfig + "/roles.yml",
				constants.PathIndexerLegacySecurityConfig + "/action_groups.yml",
				constants.PathIndexerLegacySecurityConfig + "/tenants.yml",
				constants.PathIndexerLegacySecurityConfig + "/config.yml",
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
				constants.PathIndexerSecurityConfig + "/roles.yml",
				constants.PathIndexerSecurityConfig + "/action_groups.yml",
				constants.PathIndexerSecurityConfig + "/tenants.yml",
				constants.PathIndexerSecurityConfig + "/config.yml",
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

func TestIndexerStatefulSetBuilder_CustomImage(t *testing.T) {
	t.Run("default image when no override", func(t *testing.T) {
		sts := NewIndexerStatefulSetBuilder("cluster", "ns").WithVersion("4.9.0").Build()
		got := sts.Spec.Template.Spec.Containers[0].Image
		want := constants.DefaultWazuhIndexerImage + ":4.9.0"
		if got != want {
			t.Errorf("image = %q, want %q", got, want)
		}
	})

	t.Run("custom image overrides default", func(t *testing.T) {
		sts := NewIndexerStatefulSetBuilder("cluster", "ns").
			WithVersion("4.9.0").
			WithImage("custom-repo/my-indexer:v1").
			Build()
		got := sts.Spec.Template.Spec.Containers[0].Image
		want := "custom-repo/my-indexer:v1"
		if got != want {
			t.Errorf("image = %q, want %q", got, want)
		}
	})
}

func TestIndexerStatefulSetBuilder_SecurityContextOverride(t *testing.T) {
	t.Run("default pod security context", func(t *testing.T) {
		sts := NewIndexerStatefulSetBuilder("cluster", "ns").Build()
		sc := sts.Spec.Template.Spec.SecurityContext
		if sc == nil {
			t.Fatal("expected pod security context")
		}
		if sc.FSGroup == nil || *sc.FSGroup != 1000 {
			t.Error("expected default FSGroup=1000")
		}
		if sc.RunAsUser == nil || *sc.RunAsUser != 1000 {
			t.Error("expected default RunAsUser=1000")
		}
	})

	t.Run("override FSGroup", func(t *testing.T) {
		gid := int64(2000)
		sts := NewIndexerStatefulSetBuilder("cluster", "ns").
			WithSecurityContext(&corev1.PodSecurityContext{
				FSGroup: &gid,
			}).
			Build()
		sc := sts.Spec.Template.Spec.SecurityContext
		if *sc.FSGroup != 2000 {
			t.Errorf("FSGroup = %d, want 2000", *sc.FSGroup)
		}
		// RunAsUser should still be the default
		if *sc.RunAsUser != 1000 {
			t.Errorf("RunAsUser = %d, want 1000 (default)", *sc.RunAsUser)
		}
	})

	t.Run("override supplemental groups", func(t *testing.T) {
		sts := NewIndexerStatefulSetBuilder("cluster", "ns").
			WithSecurityContext(&corev1.PodSecurityContext{
				SupplementalGroups: []int64{1001, 1002},
			}).
			Build()
		sc := sts.Spec.Template.Spec.SecurityContext
		if len(sc.SupplementalGroups) != 2 {
			t.Errorf("SupplementalGroups = %v, want [1001 1002]", sc.SupplementalGroups)
		}
	})
}

func TestIndexerStatefulSetBuilder_ContainerSecurityContextOverride(t *testing.T) {
	t.Run("default container security context", func(t *testing.T) {
		sts := NewIndexerStatefulSetBuilder("cluster", "ns").Build()
		sc := sts.Spec.Template.Spec.Containers[0].SecurityContext
		if sc == nil {
			t.Fatal("expected container security context")
		}
		if *sc.AllowPrivilegeEscalation {
			t.Error("expected AllowPrivilegeEscalation=false")
		}
		if sc.Capabilities == nil || len(sc.Capabilities.Drop) == 0 || sc.Capabilities.Drop[0] != "ALL" {
			t.Error("expected Drop ALL capabilities")
		}
	})

	t.Run("override ReadOnlyRootFilesystem", func(t *testing.T) {
		ro := true
		sts := NewIndexerStatefulSetBuilder("cluster", "ns").
			WithContainerSecurityContext(&corev1.SecurityContext{
				ReadOnlyRootFilesystem: &ro,
			}).
			Build()
		sc := sts.Spec.Template.Spec.Containers[0].SecurityContext
		if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
			t.Error("expected ReadOnlyRootFilesystem=true")
		}
		// Defaults should still be preserved
		if *sc.AllowPrivilegeEscalation {
			t.Error("expected AllowPrivilegeEscalation=false (default)")
		}
	})

	t.Run("full override", func(t *testing.T) {
		uid := int64(5000)
		sts := NewIndexerStatefulSetBuilder("cluster", "ns").
			WithContainerSecurityContext(&corev1.SecurityContext{
				AllowPrivilegeEscalation: boolPtr(true),
				RunAsUser:                &uid,
				Capabilities: &corev1.Capabilities{
					Add: []corev1.Capability{"NET_BIND_SERVICE"},
				},
			}).
			Build()
		sc := sts.Spec.Template.Spec.Containers[0].SecurityContext
		if !*sc.AllowPrivilegeEscalation {
			t.Error("expected AllowPrivilegeEscalation=true (overridden)")
		}
		if *sc.RunAsUser != 5000 {
			t.Errorf("RunAsUser = %d, want 5000", *sc.RunAsUser)
		}
		if sc.Capabilities.Add[0] != "NET_BIND_SERVICE" {
			t.Error("expected Add NET_BIND_SERVICE")
		}
	})
}

func hasMountPath(mounts []corev1.VolumeMount, path string) bool {
	for _, mount := range mounts {
		if mount.MountPath == path {
			return true
		}
	}
	return false
}
