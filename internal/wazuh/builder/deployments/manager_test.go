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
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

func TestMain(m *testing.M) {
	dns.Initialize()
	os.Exit(m.Run())
}

func TestManagerStatefulSetBuilder_CustomImage(t *testing.T) {
	t.Run("default image when no override", func(t *testing.T) {
		sts := NewManagerStatefulSetBuilder("cluster", "ns", "master").WithVersion("4.9.0").Build()
		got := sts.Spec.Template.Spec.Containers[0].Image
		want := constants.DefaultWazuhManagerImage + ":4.9.0"
		if got != want {
			t.Errorf("image = %q, want %q", got, want)
		}
	})

	t.Run("custom image overrides default", func(t *testing.T) {
		sts := NewManagerStatefulSetBuilder("cluster", "ns", "master").
			WithVersion("4.9.0").
			WithImage("custom-repo/my-manager:v1").
			Build()
		got := sts.Spec.Template.Spec.Containers[0].Image
		want := "custom-repo/my-manager:v1"
		if got != want {
			t.Errorf("image = %q, want %q", got, want)
		}
	})
}

func TestManagerStatefulSetBuilder_SecurityContextOverride(t *testing.T) {
	t.Run("default pod security context", func(t *testing.T) {
		sts := NewManagerStatefulSetBuilder("cluster", "ns", "master").Build()
		sc := sts.Spec.Template.Spec.SecurityContext
		if sc == nil {
			t.Fatal("expected pod security context")
		}
		if sc.FSGroup == nil || *sc.FSGroup != 999 {
			t.Error("expected default FSGroup=999")
		}
		if sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeUnconfined {
			t.Error("expected default SeccompProfile=Unconfined")
		}
	})

	t.Run("override FSGroup", func(t *testing.T) {
		gid := int64(2000)
		sts := NewManagerStatefulSetBuilder("cluster", "ns", "master").
			WithSecurityContext(&corev1.PodSecurityContext{
				FSGroup: &gid,
			}).
			Build()
		sc := sts.Spec.Template.Spec.SecurityContext
		if *sc.FSGroup != 2000 {
			t.Errorf("FSGroup = %d, want 2000", *sc.FSGroup)
		}
		// SeccompProfile should still be the default
		if sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeUnconfined {
			t.Error("expected SeccompProfile=Unconfined (default)")
		}
	})

	t.Run("override SeccompProfile", func(t *testing.T) {
		sts := NewManagerStatefulSetBuilder("cluster", "ns", "master").
			WithSecurityContext(&corev1.PodSecurityContext{
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				},
			}).
			Build()
		sc := sts.Spec.Template.Spec.SecurityContext
		if sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
			t.Error("expected SeccompProfile=RuntimeDefault (overridden)")
		}
		// FSGroup should still be the default
		if *sc.FSGroup != 999 {
			t.Errorf("FSGroup = %d, want 999 (default)", *sc.FSGroup)
		}
	})

	t.Run("override supplemental groups", func(t *testing.T) {
		sts := NewManagerStatefulSetBuilder("cluster", "ns", "master").
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

func TestManagerStatefulSetBuilder_ContainerSecurityContextOverride(t *testing.T) {
	t.Run("default container security context", func(t *testing.T) {
		sts := NewManagerStatefulSetBuilder("cluster", "ns", "master").Build()
		sc := sts.Spec.Template.Spec.Containers[0].SecurityContext
		if sc == nil {
			t.Fatal("expected container security context")
		}
		if sc.RunAsUser == nil || *sc.RunAsUser != 0 {
			t.Error("expected default RunAsUser=0")
		}
		if sc.Capabilities == nil || len(sc.Capabilities.Add) == 0 || sc.Capabilities.Add[0] != "SYS_CHROOT" {
			t.Error("expected Add SYS_CHROOT capability")
		}
	})

	t.Run("override ReadOnlyRootFilesystem", func(t *testing.T) {
		sts := NewManagerStatefulSetBuilder("cluster", "ns", "master").
			WithContainerSecurityContext(&corev1.SecurityContext{
				ReadOnlyRootFilesystem: new(true),
			}).
			Build()
		sc := sts.Spec.Template.Spec.Containers[0].SecurityContext
		if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
			t.Error("expected ReadOnlyRootFilesystem=true")
		}
		// Defaults should still be preserved
		if *sc.RunAsUser != 0 {
			t.Errorf("RunAsUser = %d, want 0 (default)", *sc.RunAsUser)
		}
		if sc.Capabilities == nil || len(sc.Capabilities.Add) == 0 || sc.Capabilities.Add[0] != "SYS_CHROOT" {
			t.Error("expected Add SYS_CHROOT capability (default)")
		}
	})

	t.Run("full override", func(t *testing.T) {
		uid := int64(5000)
		sts := NewManagerStatefulSetBuilder("cluster", "ns", "master").
			WithContainerSecurityContext(&corev1.SecurityContext{
				RunAsUser: &uid,
				Capabilities: &corev1.Capabilities{
					Add: []corev1.Capability{"NET_BIND_SERVICE"},
				},
			}).
			Build()
		sc := sts.Spec.Template.Spec.Containers[0].SecurityContext
		if *sc.RunAsUser != 5000 {
			t.Errorf("RunAsUser = %d, want 5000", *sc.RunAsUser)
		}
		if sc.Capabilities.Add[0] != "NET_BIND_SERVICE" {
			t.Error("expected Add NET_BIND_SERVICE")
		}
	})
}

func TestWorkerStatefulSetBuilder_CustomImage(t *testing.T) {
	t.Run("default image when no override", func(t *testing.T) {
		sts := NewWorkerStatefulSetBuilder("cluster", "ns").WithVersion("4.9.0").Build()
		got := sts.Spec.Template.Spec.Containers[0].Image
		want := constants.DefaultWazuhManagerImage + ":4.9.0"
		if got != want {
			t.Errorf("image = %q, want %q", got, want)
		}
	})

	t.Run("custom image overrides default", func(t *testing.T) {
		sts := NewWorkerStatefulSetBuilder("cluster", "ns").
			WithVersion("4.9.0").
			WithImage("custom-repo/my-manager:v1").
			Build()
		got := sts.Spec.Template.Spec.Containers[0].Image
		want := "custom-repo/my-manager:v1"
		if got != want {
			t.Errorf("image = %q, want %q", got, want)
		}
	})
}

func TestWorkerStatefulSetBuilder_SecurityContextOverride(t *testing.T) {
	t.Run("default pod security context", func(t *testing.T) {
		sts := NewWorkerStatefulSetBuilder("cluster", "ns").Build()
		sc := sts.Spec.Template.Spec.SecurityContext
		if sc == nil {
			t.Fatal("expected pod security context")
		}
		if sc.FSGroup == nil || *sc.FSGroup != 999 {
			t.Error("expected default FSGroup=999")
		}
		if sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeUnconfined {
			t.Error("expected default SeccompProfile=Unconfined")
		}
	})

	t.Run("override FSGroup", func(t *testing.T) {
		gid := int64(2000)
		sts := NewWorkerStatefulSetBuilder("cluster", "ns").
			WithSecurityContext(&corev1.PodSecurityContext{
				FSGroup: &gid,
			}).
			Build()
		sc := sts.Spec.Template.Spec.SecurityContext
		if *sc.FSGroup != 2000 {
			t.Errorf("FSGroup = %d, want 2000", *sc.FSGroup)
		}
		// SeccompProfile should still be the default
		if sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeUnconfined {
			t.Error("expected SeccompProfile=Unconfined (default)")
		}
	})
}

func TestWorkerStatefulSetBuilder_ContainerSecurityContextOverride(t *testing.T) {
	t.Run("default container security context", func(t *testing.T) {
		sts := NewWorkerStatefulSetBuilder("cluster", "ns").Build()
		sc := sts.Spec.Template.Spec.Containers[0].SecurityContext
		if sc == nil {
			t.Fatal("expected container security context")
		}
		if sc.RunAsUser == nil || *sc.RunAsUser != 0 {
			t.Error("expected default RunAsUser=0")
		}
		if sc.Capabilities == nil || len(sc.Capabilities.Add) == 0 || sc.Capabilities.Add[0] != "SYS_CHROOT" {
			t.Error("expected Add SYS_CHROOT capability")
		}
	})

	t.Run("override Capabilities", func(t *testing.T) {
		sts := NewWorkerStatefulSetBuilder("cluster", "ns").
			WithContainerSecurityContext(&corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{
					Add:  []corev1.Capability{"NET_BIND_SERVICE"},
					Drop: []corev1.Capability{"ALL"},
				},
			}).
			Build()
		sc := sts.Spec.Template.Spec.Containers[0].SecurityContext
		if sc.Capabilities.Add[0] != "NET_BIND_SERVICE" {
			t.Error("expected Add NET_BIND_SERVICE")
		}
		if sc.Capabilities.Drop[0] != "ALL" {
			t.Error("expected Drop ALL")
		}
		// RunAsUser should still be the default
		if *sc.RunAsUser != 0 {
			t.Errorf("RunAsUser = %d, want 0 (default)", *sc.RunAsUser)
		}
	})
}

func TestWorkerStatefulSetBuilder_EnvForwarding(t *testing.T) {
	customEnv := []corev1.EnvVar{
		{Name: "MY_VAR", Value: "my-value"},
	}
	customEnvFrom := []corev1.EnvFromSource{
		{
			ConfigMapRef: &corev1.ConfigMapEnvSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: "my-cm"},
			},
		},
	}

	sts := NewWorkerStatefulSetBuilder("cluster", "ns").
		WithEnv(customEnv).
		WithEnvFrom(customEnvFrom).
		Build()

	container := sts.Spec.Template.Spec.Containers[0]

	// Check that custom env is appended (after built-in envs)
	found := false
	for _, e := range container.Env {
		if e.Name == "MY_VAR" && e.Value == "my-value" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected custom env var MY_VAR to be present")
	}

	// Check envFrom
	if len(container.EnvFrom) == 0 {
		t.Fatal("expected envFrom to be set")
	}
	foundEnvFrom := false
	for _, ef := range container.EnvFrom {
		if ef.ConfigMapRef != nil && ef.ConfigMapRef.Name == "my-cm" {
			foundEnvFrom = true
			break
		}
	}
	if !foundEnvFrom {
		t.Error("expected envFrom with ConfigMapRef my-cm")
	}
}
