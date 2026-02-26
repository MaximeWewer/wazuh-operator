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

	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

func TestDashboardDeploymentBuilder_EnableSSL_DefaultHTTPS(t *testing.T) {
	dns.Initialize()
	deploy := NewDashboardDeploymentBuilder("cluster", "ns").Build()

	container := getDashboardContainer(t, deploy.Spec.Template.Spec.Containers)
	if container.LivenessProbe == nil || container.LivenessProbe.HTTPGet == nil {
		t.Fatalf("expected liveness probe with HTTPGet")
	}
	if container.ReadinessProbe == nil || container.ReadinessProbe.HTTPGet == nil {
		t.Fatalf("expected readiness probe with HTTPGet")
	}

	if container.LivenessProbe.HTTPGet.Scheme != corev1.URISchemeHTTPS {
		t.Fatalf("expected liveness probe scheme HTTPS, got %s", container.LivenessProbe.HTTPGet.Scheme)
	}
	if container.ReadinessProbe.HTTPGet.Scheme != corev1.URISchemeHTTPS {
		t.Fatalf("expected readiness probe scheme HTTPS, got %s", container.ReadinessProbe.HTTPGet.Scheme)
	}
}

func TestDashboardDeploymentBuilder_EnableSSL_FalseHTTP(t *testing.T) {
	dns.Initialize()
	deploy := NewDashboardDeploymentBuilder("cluster", "ns").
		WithEnableSSL(false).
		Build()

	container := getDashboardContainer(t, deploy.Spec.Template.Spec.Containers)
	if container.LivenessProbe == nil || container.LivenessProbe.HTTPGet == nil {
		t.Fatalf("expected liveness probe with HTTPGet")
	}
	if container.ReadinessProbe == nil || container.ReadinessProbe.HTTPGet == nil {
		t.Fatalf("expected readiness probe with HTTPGet")
	}

	if container.LivenessProbe.HTTPGet.Scheme != corev1.URISchemeHTTP {
		t.Fatalf("expected liveness probe scheme HTTP, got %s", container.LivenessProbe.HTTPGet.Scheme)
	}
	if container.ReadinessProbe.HTTPGet.Scheme != corev1.URISchemeHTTP {
		t.Fatalf("expected readiness probe scheme HTTP, got %s", container.ReadinessProbe.HTTPGet.Scheme)
	}
}

func TestDashboardDeploymentBuilder_CustomImage(t *testing.T) {
	dns.Initialize()

	t.Run("default image when no override", func(t *testing.T) {
		deploy := NewDashboardDeploymentBuilder("cluster", "ns").WithVersion("4.9.0").Build()
		got := getDashboardContainer(t, deploy.Spec.Template.Spec.Containers).Image
		want := "wazuh/wazuh-dashboard:4.9.0"
		if got != want {
			t.Errorf("image = %q, want %q", got, want)
		}
	})

	t.Run("custom image overrides default", func(t *testing.T) {
		deploy := NewDashboardDeploymentBuilder("cluster", "ns").
			WithVersion("4.9.0").
			WithImage("custom-repo/my-dashboard:v1").
			Build()
		got := getDashboardContainer(t, deploy.Spec.Template.Spec.Containers).Image
		want := "custom-repo/my-dashboard:v1"
		if got != want {
			t.Errorf("image = %q, want %q", got, want)
		}
	})
}

func TestDashboardDeploymentBuilder_SecurityContextOverride(t *testing.T) {
	dns.Initialize()

	t.Run("default pod security context", func(t *testing.T) {
		deploy := NewDashboardDeploymentBuilder("cluster", "ns").Build()
		sc := deploy.Spec.Template.Spec.SecurityContext
		if sc == nil {
			t.Fatal("expected pod security context")
		}
		if sc.FSGroup == nil || *sc.FSGroup != 1000 {
			t.Error("expected default FSGroup=1000")
		}
		if sc.RunAsUser == nil || *sc.RunAsUser != 1000 {
			t.Error("expected default RunAsUser=1000")
		}
		if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
			t.Error("expected default RunAsNonRoot=true")
		}
		if sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
			t.Error("expected default SeccompProfile=RuntimeDefault")
		}
	})

	t.Run("override FSGroup", func(t *testing.T) {
		gid := int64(2000)
		deploy := NewDashboardDeploymentBuilder("cluster", "ns").
			WithSecurityContext(&corev1.PodSecurityContext{
				FSGroup: &gid,
			}).
			Build()
		sc := deploy.Spec.Template.Spec.SecurityContext
		if *sc.FSGroup != 2000 {
			t.Errorf("FSGroup = %d, want 2000", *sc.FSGroup)
		}
		// Defaults should still be preserved
		if *sc.RunAsUser != 1000 {
			t.Errorf("RunAsUser = %d, want 1000 (default)", *sc.RunAsUser)
		}
		if !*sc.RunAsNonRoot {
			t.Error("expected RunAsNonRoot=true (default)")
		}
	})
}

func TestDashboardDeploymentBuilder_ContainerSecurityContextOverride(t *testing.T) {
	dns.Initialize()

	t.Run("default container security context", func(t *testing.T) {
		deploy := NewDashboardDeploymentBuilder("cluster", "ns").Build()
		sc := getDashboardContainer(t, deploy.Spec.Template.Spec.Containers).SecurityContext
		if sc == nil {
			t.Fatal("expected container security context")
		}
		if sc.AllowPrivilegeEscalation == nil || !*sc.AllowPrivilegeEscalation {
			t.Error("expected default AllowPrivilegeEscalation=true")
		}
	})

	t.Run("override AllowPrivilegeEscalation", func(t *testing.T) {
		f := false
		deploy := NewDashboardDeploymentBuilder("cluster", "ns").
			WithContainerSecurityContext(&corev1.SecurityContext{
				AllowPrivilegeEscalation: &f,
			}).
			Build()
		sc := getDashboardContainer(t, deploy.Spec.Template.Spec.Containers).SecurityContext
		if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
			t.Error("expected AllowPrivilegeEscalation=false (overridden)")
		}
	})

	t.Run("add ReadOnlyRootFilesystem", func(t *testing.T) {
		tr := true
		deploy := NewDashboardDeploymentBuilder("cluster", "ns").
			WithContainerSecurityContext(&corev1.SecurityContext{
				ReadOnlyRootFilesystem: &tr,
			}).
			Build()
		sc := getDashboardContainer(t, deploy.Spec.Template.Spec.Containers).SecurityContext
		if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
			t.Error("expected ReadOnlyRootFilesystem=true")
		}
		// Default should still be preserved
		if !*sc.AllowPrivilegeEscalation {
			t.Error("expected AllowPrivilegeEscalation=true (default)")
		}
	})
}

func getDashboardContainer(t *testing.T, containers []corev1.Container) corev1.Container {
	t.Helper()
	if len(containers) == 0 {
		t.Fatal("expected at least one container in Deployment")
	}
	for _, c := range containers {
		if c.Name == "dashboard" {
			return c
		}
	}
	t.Fatal("dashboard container not found")
	return corev1.Container{}
}
