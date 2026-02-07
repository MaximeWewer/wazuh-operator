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
