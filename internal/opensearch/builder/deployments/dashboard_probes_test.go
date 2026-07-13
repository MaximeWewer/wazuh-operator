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
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

// The dashboard probes must not target /app/login. That route is the basicauth login page, so it
// only answers 200 when opensearch_security.auth.type is basicauth; with an external IdP
// (OpenSearchAuthConfig with OIDC/SAML/JWT) the security plugin answers 401 to the unauthenticated
// kube-probe, the probe fails and the dashboard never becomes healthy even though it serves users
// fine. /api/status only answers 200 because the generated config lists it in
// opensearch_security.auth.unauthenticated_routes (see TestDashboardConfigExposesStatusRoute):
// the security plugin defaults that list to empty, so the probe path and that setting must stay
// in sync.
func TestDashboardProbesUseStatusAPINotLoginPage(t *testing.T) {
	dns.Initialize()
	deploy := NewDashboardDeploymentBuilder("cluster", "ns").Build()

	var dashboard *corev1.Container
	for i := range deploy.Spec.Template.Spec.Containers {
		if deploy.Spec.Template.Spec.Containers[i].Name == "dashboard" {
			dashboard = &deploy.Spec.Template.Spec.Containers[i]
			break
		}
	}
	if dashboard == nil {
		t.Fatal("dashboard container not found")
	}

	probes := map[string]*corev1.Probe{
		"liveness":  dashboard.LivenessProbe,
		"readiness": dashboard.ReadinessProbe,
	}

	for name, probe := range probes {
		if probe == nil {
			t.Errorf("%s probe is not set", name)
			continue
		}
		if probe.HTTPGet == nil {
			t.Errorf("%s probe is not an HTTP probe", name)
			continue
		}
		if got := probe.HTTPGet.Path; got != constants.PathDashboardStatusAPI {
			t.Errorf("%s probe path = %q, want %q", name, got, constants.PathDashboardStatusAPI)
		}
		if probe.HTTPGet.Path == "/app/login" {
			t.Errorf("%s probe targets the basicauth login page, which 401s under OIDC/SAML/JWT", name)
		}
	}
}
