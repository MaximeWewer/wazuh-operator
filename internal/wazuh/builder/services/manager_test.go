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

package services

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

func TestManagerServiceBuilder_WithPorts(t *testing.T) {
	builder := NewManagerServiceBuilder("test-cluster", "default", "master")
	customPorts := []corev1.ServicePort{
		{
			Name:       "http",
			Port:       80,
			TargetPort: intstr.FromInt(5601),
			Protocol:   corev1.ProtocolTCP,
		},
	}

	service := builder.WithPorts(customPorts).Build()

	if len(service.Spec.Ports) != 1 {
		t.Fatalf("expected 1 port, got %d", len(service.Spec.Ports))
	}
	if service.Spec.Ports[0].Name != "http" {
		t.Fatalf("expected port name 'http', got %q", service.Spec.Ports[0].Name)
	}
	if service.Spec.Ports[0].Port != 80 {
		t.Fatalf("expected port 80, got %d", service.Spec.Ports[0].Port)
	}
	if service.Spec.Ports[0].TargetPort.IntVal != 5601 {
		t.Fatalf("expected targetPort 5601, got %d", service.Spec.Ports[0].TargetPort.IntVal)
	}
}

func TestManagerServiceBuilder_DefaultPortsFallback(t *testing.T) {
	service := NewManagerServiceBuilder("test-cluster", "default", "master").Build()

	if len(service.Spec.Ports) != 4 {
		t.Fatalf("expected 4 default ports, got %d", len(service.Spec.Ports))
	}

	expectedNames := []string{
		constants.PortNameManagerAPI,
		constants.PortNameManagerAgentEvents,
		constants.PortNameManagerAgentAuth,
		constants.PortNameManagerCluster,
	}
	for i, p := range service.Spec.Ports {
		if p.Name != expectedNames[i] {
			t.Fatalf("expected port[%d] name %q, got %q", i, expectedNames[i], p.Name)
		}
	}
}
