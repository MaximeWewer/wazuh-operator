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

func TestDashboardServiceBuilder_DefaultPorts(t *testing.T) {
	service := NewDashboardServiceBuilder("test-cluster", "default").Build()

	if len(service.Spec.Ports) != 1 {
		t.Fatalf("expected 1 default port, got %d", len(service.Spec.Ports))
	}
	if service.Spec.Ports[0].Name != constants.PortNameDashboardHTTP {
		t.Fatalf("expected port name %q, got %q", constants.PortNameDashboardHTTP, service.Spec.Ports[0].Name)
	}
	if service.Spec.Ports[0].Port != constants.PortDashboardHTTP {
		t.Fatalf("expected port %d, got %d", constants.PortDashboardHTTP, service.Spec.Ports[0].Port)
	}
}

func TestDashboardServiceBuilder_WithPorts(t *testing.T) {
	customPorts := []corev1.ServicePort{
		{
			Name:       "custom-http",
			Port:       8080,
			TargetPort: intstr.FromInt(5601),
			Protocol:   corev1.ProtocolTCP,
		},
	}

	service := NewDashboardServiceBuilder("test-cluster", "default").
		WithPorts(customPorts).
		Build()

	if len(service.Spec.Ports) != 1 {
		t.Fatalf("expected 1 port, got %d", len(service.Spec.Ports))
	}
	if service.Spec.Ports[0].Name != "custom-http" {
		t.Fatalf("expected port name 'custom-http', got %q", service.Spec.Ports[0].Name)
	}
	if service.Spec.Ports[0].Port != 8080 {
		t.Fatalf("expected port 8080, got %d", service.Spec.Ports[0].Port)
	}
	if service.Spec.Ports[0].TargetPort.IntVal != 5601 {
		t.Fatalf("expected targetPort 5601, got %d", service.Spec.Ports[0].TargetPort.IntVal)
	}
}

func TestDashboardServiceBuilder_WithPortsOverridesNodePort(t *testing.T) {
	customPorts := []corev1.ServicePort{
		{
			Name:       "custom-http",
			Port:       8080,
			TargetPort: intstr.FromInt(5601),
			Protocol:   corev1.ProtocolTCP,
			NodePort:   31000,
		},
	}

	// When custom ports are set, nodePort on the builder should be ignored
	service := NewDashboardServiceBuilder("test-cluster", "default").
		WithServiceType(corev1.ServiceTypeNodePort).
		WithNodePort(32000).
		WithPorts(customPorts).
		Build()

	if len(service.Spec.Ports) != 1 {
		t.Fatalf("expected 1 port, got %d", len(service.Spec.Ports))
	}
	// Custom ports take precedence, so NodePort should come from custom ports
	if service.Spec.Ports[0].NodePort != 31000 {
		t.Fatalf("expected nodePort 31000 from custom ports, got %d", service.Spec.Ports[0].NodePort)
	}
}
