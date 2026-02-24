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

func TestIndexerServiceBuilder_DefaultPorts(t *testing.T) {
	service := NewIndexerServiceBuilder("test-cluster", "default").Build()

	if len(service.Spec.Ports) != 2 {
		t.Fatalf("expected 2 default ports, got %d", len(service.Spec.Ports))
	}
	if service.Spec.Ports[0].Name != constants.PortNameIndexerREST {
		t.Fatalf("expected port name %q, got %q", constants.PortNameIndexerREST, service.Spec.Ports[0].Name)
	}
	if service.Spec.Ports[0].Port != constants.PortIndexerREST {
		t.Fatalf("expected port %d, got %d", constants.PortIndexerREST, service.Spec.Ports[0].Port)
	}
	if service.Spec.Ports[1].Name != constants.PortNameIndexerTransport {
		t.Fatalf("expected port name %q, got %q", constants.PortNameIndexerTransport, service.Spec.Ports[1].Name)
	}
	if service.Spec.Ports[1].Port != constants.PortIndexerTransport {
		t.Fatalf("expected port %d, got %d", constants.PortIndexerTransport, service.Spec.Ports[1].Port)
	}
}

func TestIndexerServiceBuilder_WithPorts(t *testing.T) {
	customPorts := []corev1.ServicePort{
		{
			Name:       "custom-rest",
			Port:       8200,
			TargetPort: intstr.FromInt(9200),
			Protocol:   corev1.ProtocolTCP,
		},
	}

	service := NewIndexerServiceBuilder("test-cluster", "default").
		WithPorts(customPorts).
		Build()

	if len(service.Spec.Ports) != 1 {
		t.Fatalf("expected 1 port, got %d", len(service.Spec.Ports))
	}
	if service.Spec.Ports[0].Name != "custom-rest" {
		t.Fatalf("expected port name 'custom-rest', got %q", service.Spec.Ports[0].Name)
	}
	if service.Spec.Ports[0].Port != 8200 {
		t.Fatalf("expected port 8200, got %d", service.Spec.Ports[0].Port)
	}
	if service.Spec.Ports[0].TargetPort.IntVal != 9200 {
		t.Fatalf("expected targetPort 9200, got %d", service.Spec.Ports[0].TargetPort.IntVal)
	}
}

func TestIndexerServiceBuilder_HeadlessWithCustomPorts(t *testing.T) {
	customPorts := []corev1.ServicePort{
		{
			Name:       "custom-rest",
			Port:       8200,
			TargetPort: intstr.FromInt(9200),
			Protocol:   corev1.ProtocolTCP,
		},
	}

	builder := NewIndexerServiceBuilder("test-cluster", "default").
		WithPorts(customPorts)

	headless := builder.BuildHeadless()

	if headless.Spec.ClusterIP != corev1.ClusterIPNone {
		t.Fatalf("expected ClusterIP None, got %q", headless.Spec.ClusterIP)
	}
	// Headless appends metrics port to custom ports
	if len(headless.Spec.Ports) != 2 {
		t.Fatalf("expected 2 ports (custom + metrics), got %d", len(headless.Spec.Ports))
	}
	if headless.Spec.Ports[0].Name != "custom-rest" {
		t.Fatalf("expected first port 'custom-rest', got %q", headless.Spec.Ports[0].Name)
	}
	if headless.Spec.Ports[1].Name != constants.PortNameIndexerMetrics {
		t.Fatalf("expected second port %q, got %q", constants.PortNameIndexerMetrics, headless.Spec.Ports[1].Name)
	}
}
