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

func TestWorkerServiceBuilder_WithPorts(t *testing.T) {
	builder := NewWorkerServiceBuilder("test-cluster", "default")
	customPorts := []corev1.ServicePort{
		{
			Name:       "cluster",
			Port:       1516,
			TargetPort: intstr.FromInt(1516),
			Protocol:   corev1.ProtocolTCP,
		},
	}

	service := builder.WithPorts(customPorts).Build()

	if len(service.Spec.Ports) != 1 {
		t.Fatalf("expected 1 port, got %d", len(service.Spec.Ports))
	}
	if service.Spec.Ports[0].Name != "cluster" {
		t.Fatalf("expected port name 'cluster', got %q", service.Spec.Ports[0].Name)
	}
	if service.Spec.Ports[0].Port != 1516 {
		t.Fatalf("expected port 1516, got %d", service.Spec.Ports[0].Port)
	}
	if service.Spec.Ports[0].TargetPort.IntVal != 1516 {
		t.Fatalf("expected targetPort 1516, got %d", service.Spec.Ports[0].TargetPort.IntVal)
	}
}

func TestWorkerServiceBuilder_DefaultPortsFallback(t *testing.T) {
	service := NewWorkerServiceBuilder("test-cluster", "default").Build()

	if len(service.Spec.Ports) != 3 {
		t.Fatalf("expected 3 default ports, got %d", len(service.Spec.Ports))
	}

	expectedNames := []string{
		constants.PortNameManagerAPI,
		constants.PortNameManagerAgentEvents,
		constants.PortNameManagerCluster,
	}
	for i, p := range service.Spec.Ports {
		if p.Name != expectedNames[i] {
			t.Fatalf("expected port[%d] name %q, got %q", i, expectedNames[i], p.Name)
		}
	}
}
