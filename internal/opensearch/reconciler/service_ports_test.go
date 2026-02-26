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

package reconciler

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

func TestConvertServicePorts_Empty(t *testing.T) {
	result := convertServicePorts(nil)
	if result != nil {
		t.Fatalf("expected nil for empty input, got %v", result)
	}

	result = convertServicePorts([]wazuhv1.ServicePortSpec{})
	if result != nil {
		t.Fatalf("expected nil for empty slice, got %v", result)
	}
}

func TestConvertServicePorts_DefaultProtocol(t *testing.T) {
	ports := []wazuhv1.ServicePortSpec{
		{Name: "http", Port: 80},
	}

	result := convertServicePorts(ports)

	if len(result) != 1 {
		t.Fatalf("expected 1 port, got %d", len(result))
	}
	if result[0].Protocol != corev1.ProtocolTCP {
		t.Fatalf("expected protocol TCP, got %v", result[0].Protocol)
	}
}

func TestConvertServicePorts_ExplicitProtocol(t *testing.T) {
	ports := []wazuhv1.ServicePortSpec{
		{Name: "dns", Port: 53, Protocol: corev1.ProtocolUDP},
	}

	result := convertServicePorts(ports)

	if len(result) != 1 {
		t.Fatalf("expected 1 port, got %d", len(result))
	}
	if result[0].Protocol != corev1.ProtocolUDP {
		t.Fatalf("expected protocol UDP, got %v", result[0].Protocol)
	}
}

func TestConvertServicePorts_DefaultTargetPort(t *testing.T) {
	ports := []wazuhv1.ServicePortSpec{
		{Name: "http", Port: 80},
	}

	result := convertServicePorts(ports)

	if result[0].TargetPort.IntVal != 80 {
		t.Fatalf("expected targetPort 80 (same as port), got %d", result[0].TargetPort.IntVal)
	}
}

func TestConvertServicePorts_ExplicitTargetPort(t *testing.T) {
	ports := []wazuhv1.ServicePortSpec{
		{Name: "http", Port: 80, TargetPort: 8080},
	}

	result := convertServicePorts(ports)

	if result[0].TargetPort.IntVal != 8080 {
		t.Fatalf("expected targetPort 8080, got %d", result[0].TargetPort.IntVal)
	}
}

func TestConvertServicePorts_NodePort(t *testing.T) {
	ports := []wazuhv1.ServicePortSpec{
		{Name: "http", Port: 80, NodePort: 30080},
	}

	result := convertServicePorts(ports)

	if result[0].NodePort != 30080 {
		t.Fatalf("expected nodePort 30080, got %d", result[0].NodePort)
	}
}

func TestConvertServicePorts_MultiplePorts(t *testing.T) {
	ports := []wazuhv1.ServicePortSpec{
		{Name: "http", Port: 80, TargetPort: 8080},
		{Name: "https", Port: 443, TargetPort: 8443, Protocol: corev1.ProtocolTCP},
	}

	result := convertServicePorts(ports)

	if len(result) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(result))
	}
	if result[0].Name != "http" || result[0].Port != 80 {
		t.Fatalf("unexpected first port: %+v", result[0])
	}
	if result[1].Name != "https" || result[1].Port != 443 {
		t.Fatalf("unexpected second port: %+v", result[1])
	}
}
