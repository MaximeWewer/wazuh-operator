package reconciler

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

func TestConvertServicePorts_Defaulting(t *testing.T) {
	input := []wazuhv1.ServicePortSpec{
		{
			Name: "api",
			Port: 55000,
		},
	}

	got := convertServicePorts(input)
	if len(got) != 1 {
		t.Fatalf("expected 1 converted port, got %d", len(got))
	}

	if got[0].Protocol != corev1.ProtocolTCP {
		t.Fatalf("expected default protocol TCP, got %s", got[0].Protocol)
	}
	if got[0].TargetPort.IntVal != 55000 {
		t.Fatalf("expected targetPort to default to port (55000), got %d", got[0].TargetPort.IntVal)
	}
}
