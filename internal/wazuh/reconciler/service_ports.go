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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/builder/services"
)

func convertServicePorts(ports []wazuhv1.ServicePortSpec) []corev1.ServicePort {
	if len(ports) == 0 {
		return nil
	}
	out := make([]corev1.ServicePort, 0, len(ports))
	for _, p := range ports {
		protocol := p.Protocol
		if protocol == "" {
			protocol = corev1.ProtocolTCP
		}
		targetPort := p.TargetPort
		if targetPort == 0 {
			targetPort = p.Port
		}
		out = append(out, corev1.ServicePort{
			Name:       p.Name,
			Port:       p.Port,
			TargetPort: intstr.FromInt(int(targetPort)),
			NodePort:   p.NodePort,
			Protocol:   protocol,
		})
	}
	return out
}

func applyManagerServiceSpec(builder *services.ManagerServiceBuilder, svcSpec *wazuhv1.ServiceSpec) {
	if svcSpec == nil {
		return
	}
	if svcSpec.Type != "" {
		builder.WithServiceType(svcSpec.Type)
	}
	if len(svcSpec.Annotations) > 0 {
		builder.WithAnnotations(svcSpec.Annotations)
	}
	if svcSpec.LoadBalancerIP != "" {
		builder.WithLoadBalancerIP(svcSpec.LoadBalancerIP)
	}
	if len(svcSpec.Ports) > 0 {
		builder.WithPorts(convertServicePorts(svcSpec.Ports))
	}
}

func applyWorkerServiceSpec(builder *services.WorkerServiceBuilder, svcSpec *wazuhv1.ServiceSpec) {
	if svcSpec == nil {
		return
	}
	if svcSpec.Type != "" {
		builder.WithServiceType(svcSpec.Type)
	}
	if len(svcSpec.Annotations) > 0 {
		builder.WithAnnotations(svcSpec.Annotations)
	}
	if len(svcSpec.Ports) > 0 {
		builder.WithPorts(convertServicePorts(svcSpec.Ports))
	}
}
