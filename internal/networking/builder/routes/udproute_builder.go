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

package routes

import (
	"fmt"
	"maps"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

// UDPRouteBuilder builds UDPRoute resources for Gateway API
type UDPRouteBuilder struct {
	name        string
	namespace   string
	clusterName string
	labels      map[string]string
	gatewayRef  *wazuhv1.GatewayReference
	serviceName string
	servicePort int32
	annotations map[string]string
}

// NewUDPRouteBuilder creates a new UDPRouteBuilder
func NewUDPRouteBuilder(name, namespace, clusterName string) *UDPRouteBuilder {
	return &UDPRouteBuilder{
		name:        name,
		namespace:   namespace,
		clusterName: clusterName,
		labels: map[string]string{
			"app.kubernetes.io/name":       "wazuh",
			"app.kubernetes.io/instance":   clusterName,
			"app.kubernetes.io/managed-by": "wazuh-operator",
			"wazuh.com/cluster":            clusterName,
		},
	}
}

// WithGatewayRef sets the parent Gateway reference
func (b *UDPRouteBuilder) WithGatewayRef(ref *wazuhv1.GatewayReference) *UDPRouteBuilder {
	b.gatewayRef = ref
	return b
}

// WithBackendService sets the backend service
func (b *UDPRouteBuilder) WithBackendService(name string, port int32) *UDPRouteBuilder {
	b.serviceName = name
	b.servicePort = port
	return b
}

// WithAnnotations sets additional annotations
func (b *UDPRouteBuilder) WithAnnotations(annotations map[string]string) *UDPRouteBuilder {
	b.annotations = annotations
	return b
}

// WithLabels adds additional labels
func (b *UDPRouteBuilder) WithLabels(labels map[string]string) *UDPRouteBuilder {
	maps.Copy(b.labels, labels)
	return b
}

// Build creates the UDPRoute resource
func (b *UDPRouteBuilder) Build() *gatewayv1alpha2.UDPRoute {
	// Build parent references
	var parentRefs []gatewayv1alpha2.ParentReference
	if b.gatewayRef != nil {
		parentRef := gatewayv1alpha2.ParentReference{
			Name: gatewayv1alpha2.ObjectName(b.gatewayRef.Name),
		}
		if b.gatewayRef.Namespace != "" {
			ns := gatewayv1alpha2.Namespace(b.gatewayRef.Namespace)
			parentRef.Namespace = &ns
		}
		if b.gatewayRef.SectionName != "" {
			sn := gatewayv1alpha2.SectionName(b.gatewayRef.SectionName)
			parentRef.SectionName = &sn
		}
		parentRefs = append(parentRefs, parentRef)
	}

	// Build backend reference
	port := b.servicePort
	backendRef := gatewayv1alpha2.BackendRef{
		BackendObjectReference: gatewayv1alpha2.BackendObjectReference{
			Name: gatewayv1alpha2.ObjectName(b.serviceName),
			Port: &port,
		},
	}

	// Merge annotations
	allAnnotations := make(map[string]string)
	maps.Copy(allAnnotations, b.annotations)

	route := &gatewayv1alpha2.UDPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:        b.name,
			Namespace:   b.namespace,
			Labels:      b.labels,
			Annotations: allAnnotations,
		},
		Spec: gatewayv1alpha2.UDPRouteSpec{
			CommonRouteSpec: gatewayv1alpha2.CommonRouteSpec{
				ParentRefs: parentRefs,
			},
			Rules: []gatewayv1alpha2.UDPRouteRule{
				{
					BackendRefs: []gatewayv1alpha2.BackendRef{backendRef},
				},
			},
		},
	}

	return route
}

// BuildSyslogUDPRoute creates a UDPRoute for syslog ingestion (default port 514)
func BuildSyslogUDPRoute(clusterName, namespace string, gatewayAPI *wazuhv1.GatewayAPISpec, isMaster bool) *gatewayv1alpha2.UDPRoute {
	var name, serviceName string
	if isMaster {
		name = fmt.Sprintf("%s-manager-master-syslog", clusterName)
		serviceName = fmt.Sprintf("%s-manager-master", clusterName)
	} else {
		name = fmt.Sprintf("%s-manager-worker-syslog", clusterName)
		serviceName = fmt.Sprintf("%s-manager-worker", clusterName)
	}

	// Default syslog port is 514
	port := int32(514)
	if gatewayAPI.UDP != nil && gatewayAPI.UDP.SyslogPort > 0 {
		port = gatewayAPI.UDP.SyslogPort
	}

	builder := NewUDPRouteBuilder(name, namespace, clusterName).
		WithGatewayRef(gatewayAPI.GatewayRef).
		WithBackendService(serviceName, port).
		WithLabels(map[string]string{
			"app.kubernetes.io/component": "manager-syslog",
		})

	if gatewayAPI.UDP != nil && gatewayAPI.UDP.Annotations != nil {
		builder.WithAnnotations(gatewayAPI.UDP.Annotations)
	}

	return builder.Build()
}
