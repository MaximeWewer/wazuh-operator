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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

// TCPRouteBuilder builds TCPRoute resources for Gateway API
type TCPRouteBuilder struct {
	name        string
	namespace   string
	clusterName string
	labels      map[string]string
	gatewayRef  *wazuhv1.GatewayReference
	serviceName string
	servicePort int32
	annotations map[string]string
}

// NewTCPRouteBuilder creates a new TCPRouteBuilder
func NewTCPRouteBuilder(name, namespace, clusterName string) *TCPRouteBuilder {
	return &TCPRouteBuilder{
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
func (b *TCPRouteBuilder) WithGatewayRef(ref *wazuhv1.GatewayReference) *TCPRouteBuilder {
	b.gatewayRef = ref
	return b
}

// WithBackendService sets the backend service
func (b *TCPRouteBuilder) WithBackendService(name string, port int32) *TCPRouteBuilder {
	b.serviceName = name
	b.servicePort = port
	return b
}

// WithAnnotations sets additional annotations
func (b *TCPRouteBuilder) WithAnnotations(annotations map[string]string) *TCPRouteBuilder {
	b.annotations = annotations
	return b
}

// WithLabels adds additional labels
func (b *TCPRouteBuilder) WithLabels(labels map[string]string) *TCPRouteBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// Build creates the TCPRoute resource
func (b *TCPRouteBuilder) Build() *gatewayv1alpha2.TCPRoute {
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
	for k, v := range b.annotations {
		allAnnotations[k] = v
	}

	route := &gatewayv1alpha2.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:        b.name,
			Namespace:   b.namespace,
			Labels:      b.labels,
			Annotations: allAnnotations,
		},
		Spec: gatewayv1alpha2.TCPRouteSpec{
			CommonRouteSpec: gatewayv1alpha2.CommonRouteSpec{
				ParentRefs: parentRefs,
			},
			Rules: []gatewayv1alpha2.TCPRouteRule{
				{
					BackendRefs: []gatewayv1alpha2.BackendRef{backendRef},
				},
			},
		},
	}

	return route
}

// BuildAgentEnrollmentTCPRoute creates a TCPRoute for agent enrollment (port 1515)
func BuildAgentEnrollmentTCPRoute(clusterName, namespace string, gatewayAPI *wazuhv1.GatewayAPISpec, isMaster bool) *gatewayv1alpha2.TCPRoute {
	var name, serviceName string
	if isMaster {
		name = fmt.Sprintf("%s-manager-master-enrollment", clusterName)
		serviceName = fmt.Sprintf("%s-manager-master", clusterName)
	} else {
		name = fmt.Sprintf("%s-manager-worker-enrollment", clusterName)
		serviceName = fmt.Sprintf("%s-manager-worker", clusterName)
	}

	builder := NewTCPRouteBuilder(name, namespace, clusterName).
		WithGatewayRef(gatewayAPI.GatewayRef).
		WithBackendService(serviceName, 1515).
		WithLabels(map[string]string{
			"app.kubernetes.io/component": "manager-enrollment",
		})

	if gatewayAPI.TCP != nil && gatewayAPI.TCP.Annotations != nil {
		builder.WithAnnotations(gatewayAPI.TCP.Annotations)
	}

	return builder.Build()
}

// BuildAgentEventsTCPRoute creates a TCPRoute for agent events (port 1514)
func BuildAgentEventsTCPRoute(clusterName, namespace string, gatewayAPI *wazuhv1.GatewayAPISpec, isMaster bool) *gatewayv1alpha2.TCPRoute {
	var name, serviceName string
	if isMaster {
		name = fmt.Sprintf("%s-manager-master-events", clusterName)
		serviceName = fmt.Sprintf("%s-manager-master", clusterName)
	} else {
		name = fmt.Sprintf("%s-manager-worker-events", clusterName)
		serviceName = fmt.Sprintf("%s-manager-worker", clusterName)
	}

	builder := NewTCPRouteBuilder(name, namespace, clusterName).
		WithGatewayRef(gatewayAPI.GatewayRef).
		WithBackendService(serviceName, 1514).
		WithLabels(map[string]string{
			"app.kubernetes.io/component": "manager-events",
		})

	if gatewayAPI.TCP != nil && gatewayAPI.TCP.Annotations != nil {
		builder.WithAnnotations(gatewayAPI.TCP.Annotations)
	}

	return builder.Build()
}

// BuildClusterCommTCPRoute creates a TCPRoute for cluster communication (port 1516)
func BuildClusterCommTCPRoute(clusterName, namespace string, gatewayAPI *wazuhv1.GatewayAPISpec, isMaster bool) *gatewayv1alpha2.TCPRoute {
	var name, serviceName string
	if isMaster {
		name = fmt.Sprintf("%s-manager-master-cluster", clusterName)
		serviceName = fmt.Sprintf("%s-manager-master", clusterName)
	} else {
		name = fmt.Sprintf("%s-manager-worker-cluster", clusterName)
		serviceName = fmt.Sprintf("%s-manager-worker", clusterName)
	}

	builder := NewTCPRouteBuilder(name, namespace, clusterName).
		WithGatewayRef(gatewayAPI.GatewayRef).
		WithBackendService(serviceName, 1516).
		WithLabels(map[string]string{
			"app.kubernetes.io/component": "manager-cluster",
		})

	if gatewayAPI.TCP != nil && gatewayAPI.TCP.Annotations != nil {
		builder.WithAnnotations(gatewayAPI.TCP.Annotations)
	}

	return builder.Build()
}
