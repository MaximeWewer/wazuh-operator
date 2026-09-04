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
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

// HTTPRouteBuilder builds HTTPRoute resources for Gateway API
type HTTPRouteBuilder struct {
	name        string
	namespace   string
	clusterName string
	labels      map[string]string
	gatewayRef  *wazuhv1.GatewayReference
	hostnames   []string
	serviceName string
	servicePort int32
	pathPrefix  string
	annotations map[string]string
}

// NewHTTPRouteBuilder creates a new HTTPRouteBuilder
func NewHTTPRouteBuilder(name, namespace, clusterName string) *HTTPRouteBuilder {
	return &HTTPRouteBuilder{
		name:        name,
		namespace:   namespace,
		clusterName: clusterName,
		labels: map[string]string{
			"app.kubernetes.io/name":       "wazuh",
			"app.kubernetes.io/instance":   clusterName,
			"app.kubernetes.io/managed-by": "wazuh-operator",
			"wazuh.com/cluster":            clusterName,
		},
		pathPrefix: "/",
	}
}

// WithGatewayRef sets the parent Gateway reference
func (b *HTTPRouteBuilder) WithGatewayRef(ref *wazuhv1.GatewayReference) *HTTPRouteBuilder {
	b.gatewayRef = ref
	return b
}

// WithHostnames sets the hostnames for the route
func (b *HTTPRouteBuilder) WithHostnames(hostnames []string) *HTTPRouteBuilder {
	b.hostnames = hostnames
	return b
}

// WithBackendService sets the backend service
func (b *HTTPRouteBuilder) WithBackendService(name string, port int32) *HTTPRouteBuilder {
	b.serviceName = name
	b.servicePort = port
	return b
}

// WithPathPrefix sets the path prefix for matching
func (b *HTTPRouteBuilder) WithPathPrefix(prefix string) *HTTPRouteBuilder {
	b.pathPrefix = prefix
	return b
}

// WithAnnotations sets additional annotations
func (b *HTTPRouteBuilder) WithAnnotations(annotations map[string]string) *HTTPRouteBuilder {
	b.annotations = annotations
	return b
}

// WithLabels adds additional labels
func (b *HTTPRouteBuilder) WithLabels(labels map[string]string) *HTTPRouteBuilder {
	maps.Copy(b.labels, labels)
	return b
}

// Build creates the HTTPRoute resource
func (b *HTTPRouteBuilder) Build() *gatewayv1.HTTPRoute {
	// Build parent references
	var parentRefs []gatewayv1.ParentReference
	if b.gatewayRef != nil {
		parentRef := gatewayv1.ParentReference{
			Name: gatewayv1.ObjectName(b.gatewayRef.Name),
		}
		if b.gatewayRef.Namespace != "" {
			ns := gatewayv1.Namespace(b.gatewayRef.Namespace)
			parentRef.Namespace = &ns
		}
		if b.gatewayRef.SectionName != "" {
			sn := gatewayv1.SectionName(b.gatewayRef.SectionName)
			parentRef.SectionName = &sn
		}
		parentRefs = append(parentRefs, parentRef)
	}

	// Build hostnames
	var hostnames []gatewayv1.Hostname
	for _, h := range b.hostnames {
		hostnames = append(hostnames, gatewayv1.Hostname(h))
	}

	// Build backend reference
	port := b.servicePort
	backendRef := gatewayv1.HTTPBackendRef{
		BackendRef: gatewayv1.BackendRef{
			BackendObjectReference: gatewayv1.BackendObjectReference{
				Name: gatewayv1.ObjectName(b.serviceName),
				Port: &port,
			},
		},
	}

	// Build path match
	pathType := gatewayv1.PathMatchPathPrefix
	pathMatch := gatewayv1.HTTPPathMatch{
		Type:  &pathType,
		Value: &b.pathPrefix,
	}

	// Merge annotations
	allAnnotations := make(map[string]string)
	maps.Copy(allAnnotations, b.annotations)

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:        b.name,
			Namespace:   b.namespace,
			Labels:      b.labels,
			Annotations: allAnnotations,
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: parentRefs,
			},
			Hostnames: hostnames,
			Rules: []gatewayv1.HTTPRouteRule{
				{
					Matches: []gatewayv1.HTTPRouteMatch{
						{
							Path: &pathMatch,
						},
					},
					BackendRefs: []gatewayv1.HTTPBackendRef{backendRef},
				},
			},
		},
	}

	return route
}

// BuildDashboardHTTPRoute creates an HTTPRoute for the Wazuh Dashboard
func BuildDashboardHTTPRoute(clusterName, namespace string, gatewayAPI *wazuhv1.GatewayAPISpec) *gatewayv1.HTTPRoute {
	name := fmt.Sprintf("%s-dashboard", clusterName)
	serviceName := fmt.Sprintf("%s-dashboard", clusterName)

	builder := NewHTTPRouteBuilder(name, namespace, clusterName).
		WithGatewayRef(gatewayAPI.GatewayRef).
		WithHostnames(gatewayAPI.Hostnames).
		WithBackendService(serviceName, 5601).
		WithLabels(map[string]string{
			"app.kubernetes.io/component": "dashboard",
		})

	if gatewayAPI.HTTP != nil {
		if gatewayAPI.HTTP.PathPrefix != "" {
			builder.WithPathPrefix(gatewayAPI.HTTP.PathPrefix)
		}
		if gatewayAPI.HTTP.Annotations != nil {
			builder.WithAnnotations(gatewayAPI.HTTP.Annotations)
		}
	}

	return builder.Build()
}

// BuildManagerAPIHTTPRoute creates an HTTPRoute for the Wazuh Manager API
func BuildManagerAPIHTTPRoute(clusterName, namespace string, gatewayAPI *wazuhv1.GatewayAPISpec, isMaster bool) *gatewayv1.HTTPRoute {
	var name, serviceName string
	if isMaster {
		name = fmt.Sprintf("%s-manager-master-api", clusterName)
		serviceName = fmt.Sprintf("%s-manager-master", clusterName)
	} else {
		name = fmt.Sprintf("%s-manager-worker-api", clusterName)
		serviceName = fmt.Sprintf("%s-manager-worker", clusterName)
	}

	builder := NewHTTPRouteBuilder(name, namespace, clusterName).
		WithGatewayRef(gatewayAPI.GatewayRef).
		WithHostnames(gatewayAPI.Hostnames).
		WithBackendService(serviceName, 55000).
		WithLabels(map[string]string{
			"app.kubernetes.io/component": "manager-api",
		})

	if gatewayAPI.HTTP != nil {
		if gatewayAPI.HTTP.PathPrefix != "" {
			builder.WithPathPrefix(gatewayAPI.HTTP.PathPrefix)
		}
		if gatewayAPI.HTTP.Annotations != nil {
			builder.WithAnnotations(gatewayAPI.HTTP.Annotations)
		}
	}

	return builder.Build()
}

// BuildIndexerHTTPRoute creates an HTTPRoute for the OpenSearch Indexer REST API
func BuildIndexerHTTPRoute(clusterName, namespace string, gatewayAPI *wazuhv1.GatewayAPISpec) *gatewayv1.HTTPRoute {
	name := fmt.Sprintf("%s-indexer", clusterName)
	serviceName := fmt.Sprintf("%s-indexer", clusterName)

	builder := NewHTTPRouteBuilder(name, namespace, clusterName).
		WithGatewayRef(gatewayAPI.GatewayRef).
		WithHostnames(gatewayAPI.Hostnames).
		WithBackendService(serviceName, 9200).
		WithLabels(map[string]string{
			"app.kubernetes.io/component": "indexer",
		})

	if gatewayAPI.HTTP != nil {
		if gatewayAPI.HTTP.PathPrefix != "" {
			builder.WithPathPrefix(gatewayAPI.HTTP.PathPrefix)
		}
		if gatewayAPI.HTTP.Annotations != nil {
			builder.WithAnnotations(gatewayAPI.HTTP.Annotations)
		}
	}

	return builder.Build()
}
