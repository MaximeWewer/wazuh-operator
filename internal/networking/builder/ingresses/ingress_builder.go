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

package ingresses

import (
	"fmt"
	"maps"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

// IngressBuilder builds networkingv1.Ingress resources
type IngressBuilder struct {
	name             string
	namespace        string
	clusterName      string
	labels           map[string]string
	annotations      map[string]string
	ingressClassName string
	hosts            []wazuhv1.IngressHost
	tls              []wazuhv1.IngressTLS
	serviceName      string
	servicePort      int32
}

// NewIngressBuilder creates a new IngressBuilder
func NewIngressBuilder(name, namespace, clusterName string) *IngressBuilder {
	return &IngressBuilder{
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

// WithIngressClassName sets the ingress class name
func (b *IngressBuilder) WithIngressClassName(className string) *IngressBuilder {
	b.ingressClassName = className
	return b
}

// WithAnnotations sets the annotations
func (b *IngressBuilder) WithAnnotations(annotations map[string]string) *IngressBuilder {
	b.annotations = annotations
	return b
}

// WithHosts sets the hosts configuration
func (b *IngressBuilder) WithHosts(hosts []wazuhv1.IngressHost) *IngressBuilder {
	b.hosts = hosts
	return b
}

// WithTLS sets the TLS configuration
func (b *IngressBuilder) WithTLS(tls []wazuhv1.IngressTLS) *IngressBuilder {
	b.tls = tls
	return b
}

// WithBackendService sets the default backend service
func (b *IngressBuilder) WithBackendService(name string, port int32) *IngressBuilder {
	b.serviceName = name
	b.servicePort = port
	return b
}

// WithLabels adds additional labels
func (b *IngressBuilder) WithLabels(labels map[string]string) *IngressBuilder {
	maps.Copy(b.labels, labels)
	return b
}

// Build creates the networkingv1.Ingress resource
func (b *IngressBuilder) Build() *networkingv1.Ingress {
	// Build ingress rules from hosts
	var rules []networkingv1.IngressRule
	for _, host := range b.hosts {
		var paths []networkingv1.HTTPIngressPath
		for _, p := range host.Paths {
			pathType := networkingv1.PathTypePrefix
			if p.PathType != "" {
				pathType = networkingv1.PathType(p.PathType)
			}
			path := p.Path
			if path == "" {
				path = "/"
			}
			paths = append(paths, networkingv1.HTTPIngressPath{
				Path:     path,
				PathType: &pathType,
				Backend: networkingv1.IngressBackend{
					Service: &networkingv1.IngressServiceBackend{
						Name: b.serviceName,
						Port: networkingv1.ServiceBackendPort{
							Number: b.servicePort,
						},
					},
				},
			})
		}

		// If no paths specified, add a default "/" path
		if len(paths) == 0 {
			pathType := networkingv1.PathTypePrefix
			paths = append(paths, networkingv1.HTTPIngressPath{
				Path:     "/",
				PathType: &pathType,
				Backend: networkingv1.IngressBackend{
					Service: &networkingv1.IngressServiceBackend{
						Name: b.serviceName,
						Port: networkingv1.ServiceBackendPort{
							Number: b.servicePort,
						},
					},
				},
			})
		}

		rules = append(rules, networkingv1.IngressRule{
			Host: host.Host,
			IngressRuleValue: networkingv1.IngressRuleValue{
				HTTP: &networkingv1.HTTPIngressRuleValue{
					Paths: paths,
				},
			},
		})
	}

	// Build TLS from spec
	var tlsConfig []networkingv1.IngressTLS
	for _, t := range b.tls {
		tlsConfig = append(tlsConfig, networkingv1.IngressTLS{
			Hosts:      t.Hosts,
			SecretName: t.SecretName,
		})
	}

	// Merge annotations
	allAnnotations := make(map[string]string)
	maps.Copy(allAnnotations, b.annotations)

	// Build ingress spec
	spec := networkingv1.IngressSpec{
		Rules: rules,
		TLS:   tlsConfig,
	}
	if b.ingressClassName != "" {
		spec.IngressClassName = &b.ingressClassName
	}

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        b.name,
			Namespace:   b.namespace,
			Labels:      b.labels,
			Annotations: allAnnotations,
		},
		Spec: spec,
	}

	return ingress
}

// BuildDashboardIngress creates an Ingress for the Wazuh Dashboard
func BuildDashboardIngress(clusterName, namespace string, ingressSpec *wazuhv1.IngressSpec) *networkingv1.Ingress {
	name := fmt.Sprintf("%s-dashboard", clusterName)
	serviceName := fmt.Sprintf("%s-dashboard", clusterName)

	return NewIngressBuilder(name, namespace, clusterName).
		WithIngressClassName(ingressSpec.IngressClassName).
		WithAnnotations(ingressSpec.Annotations).
		WithHosts(ingressSpec.Hosts).
		WithTLS(ingressSpec.TLS).
		WithBackendService(serviceName, 5601).
		WithLabels(map[string]string{
			"app.kubernetes.io/component": "dashboard",
		}).
		Build()
}

// BuildManagerMasterIngress creates an Ingress for the Wazuh Manager Master API
func BuildManagerMasterIngress(clusterName, namespace string, ingressSpec *wazuhv1.IngressSpec) *networkingv1.Ingress {
	name := fmt.Sprintf("%s-manager-master", clusterName)
	serviceName := fmt.Sprintf("%s-manager-master", clusterName)

	return NewIngressBuilder(name, namespace, clusterName).
		WithIngressClassName(ingressSpec.IngressClassName).
		WithAnnotations(ingressSpec.Annotations).
		WithHosts(ingressSpec.Hosts).
		WithTLS(ingressSpec.TLS).
		WithBackendService(serviceName, 55000).
		WithLabels(map[string]string{
			"app.kubernetes.io/component": "manager-master",
		}).
		Build()
}

// BuildManagerWorkersIngress creates an Ingress for the Wazuh Manager Workers API
func BuildManagerWorkersIngress(clusterName, namespace string, ingressSpec *wazuhv1.IngressSpec) *networkingv1.Ingress {
	name := fmt.Sprintf("%s-manager-workers", clusterName)
	serviceName := fmt.Sprintf("%s-manager-worker", clusterName)

	return NewIngressBuilder(name, namespace, clusterName).
		WithIngressClassName(ingressSpec.IngressClassName).
		WithAnnotations(ingressSpec.Annotations).
		WithHosts(ingressSpec.Hosts).
		WithTLS(ingressSpec.TLS).
		WithBackendService(serviceName, 55000).
		WithLabels(map[string]string{
			"app.kubernetes.io/component": "manager-workers",
		}).
		Build()
}

// BuildIndexerIngress creates an Ingress for the OpenSearch Indexer REST API
func BuildIndexerIngress(clusterName, namespace string, ingressSpec *wazuhv1.IngressSpec) *networkingv1.Ingress {
	name := fmt.Sprintf("%s-indexer", clusterName)
	serviceName := fmt.Sprintf("%s-indexer", clusterName)

	return NewIngressBuilder(name, namespace, clusterName).
		WithIngressClassName(ingressSpec.IngressClassName).
		WithAnnotations(ingressSpec.Annotations).
		WithHosts(ingressSpec.Hosts).
		WithTLS(ingressSpec.TLS).
		WithBackendService(serviceName, 9200).
		WithLabels(map[string]string{
			"app.kubernetes.io/component": "indexer",
		}).
		Build()
}
