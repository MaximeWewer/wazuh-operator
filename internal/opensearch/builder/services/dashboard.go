/*
Copyright 2025.

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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// DashboardServiceBuilder builds Services for OpenSearch Dashboard
type DashboardServiceBuilder struct {
	name           string
	namespace      string
	clusterName    string
	version        string
	serviceType    corev1.ServiceType
	labels         map[string]string
	annotations    map[string]string
	loadBalancerIP string
	nodePort       int32
}

// NewDashboardServiceBuilder creates a new DashboardServiceBuilder
func NewDashboardServiceBuilder(clusterName, namespace string) *DashboardServiceBuilder {
	return &DashboardServiceBuilder{
		name:        constants.DashboardName(clusterName),
		namespace:   namespace,
		clusterName: clusterName,
		version:     constants.DefaultWazuhVersion,
		serviceType: corev1.ServiceTypeClusterIP,
		labels:      make(map[string]string),
		annotations: make(map[string]string),
	}
}

// WithVersion sets the OpenSearch version
func (b *DashboardServiceBuilder) WithVersion(version string) *DashboardServiceBuilder {
	b.version = version
	return b
}

// WithServiceType sets the service type
func (b *DashboardServiceBuilder) WithServiceType(serviceType corev1.ServiceType) *DashboardServiceBuilder {
	b.serviceType = serviceType
	return b
}

// WithLabels adds custom labels
func (b *DashboardServiceBuilder) WithLabels(labels map[string]string) *DashboardServiceBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations adds custom annotations
func (b *DashboardServiceBuilder) WithAnnotations(annotations map[string]string) *DashboardServiceBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// WithLoadBalancerIP sets the load balancer IP
func (b *DashboardServiceBuilder) WithLoadBalancerIP(ip string) *DashboardServiceBuilder {
	b.loadBalancerIP = ip
	return b
}

// WithNodePort sets the node port
func (b *DashboardServiceBuilder) WithNodePort(nodePort int32) *DashboardServiceBuilder {
	b.nodePort = nodePort
	return b
}

// Build creates the Service
func (b *DashboardServiceBuilder) Build() *corev1.Service {
	labels := b.buildLabels()
	selectorLabels := b.buildSelectorLabels()

	port := corev1.ServicePort{
		Name:       constants.PortNameDashboardHTTP,
		Port:       constants.PortDashboardHTTP,
		TargetPort: intstr.FromInt(int(constants.PortDashboardHTTP)),
		Protocol:   corev1.ProtocolTCP,
	}

	// Set node port if specified and service type is NodePort or LoadBalancer
	if b.nodePort > 0 && (b.serviceType == corev1.ServiceTypeNodePort || b.serviceType == corev1.ServiceTypeLoadBalancer) {
		port.NodePort = b.nodePort
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        b.name,
			Namespace:   b.namespace,
			Labels:      labels,
			Annotations: b.annotations,
		},
		Spec: corev1.ServiceSpec{
			Type:     b.serviceType,
			Selector: selectorLabels,
			Ports:    []corev1.ServicePort{port},
		},
	}

	// Handle LoadBalancer IP
	if b.serviceType == corev1.ServiceTypeLoadBalancer && b.loadBalancerIP != "" {
		svc.Spec.LoadBalancerIP = b.loadBalancerIP
	}

	return svc
}

// buildLabels builds the complete label set
func (b *DashboardServiceBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, constants.ComponentDashboard, b.version)
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}

// buildSelectorLabels builds the selector labels
func (b *DashboardServiceBuilder) buildSelectorLabels() map[string]string {
	return constants.SelectorLabels(b.clusterName, constants.ComponentDashboard)
}
