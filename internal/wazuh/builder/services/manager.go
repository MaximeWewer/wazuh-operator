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

// Package services provides Kubernetes Service builders for Wazuh components
package services

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// ManagerServiceBuilder builds Services for Wazuh Manager
type ManagerServiceBuilder struct {
	name           string
	namespace      string
	clusterName    string
	version        string
	nodeType       string // "master" or "worker"
	serviceType    corev1.ServiceType
	headless       bool
	labels         map[string]string
	annotations    map[string]string
	loadBalancerIP string
}

// NewManagerServiceBuilder creates a new ManagerServiceBuilder
func NewManagerServiceBuilder(clusterName, namespace, nodeType string) *ManagerServiceBuilder {
	name := fmt.Sprintf("%s-manager-%s", clusterName, nodeType)
	return &ManagerServiceBuilder{
		name:        name,
		namespace:   namespace,
		clusterName: clusterName,
		version:     constants.DefaultWazuhVersion,
		nodeType:    nodeType,
		serviceType: corev1.ServiceTypeClusterIP,
		headless:    false,
		labels:      make(map[string]string),
		annotations: make(map[string]string),
	}
}

// WithVersion sets the Wazuh version
func (b *ManagerServiceBuilder) WithVersion(version string) *ManagerServiceBuilder {
	b.version = version
	return b
}

// WithServiceType sets the service type
func (b *ManagerServiceBuilder) WithServiceType(serviceType corev1.ServiceType) *ManagerServiceBuilder {
	b.serviceType = serviceType
	return b
}

// WithHeadless makes this a headless service
func (b *ManagerServiceBuilder) WithHeadless(headless bool) *ManagerServiceBuilder {
	b.headless = headless
	return b
}

// WithLabels adds custom labels
func (b *ManagerServiceBuilder) WithLabels(labels map[string]string) *ManagerServiceBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations adds custom annotations
func (b *ManagerServiceBuilder) WithAnnotations(annotations map[string]string) *ManagerServiceBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// WithLoadBalancerIP sets the load balancer IP
func (b *ManagerServiceBuilder) WithLoadBalancerIP(ip string) *ManagerServiceBuilder {
	b.loadBalancerIP = ip
	return b
}

// Build creates the Service
func (b *ManagerServiceBuilder) Build() *corev1.Service {
	labels := b.buildLabels()
	selectorLabels := b.buildSelectorLabels()

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
			Ports: []corev1.ServicePort{
				{
					Name:       constants.PortNameManagerAPI,
					Port:       constants.PortManagerAPI,
					TargetPort: intstr.FromInt(int(constants.PortManagerAPI)),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       constants.PortNameManagerAgentEvents,
					Port:       constants.PortManagerAgentEvents,
					TargetPort: intstr.FromInt(int(constants.PortManagerAgentEvents)),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       constants.PortNameManagerAgentAuth,
					Port:       constants.PortManagerAgentAuth,
					TargetPort: intstr.FromInt(int(constants.PortManagerAgentAuth)),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       constants.PortNameManagerCluster,
					Port:       constants.PortManagerCluster,
					TargetPort: intstr.FromInt(int(constants.PortManagerCluster)),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	// Handle headless service
	if b.headless {
		svc.Spec.ClusterIP = corev1.ClusterIPNone
	}

	// Handle LoadBalancer IP
	if b.serviceType == corev1.ServiceTypeLoadBalancer && b.loadBalancerIP != "" {
		svc.Spec.LoadBalancerIP = b.loadBalancerIP
	}

	return svc
}

// BuildHeadless creates a headless Service for StatefulSet
func (b *ManagerServiceBuilder) BuildHeadless() *corev1.Service {
	b.headless = true
	svc := b.Build()
	// Headless services for StatefulSets typically have a different name
	svc.Name = b.name + "-headless"
	return svc
}

// buildLabels builds the complete label set
func (b *ManagerServiceBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, "wazuh-manager", b.version)
	labels[constants.LabelManagerNodeType] = b.nodeType
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}

// buildSelectorLabels builds the selector labels
func (b *ManagerServiceBuilder) buildSelectorLabels() map[string]string {
	labels := constants.SelectorLabels(b.clusterName, "wazuh-manager")
	labels[constants.LabelManagerNodeType] = b.nodeType
	return labels
}

// ManagerExternalServiceBuilder builds external access services for Wazuh Manager
type ManagerExternalServiceBuilder struct {
	name         string
	namespace    string
	clusterName  string
	version      string
	serviceType  corev1.ServiceType
	labels       map[string]string
	annotations  map[string]string
	nodePorts    map[string]int32
	exposedPorts []string // Which ports to expose externally
}

// NewManagerExternalServiceBuilder creates a new ManagerExternalServiceBuilder
func NewManagerExternalServiceBuilder(clusterName, namespace string) *ManagerExternalServiceBuilder {
	name := fmt.Sprintf("%s-manager-external", clusterName)
	return &ManagerExternalServiceBuilder{
		name:         name,
		namespace:    namespace,
		clusterName:  clusterName,
		version:      constants.DefaultWazuhVersion,
		serviceType:  corev1.ServiceTypeLoadBalancer,
		labels:       make(map[string]string),
		annotations:  make(map[string]string),
		nodePorts:    make(map[string]int32),
		exposedPorts: []string{"api", "agents", "registration"},
	}
}

// WithServiceType sets the service type
func (b *ManagerExternalServiceBuilder) WithServiceType(serviceType corev1.ServiceType) *ManagerExternalServiceBuilder {
	b.serviceType = serviceType
	return b
}

// WithNodePort sets a node port for a specific service port
func (b *ManagerExternalServiceBuilder) WithNodePort(portName string, nodePort int32) *ManagerExternalServiceBuilder {
	b.nodePorts[portName] = nodePort
	return b
}

// WithExposedPorts sets which ports to expose
func (b *ManagerExternalServiceBuilder) WithExposedPorts(ports []string) *ManagerExternalServiceBuilder {
	b.exposedPorts = ports
	return b
}

// WithAnnotations adds custom annotations
func (b *ManagerExternalServiceBuilder) WithAnnotations(annotations map[string]string) *ManagerExternalServiceBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// Build creates the external Service
func (b *ManagerExternalServiceBuilder) Build() *corev1.Service {
	labels := constants.CommonLabels(b.clusterName, "wazuh-manager", b.version)
	for k, v := range b.labels {
		labels[k] = v
	}

	selectorLabels := constants.SelectorLabels(b.clusterName, "wazuh-manager")
	// Select only master for external access
	selectorLabels[constants.LabelManagerNodeType] = "master"

	var ports []corev1.ServicePort

	for _, portName := range b.exposedPorts {
		var port corev1.ServicePort
		switch portName {
		case "api":
			port = corev1.ServicePort{
				Name:       constants.PortNameManagerAPI,
				Port:       constants.PortManagerAPI,
				TargetPort: intstr.FromInt(int(constants.PortManagerAPI)),
				Protocol:   corev1.ProtocolTCP,
			}
		case "agents":
			port = corev1.ServicePort{
				Name:       constants.PortNameManagerAgentEvents,
				Port:       constants.PortManagerAgentEvents,
				TargetPort: intstr.FromInt(int(constants.PortManagerAgentEvents)),
				Protocol:   corev1.ProtocolTCP,
			}
		case "registration":
			port = corev1.ServicePort{
				Name:       constants.PortNameManagerAgentAuth,
				Port:       constants.PortManagerAgentAuth,
				TargetPort: intstr.FromInt(int(constants.PortManagerAgentAuth)),
				Protocol:   corev1.ProtocolTCP,
			}
		}

		// Set node port if specified
		if nodePort, ok := b.nodePorts[portName]; ok {
			port.NodePort = nodePort
		}

		ports = append(ports, port)
	}

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        b.name,
			Namespace:   b.namespace,
			Labels:      labels,
			Annotations: b.annotations,
		},
		Spec: corev1.ServiceSpec{
			Type:     b.serviceType,
			Selector: selectorLabels,
			Ports:    ports,
		},
	}
}
