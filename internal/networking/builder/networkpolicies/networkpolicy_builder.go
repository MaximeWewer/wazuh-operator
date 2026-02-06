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

package networkpolicies

import (
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// BuildIndexerNetworkPolicy builds a NetworkPolicy for the Indexer component
// Default rules: allow ingress from indexer/manager/dashboard pods on 9200,9300,9600
// Egress: DNS + indexer peers
func BuildIndexerNetworkPolicy(clusterName, namespace string, spec *wazuhv1.NetworkPolicySpec) *networkingv1.NetworkPolicy {
	tcp := corev1.ProtocolTCP
	udp := corev1.ProtocolUDP
	portREST := intstr.FromInt(int(constants.PortIndexerREST))
	portTransport := intstr.FromInt(int(constants.PortIndexerTransport))
	portMetrics := intstr.FromInt(int(constants.PortIndexerMetrics))
	portDNS := intstr.FromInt(53)

	selectorLabels := constants.SelectorLabels(clusterName, constants.ComponentIndexer)

	ingress := []networkingv1.NetworkPolicyIngressRule{
		{
			// Allow from indexer, manager, and dashboard pods
			From: []networkingv1.NetworkPolicyPeer{
				{PodSelector: &metav1.LabelSelector{MatchLabels: constants.SelectorLabels(clusterName, constants.ComponentIndexer)}},
				{PodSelector: &metav1.LabelSelector{MatchLabels: constants.SelectorLabels(clusterName, constants.ComponentManager)}},
				{PodSelector: &metav1.LabelSelector{MatchLabels: constants.SelectorLabels(clusterName, constants.ComponentDashboard)}},
			},
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &tcp, Port: &portREST},
				{Protocol: &tcp, Port: &portTransport},
				{Protocol: &tcp, Port: &portMetrics},
			},
		},
	}

	egress := []networkingv1.NetworkPolicyEgressRule{
		{
			// DNS
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &tcp, Port: &portDNS},
				{Protocol: &udp, Port: &portDNS},
			},
		},
		{
			// Indexer peers (transport + REST)
			To: []networkingv1.NetworkPolicyPeer{
				{PodSelector: &metav1.LabelSelector{MatchLabels: constants.SelectorLabels(clusterName, constants.ComponentIndexer)}},
			},
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &tcp, Port: &portREST},
				{Protocol: &tcp, Port: &portTransport},
			},
		},
	}

	// Append user-defined rules
	ingress = append(ingress, convertIngressRules(spec.Ingress)...)
	egress = append(egress, convertEgressRules(spec.Egress)...)

	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterName + "-indexer",
			Namespace: namespace,
			Labels:    constants.CommonLabels(clusterName, constants.ComponentIndexer, ""),
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: selectorLabels},
			Ingress:     ingress,
			Egress:      egress,
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
		},
	}
}

// BuildManagerNetworkPolicy builds a NetworkPolicy for the Manager component
// Default rules: ingress from managers/dashboard on cluster/API/agent ports
// Egress: DNS + indexer + manager peers
func BuildManagerNetworkPolicy(clusterName, namespace string, spec *wazuhv1.NetworkPolicySpec) *networkingv1.NetworkPolicy {
	tcp := corev1.ProtocolTCP
	udp := corev1.ProtocolUDP
	portAPI := intstr.FromInt(int(constants.PortManagerAPI))
	portAgentEvents := intstr.FromInt(int(constants.PortManagerAgentEvents))
	portAgentAuth := intstr.FromInt(int(constants.PortManagerAgentAuth))
	portCluster := intstr.FromInt(int(constants.PortManagerCluster))
	portIndexerREST := intstr.FromInt(int(constants.PortIndexerREST))
	portDNS := intstr.FromInt(53)

	selectorLabels := constants.SelectorLabels(clusterName, constants.ComponentManager)

	ingress := []networkingv1.NetworkPolicyIngressRule{
		{
			// Allow from manager peers and dashboard
			From: []networkingv1.NetworkPolicyPeer{
				{PodSelector: &metav1.LabelSelector{MatchLabels: constants.SelectorLabels(clusterName, constants.ComponentManager)}},
				{PodSelector: &metav1.LabelSelector{MatchLabels: constants.SelectorLabels(clusterName, constants.ComponentDashboard)}},
			},
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &tcp, Port: &portAPI},
				{Protocol: &tcp, Port: &portCluster},
			},
		},
		{
			// Allow agent connections from any source
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &tcp, Port: &portAgentEvents},
				{Protocol: &tcp, Port: &portAgentAuth},
			},
		},
	}

	egress := []networkingv1.NetworkPolicyEgressRule{
		{
			// DNS
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &tcp, Port: &portDNS},
				{Protocol: &udp, Port: &portDNS},
			},
		},
		{
			// Indexer REST
			To: []networkingv1.NetworkPolicyPeer{
				{PodSelector: &metav1.LabelSelector{MatchLabels: constants.SelectorLabels(clusterName, constants.ComponentIndexer)}},
			},
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &tcp, Port: &portIndexerREST},
			},
		},
		{
			// Manager peers (cluster + API)
			To: []networkingv1.NetworkPolicyPeer{
				{PodSelector: &metav1.LabelSelector{MatchLabels: constants.SelectorLabels(clusterName, constants.ComponentManager)}},
			},
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &tcp, Port: &portCluster},
				{Protocol: &tcp, Port: &portAPI},
			},
		},
	}

	// Append user-defined rules
	ingress = append(ingress, convertIngressRules(spec.Ingress)...)
	egress = append(egress, convertEgressRules(spec.Egress)...)

	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterName + "-manager",
			Namespace: namespace,
			Labels:    constants.CommonLabels(clusterName, constants.ComponentManager, ""),
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: selectorLabels},
			Ingress:     ingress,
			Egress:      egress,
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
		},
	}
}

// BuildDashboardNetworkPolicy builds a NetworkPolicy for the Dashboard component
// Default rules: ingress on 5601, egress to DNS + indexer 9200 + manager API 55000
func BuildDashboardNetworkPolicy(clusterName, namespace string, spec *wazuhv1.NetworkPolicySpec) *networkingv1.NetworkPolicy {
	tcp := corev1.ProtocolTCP
	udp := corev1.ProtocolUDP
	portDashboard := intstr.FromInt(int(constants.PortDashboardHTTP))
	portIndexerREST := intstr.FromInt(int(constants.PortIndexerREST))
	portManagerAPI := intstr.FromInt(int(constants.PortManagerAPI))
	portDNS := intstr.FromInt(53)

	selectorLabels := constants.SelectorLabels(clusterName, constants.ComponentDashboard)

	ingress := []networkingv1.NetworkPolicyIngressRule{
		{
			// Allow ingress on dashboard port from any source
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &tcp, Port: &portDashboard},
			},
		},
	}

	egress := []networkingv1.NetworkPolicyEgressRule{
		{
			// DNS
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &tcp, Port: &portDNS},
				{Protocol: &udp, Port: &portDNS},
			},
		},
		{
			// Indexer REST
			To: []networkingv1.NetworkPolicyPeer{
				{PodSelector: &metav1.LabelSelector{MatchLabels: constants.SelectorLabels(clusterName, constants.ComponentIndexer)}},
			},
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &tcp, Port: &portIndexerREST},
			},
		},
		{
			// Manager API
			To: []networkingv1.NetworkPolicyPeer{
				{PodSelector: &metav1.LabelSelector{MatchLabels: constants.SelectorLabels(clusterName, constants.ComponentManager)}},
			},
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &tcp, Port: &portManagerAPI},
			},
		},
	}

	// Append user-defined rules
	ingress = append(ingress, convertIngressRules(spec.Ingress)...)
	egress = append(egress, convertEgressRules(spec.Egress)...)

	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterName + "-dashboard",
			Namespace: namespace,
			Labels:    constants.CommonLabels(clusterName, constants.ComponentDashboard, ""),
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: selectorLabels},
			Ingress:     ingress,
			Egress:      egress,
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
		},
	}
}

// convertIngressRules converts CRD ingress rules to Kubernetes NetworkPolicy ingress rules
func convertIngressRules(rules []wazuhv1.NetworkPolicyIngressRule) []networkingv1.NetworkPolicyIngressRule {
	var result []networkingv1.NetworkPolicyIngressRule
	for _, rule := range rules {
		var peers []networkingv1.NetworkPolicyPeer
		for _, from := range rule.From {
			peers = append(peers, networkingv1.NetworkPolicyPeer{
				PodSelector:       from.PodSelector,
				NamespaceSelector: from.NamespaceSelector,
			})
		}
		var ports []networkingv1.NetworkPolicyPort
		for _, port := range rule.Ports {
			np := networkingv1.NetworkPolicyPort{Protocol: port.Protocol}
			if port.Port != nil {
				p := intstr.FromInt(int(*port.Port))
				np.Port = &p
			}
			ports = append(ports, np)
		}
		result = append(result, networkingv1.NetworkPolicyIngressRule{
			From:  peers,
			Ports: ports,
		})
	}
	return result
}

// convertEgressRules converts CRD egress rules to Kubernetes NetworkPolicy egress rules
func convertEgressRules(rules []wazuhv1.NetworkPolicyEgressRule) []networkingv1.NetworkPolicyEgressRule {
	var result []networkingv1.NetworkPolicyEgressRule
	for _, rule := range rules {
		var peers []networkingv1.NetworkPolicyPeer
		for _, to := range rule.To {
			peers = append(peers, networkingv1.NetworkPolicyPeer{
				PodSelector:       to.PodSelector,
				NamespaceSelector: to.NamespaceSelector,
			})
		}
		var ports []networkingv1.NetworkPolicyPort
		for _, port := range rule.Ports {
			np := networkingv1.NetworkPolicyPort{Protocol: port.Protocol}
			if port.Port != nil {
				p := intstr.FromInt(int(*port.Port))
				np.Port = &p
			}
			ports = append(ports, np)
		}
		result = append(result, networkingv1.NetworkPolicyEgressRule{
			To:    peers,
			Ports: ports,
		})
	}
	return result
}
