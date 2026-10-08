package networkpolicies

import (
	"testing"

	networkingv1 "k8s.io/api/networking/v1"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// operatorAllowedOn reports whether np lets the operator namespace reach port.
func operatorAllowedOn(np *networkingv1.NetworkPolicy, operatorNamespace string, port int) bool {
	for _, rule := range np.Spec.Ingress {
		nsOK := false
		for _, peer := range rule.From {
			if peer.NamespaceSelector != nil && peer.PodSelector == nil &&
				peer.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] == operatorNamespace {
				nsOK = true
			}
		}
		if !nsOK {
			continue
		}
		for _, p := range rule.Ports {
			if p.Port != nil && p.Port.IntValue() == port {
				return true
			}
		}
	}
	return false
}

// TestNetworkPoliciesAllowOperator guards operator access under an enforcing CNI: the
// operator drives the indexer REST API and the manager API from its own namespace, which
// the same-namespace pod selectors do not cover.
func TestNetworkPoliciesAllowOperator(t *testing.T) {
	spec := &wazuhv1.NetworkPolicySpec{Enabled: true}
	idx := BuildIndexerNetworkPolicy("c", "wazuh", "wazuh-operator", spec)
	if !operatorAllowedOn(idx, "wazuh-operator", int(constants.PortIndexerREST)) {
		t.Error("indexer policy does not let the operator reach the REST API")
	}
	mgr := BuildManagerNetworkPolicy("c", "wazuh", "wazuh-operator", spec)
	if !operatorAllowedOn(mgr, "wazuh-operator", int(constants.PortManagerAPI)) {
		t.Error("manager policy does not let the operator reach the Wazuh API")
	}
	if operatorAllowedOn(mgr, "wazuh-operator", int(constants.PortManagerCluster)) {
		t.Error("the operator must not be granted the manager cluster port")
	}
	if n := len(BuildIndexerNetworkPolicy("c", "wazuh", "", spec).Spec.Ingress); n != 1 {
		t.Errorf("unknown operator namespace must not add a rule, got %d ingress rules", n)
	}
}

// internetEgressAllowed reports whether np allows TCP port to any destination.
func internetEgressAllowed(np *networkingv1.NetworkPolicy, port int) bool {
	for _, rule := range np.Spec.Egress {
		if len(rule.To) != 0 {
			continue
		}
		for _, p := range rule.Ports {
			if p.Port != nil && p.Port.IntValue() == port {
				return true
			}
		}
	}
	return false
}

// TestNetworkPoliciesInternetEgress guards the egress verified under Calico: manager and
// indexer had no outbound access at all, breaking URL-fed CDB lists, vulnerability feeds,
// integrations, snapshot repositories and the indexer plugin download.
func TestNetworkPoliciesInternetEgress(t *testing.T) {
	on := &wazuhv1.NetworkPolicySpec{Enabled: true}
	for name, np := range map[string]*networkingv1.NetworkPolicy{
		"indexer": BuildIndexerNetworkPolicy("c", "wazuh", "wazuh-operator", on),
		"manager": BuildManagerNetworkPolicy("c", "wazuh", "wazuh-operator", on),
	} {
		if !internetEgressAllowed(np, 443) || !internetEgressAllowed(np, 80) {
			t.Errorf("%s: HTTP/HTTPS egress not allowed by default", name)
		}
		if internetEgressAllowed(np, 22) {
			t.Errorf("%s: other ports must stay closed", name)
		}
	}
	off := false
	np := BuildManagerNetworkPolicy("c", "wazuh", "wazuh-operator", &wazuhv1.NetworkPolicySpec{Enabled: true, AllowInternetEgress: &off})
	if internetEgressAllowed(np, 443) {
		t.Error("allowInternetEgress=false must not allow HTTPS egress")
	}
}

// TestUserEgressIPBlock guards the documented way to open a specific external destination
// once allowInternetEgress is false.
func TestUserEgressIPBlock(t *testing.T) {
	off := false
	port := int32(443)
	spec := &wazuhv1.NetworkPolicySpec{Enabled: true, AllowInternetEgress: &off, Egress: []wazuhv1.NetworkPolicyEgressRule{{
		To:    []wazuhv1.NetworkPolicyPeer{{IPBlock: &wazuhv1.NetworkPolicyIPBlock{CIDR: "203.0.113.0/24", Except: []string{"203.0.113.7/32"}}}},
		Ports: []wazuhv1.NetworkPolicyPort{{Port: &port}},
	}}}
	np := BuildManagerNetworkPolicy("c", "wazuh", "wazuh-operator", spec)
	last := np.Spec.Egress[len(np.Spec.Egress)-1]
	if len(last.To) != 1 || last.To[0].IPBlock == nil || last.To[0].IPBlock.CIDR != "203.0.113.0/24" || len(last.To[0].IPBlock.Except) != 1 {
		t.Fatalf("user ipBlock egress not rendered: %+v", last)
	}
}
