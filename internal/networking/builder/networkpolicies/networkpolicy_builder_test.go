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
