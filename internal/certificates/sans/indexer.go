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

package sans

import (
	"fmt"

	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

// IndexerNode is an indexer pod and the headless Service that gives it its DNS name.
type IndexerNode struct {
	Pod     string
	Service string
}

// GenerateIndexerNodeSANs generates Subject Alternative Names for the simple-mode indexer
// nodes <cluster>-indexer-0..replicas-1 (see GenerateIndexerSANs).
func GenerateIndexerNodeSANs(clusterName, namespace string, replicas int32) []string {
	headlessService := clusterName + "-indexer-headless"
	nodes := make([]IndexerNode, 0, replicas)
	for i := range replicas {
		nodes = append(nodes, IndexerNode{Pod: fmt.Sprintf("%s-indexer-%d", clusterName, i), Service: headlessService})
	}
	return GenerateIndexerSANs(clusterName, namespace, nodes)
}

// GenerateIndexerSANs generates Subject Alternative Names for the given indexer nodes:
// the indexer Service, the wildcard of every headless Service the nodes sit behind (one per
// nodePool in advanced mode), and each node's name and FQDN. The operator connects pod by
// pod (securityadmin, certificate hot reload), so each pod's FQDN must verify.
func GenerateIndexerSANs(clusterName, namespace string, nodes []IndexerNode) []string {
	indexerService := clusterName + "-indexer"
	headlessService := clusterName + "-indexer-headless"

	sans := []string{
		"localhost",
		indexerService,
		fmt.Sprintf("%s.%s", indexerService, namespace),
		fmt.Sprintf("%s.%s.svc", indexerService, namespace),
		dns.ServiceFQDN(indexerService, namespace),
		dns.WildcardServiceFQDN(headlessService, namespace),
	}
	seen := map[string]bool{headlessService: true}
	for _, n := range nodes {
		if !seen[n.Service] {
			seen[n.Service] = true
			sans = append(sans, dns.WildcardServiceFQDN(n.Service, namespace))
		}
	}
	for _, n := range nodes {
		sans = append(sans, n.Pod, dns.PodFQDN(n.Pod, n.Service, namespace))
	}
	return sans
}
