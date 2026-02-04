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

// GenerateIndexerNodeSANs generates Subject Alternative Names for indexer nodes.
// Includes service FQDN, headless service wildcard, and individual pod FQDNs.
func GenerateIndexerNodeSANs(clusterName, namespace string, replicas int32) []string {
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

	// Add individual pod names
	for i := int32(0); i < replicas; i++ {
		podName := fmt.Sprintf("%s-indexer-%d", clusterName, i)
		sans = append(sans, podName, dns.PodFQDN(podName, headlessService, namespace))
	}

	return sans
}
