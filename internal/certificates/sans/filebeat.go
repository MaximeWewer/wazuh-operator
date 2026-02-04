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

// GenerateFilebeatSANs generates Subject Alternative Names for filebeat.
// Filebeat runs as sidecar in manager pods, so SANs include manager service names.
func GenerateFilebeatSANs(clusterName, namespace string, workerReplicas int32) []string {
	masterService := clusterName + "-manager-master"
	workersService := clusterName + "-manager-workers"
	masterPod := clusterName + "-manager-master-0"

	sans := []string{
		"localhost",
		masterService,
		fmt.Sprintf("%s.%s", masterService, namespace),
		fmt.Sprintf("%s.%s.svc", masterService, namespace),
		dns.ServiceFQDN(masterService, namespace),
		masterPod,
		dns.PodFQDN(masterPod, masterService, namespace),
		workersService,
		fmt.Sprintf("%s.%s", workersService, namespace),
		fmt.Sprintf("%s.%s.svc", workersService, namespace),
		dns.ServiceFQDN(workersService, namespace),
	}

	for i := int32(0); i < workerReplicas; i++ {
		podName := fmt.Sprintf("%s-manager-workers-%d", clusterName, i)
		sans = append(sans, podName, dns.PodFQDN(podName, workersService, namespace))
	}

	return sans
}
