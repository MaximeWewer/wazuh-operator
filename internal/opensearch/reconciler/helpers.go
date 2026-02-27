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

package reconciler

import corev1 "k8s.io/api/core/v1"

// preserveNodePorts copies server-assigned NodePort values from the existing
// Service to the desired Service for ports where the desired NodePort is 0.
func preserveNodePorts(desired, existing *corev1.Service) {
	for i := range desired.Spec.Ports {
		if desired.Spec.Ports[i].NodePort == 0 {
			for _, ep := range existing.Spec.Ports {
				if ep.Port == desired.Spec.Ports[i].Port && ep.Protocol == desired.Spec.Ports[i].Protocol {
					desired.Spec.Ports[i].NodePort = ep.NodePort
					break
				}
			}
		}
	}
}

// mapsEqualStr compares two string maps for equality.
func mapsEqualStr(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
