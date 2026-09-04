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

import (
	"bytes"

	corev1 "k8s.io/api/core/v1"
)

// preserveServiceDefaults copies all server-assigned and server-defaulted
// fields from the existing Service into the desired Service so that
// apiequality.Semantic.DeepEqual does not report false diffs.
func preserveServiceDefaults(desired, existing *corev1.Service) {
	// Immutable fields assigned by the API server
	desired.Spec.ClusterIP = existing.Spec.ClusterIP
	desired.Spec.ClusterIPs = existing.Spec.ClusterIPs

	// Fields defaulted by the API server when not explicitly set
	if desired.Spec.IPFamilyPolicy == nil {
		desired.Spec.IPFamilyPolicy = existing.Spec.IPFamilyPolicy
	}
	if desired.Spec.IPFamilies == nil {
		desired.Spec.IPFamilies = existing.Spec.IPFamilies
	}
	if desired.Spec.InternalTrafficPolicy == nil {
		desired.Spec.InternalTrafficPolicy = existing.Spec.InternalTrafficPolicy
	}
	if desired.Spec.ExternalTrafficPolicy == "" {
		desired.Spec.ExternalTrafficPolicy = existing.Spec.ExternalTrafficPolicy
	}
	if desired.Spec.SessionAffinity == "" {
		desired.Spec.SessionAffinity = existing.Spec.SessionAffinity
	}
	if desired.Spec.HealthCheckNodePort == 0 {
		desired.Spec.HealthCheckNodePort = existing.Spec.HealthCheckNodePort
	}
	if desired.Spec.AllocateLoadBalancerNodePorts == nil {
		desired.Spec.AllocateLoadBalancerNodePorts = existing.Spec.AllocateLoadBalancerNodePorts
	}

	// Server-assigned NodePort values
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

// mapsEqualBytes compares two byte-slice maps for equality.
func mapsEqualBytes(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		bv, ok := b[k]
		if !ok || !bytes.Equal(v, bv) {
			return false
		}
	}
	return true
}
