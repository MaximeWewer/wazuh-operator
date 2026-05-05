/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package validation

import wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"

// overlapsClusterRefs returns true if a and b share at least one (name,namespace) pair.
// Used to skip duplicate-content checks across CRs that don't target the same cluster.
func overlapsClusterRefs(a, b []wazuhv1.WazuhClusterRef) bool {
	for _, ra := range a {
		for _, rb := range b {
			if ra.Name == rb.Name && ra.Namespace == rb.Namespace {
				return true
			}
		}
	}
	return false
}
