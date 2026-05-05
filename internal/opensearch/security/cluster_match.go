/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package security

import wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"

// matchesCluster returns true if any entry in refs targets the given cluster.
// Used to filter multi-cluster OpenSearch CRs against a single cluster.
func matchesCluster(refs []wazuhv1.WazuhClusterRef, name, namespace string) bool {
	for _, ref := range refs {
		if ref.Name == name && ref.Namespace == namespace {
			return true
		}
	}
	return false
}
