/*
Copyright 2025.

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

package validation

import (
	"k8s.io/apimachinery/pkg/util/validation/field"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
)

// ValidateClusterCreate validates a WazuhCluster for creation
func ValidateClusterCreate(cluster *wazuhv1alpha1.WazuhCluster) field.ErrorList {
	return ValidateWazuhCluster(cluster)
}

// ValidateClusterUpdate validates a WazuhCluster for update
func ValidateClusterUpdate(newCluster, oldCluster *wazuhv1alpha1.WazuhCluster) field.ErrorList {
	allErrs := ValidateWazuhCluster(newCluster)

	specPath := field.NewPath("spec")

	// Validate immutable fields for indexer
	if oldCluster.Spec.Indexer != nil && newCluster.Spec.Indexer != nil {
		if oldCluster.Spec.Indexer.StorageSize != "" && newCluster.Spec.Indexer.StorageSize != oldCluster.Spec.Indexer.StorageSize {
			// PVC size can only be increased, not decreased
			// This is a simplified check - proper volume expansion validation would need to compare quantities
			allErrs = append(allErrs, field.Forbidden(specPath.Child("indexer").Child("storageSize"),
				"storage size cannot be decreased after creation"))
		}
	}

	return allErrs
}

// ValidateIndexerSpec validates the indexer specification
func ValidateIndexerSpec(spec *wazuhv1alpha1.WazuhIndexerClusterSpec) field.ErrorList {
	var allErrs field.ErrorList

	if spec == nil {
		return allErrs
	}

	specPath := field.NewPath("indexer")

	// Validate replicas
	if spec.Replicas < 1 {
		allErrs = append(allErrs, field.Invalid(specPath.Child("replicas"), spec.Replicas, "indexer replicas must be at least 1"))
	}

	// For a proper cluster, you need at least 3 nodes for quorum
	if spec.Replicas > 1 && spec.Replicas < 3 {
		allErrs = append(allErrs, field.Invalid(specPath.Child("replicas"), spec.Replicas,
			"for high availability, indexer replicas should be 1 (single node) or at least 3"))
	}

	return allErrs
}

// ValidateManagerSpec validates the manager specification
func ValidateManagerSpec(spec *wazuhv1alpha1.WazuhManagerClusterSpec) field.ErrorList {
	var allErrs field.ErrorList

	if spec == nil {
		return allErrs
	}

	specPath := field.NewPath("manager")

	// Validate master replicas - master always has 1 replica in this design
	// No validation needed since WazuhMasterSpec does not have Replicas field

	// Validate worker replicas
	if spec.Workers.Replicas != nil && *spec.Workers.Replicas < 0 {
		allErrs = append(allErrs, field.Invalid(specPath.Child("workers").Child("replicas"),
			*spec.Workers.Replicas, "worker replicas must be non-negative"))
	}

	return allErrs
}

// ValidateDashboardSpec validates the dashboard specification
func ValidateDashboardSpec(spec *wazuhv1alpha1.WazuhDashboardClusterSpec) field.ErrorList {
	var allErrs field.ErrorList

	if spec == nil {
		return allErrs
	}

	specPath := field.NewPath("dashboard")

	// Validate replicas
	if spec.Replicas < 0 {
		allErrs = append(allErrs, field.Invalid(specPath.Child("replicas"), spec.Replicas, "dashboard replicas must be non-negative"))
	}

	return allErrs
}

// ValidateClusterReferences validates cross-references in a cluster
func ValidateClusterReferences(cluster *wazuhv1alpha1.WazuhCluster) field.ErrorList {
	var allErrs field.ErrorList

	// Add any cross-reference validation here
	// For example, ensuring that referenced secrets exist

	return allErrs
}
