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

// Package validation provides validation logic for OpenSearch nodePool configurations
package validation

import (
	"fmt"
	"regexp"

	"github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// ValidationError represents a validation error with context
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s", e.Field, e.Message)
	}
	return e.Message
}

// ValidationResult contains the results of nodePool validation
type ValidationResult struct {
	Valid    bool
	Errors   []ValidationError
	Warnings []string
}

// AddError adds an error to the validation result
func (r *ValidationResult) AddError(field, message string) {
	r.Valid = false
	r.Errors = append(r.Errors, ValidationError{Field: field, Message: message})
}

// AddWarning adds a warning to the validation result
func (r *ValidationResult) AddWarning(message string) {
	r.Warnings = append(r.Warnings, message)
}

// nodePoolNameRegex validates DNS-compatible names
var nodePoolNameRegex = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// ValidateNodePools validates the complete nodePool configuration
// This includes mode exclusivity, quorum requirements, and data node minimum
func ValidateNodePools(spec *v1alpha1.WazuhIndexerClusterSpec) *ValidationResult {
	result := &ValidationResult{Valid: true}

	// Check mode exclusivity: cannot have both replicas and nodePools
	if spec.Replicas > 0 && len(spec.NodePools) > 0 {
		result.AddError("spec.indexer",
			"replicas and nodePools are mutually exclusive; use either replicas (simple mode) or nodePools (advanced mode), not both")
		return result
	}

	// If using simple mode (no nodePools), no further validation needed
	if !spec.IsAdvancedMode() {
		return result
	}

	// Validate that at least one nodePool is defined
	if len(spec.NodePools) == 0 {
		result.AddError("spec.indexer.nodePools", "at least one nodePool must be defined")
		return result
	}

	// Track seen pool names for uniqueness check
	seenNames := make(map[string]bool)

	// Track cluster_manager and data node counts
	var clusterManagerCount int32
	var dataNodeCount int32
	hasClusterManagerRole := false
	hasDataRole := false

	// Validate each nodePool
	for i, pool := range spec.NodePools {
		poolField := fmt.Sprintf("spec.indexer.nodePools[%d]", i)
		poolResult := ValidateNodePoolSpec(&pool, poolField)

		// Merge errors
		if !poolResult.Valid {
			result.Valid = false
			result.Errors = append(result.Errors, poolResult.Errors...)
		}
		result.Warnings = append(result.Warnings, poolResult.Warnings...)

		// Check name uniqueness
		if seenNames[pool.Name] {
			result.AddError(poolField+".name",
				fmt.Sprintf("duplicate nodePool name '%s'; each nodePool must have a unique name", pool.Name))
		}
		seenNames[pool.Name] = true

		// Count roles
		if pool.HasClusterManagerRole() {
			hasClusterManagerRole = true
			clusterManagerCount += pool.Replicas
		}
		if pool.HasDataRole() {
			hasDataRole = true
			dataNodeCount += pool.Replicas
		}
	}

	// Validate cluster_manager quorum (minimum 3 nodes)
	if hasClusterManagerRole && clusterManagerCount < constants.MinClusterManagerNodes {
		result.AddError("spec.indexer.nodePools",
			fmt.Sprintf("cluster_manager role requires at least %d nodes for quorum; found %d",
				constants.MinClusterManagerNodes, clusterManagerCount))
	}

	// Validate at least one data node
	if hasDataRole && dataNodeCount < constants.MinDataNodes {
		result.AddError("spec.indexer.nodePools",
			fmt.Sprintf("at least %d data node is required; found %d",
				constants.MinDataNodes, dataNodeCount))
	}

	// Warn if no data role defined at all (cluster will have no storage)
	if !hasDataRole {
		result.AddWarning("no nodePool has the data role; the cluster will not be able to store data")
	}

	return result
}

// ValidateNodePoolSpec validates a single nodePool specification
func ValidateNodePoolSpec(pool *v1alpha1.IndexerNodePoolSpec, fieldPrefix string) *ValidationResult {
	result := &ValidationResult{Valid: true}

	// Validate name
	if pool.Name == "" {
		result.AddError(fieldPrefix+".name", "name is required")
	} else {
		// Check name format (DNS-compatible)
		if !nodePoolNameRegex.MatchString(pool.Name) {
			result.AddError(fieldPrefix+".name",
				"name must be DNS-compatible (lowercase alphanumeric, may contain hyphens, must start and end with alphanumeric)")
		}
		// Check name length
		if len(pool.Name) > constants.MaxNodePoolNameLength {
			result.AddError(fieldPrefix+".name",
				fmt.Sprintf("name must be at most %d characters; got %d",
					constants.MaxNodePoolNameLength, len(pool.Name)))
		}
	}

	// Validate replicas
	if pool.Replicas < 0 {
		result.AddError(fieldPrefix+".replicas", "replicas cannot be negative")
	}

	// Validate roles
	for i, role := range pool.Roles {
		if !isValidRole(role) {
			result.AddError(fmt.Sprintf("%s.roles[%d]", fieldPrefix, i),
				fmt.Sprintf("invalid role '%s'; valid roles are: %v",
					role, constants.OpenSearchRoleList))
		}
	}

	// Warn about resource-constrained configurations
	if pool.HasClusterManagerRole() && pool.HasDataRole() {
		result.AddWarning(fmt.Sprintf("nodePool '%s' has both cluster_manager and data roles; "+
			"consider separating these roles for better stability in production", pool.Name))
	}

	// Validate storage
	if pool.StorageSize == "" && pool.HasDataRole() {
		result.AddWarning(fmt.Sprintf("nodePool '%s' has data role but no storageSize specified; "+
			"using default", pool.Name))
	}

	return result
}

// ValidateModeTransition checks if a mode transition is valid
// Returns an error if trying to transition between modes (not allowed)
func ValidateModeTransition(currentMode, newMode string) error {
	if currentMode != "" && newMode != "" && currentMode != newMode {
		return fmt.Errorf("transitioning from %s mode to %s mode is not supported; "+
			"please create a new cluster with the desired topology", currentMode, newMode)
	}
	return nil
}

// ValidateScaleDown checks if a nodePool scale-down is safe
// Returns warnings and blockers
func ValidateScaleDown(pool *v1alpha1.IndexerNodePoolSpec, currentReplicas, desiredReplicas int32, totalClusterManagers int32) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if desiredReplicas >= currentReplicas {
		// Not a scale-down
		return result
	}

	// Check cluster_manager quorum
	if pool.HasClusterManagerRole() {
		newTotal := totalClusterManagers - (currentReplicas - desiredReplicas)
		if newTotal < constants.MinClusterManagerNodes {
			result.AddError("scale-down",
				fmt.Sprintf("scaling down nodePool '%s' would reduce cluster_manager nodes to %d, "+
					"below minimum quorum of %d", pool.Name, newTotal, constants.MinClusterManagerNodes))
		}
	}

	// Data nodes require drain before scale-down (warning, not error)
	if pool.HasDataRole() {
		result.AddWarning(fmt.Sprintf("nodePool '%s' has data role; shards must be relocated before nodes are terminated",
			pool.Name))
	}

	return result
}

// isValidRole checks if a role is a valid OpenSearch node role
func isValidRole(role v1alpha1.IndexerNodeRole) bool {
	roleStr := string(role)
	return constants.IsValidOpenSearchRole(roleStr)
}
