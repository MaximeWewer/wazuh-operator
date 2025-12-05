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
	"testing"

	"github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
)

func TestValidateNodePools_ModeExclusivity(t *testing.T) {
	tests := []struct {
		name        string
		spec        *v1alpha1.WazuhIndexerClusterSpec
		expectValid bool
		errorField  string
	}{
		{
			name: "simple mode - replicas only",
			spec: &v1alpha1.WazuhIndexerClusterSpec{
				Replicas: 3,
			},
			expectValid: true,
		},
		{
			name: "advanced mode - nodePools only",
			spec: &v1alpha1.WazuhIndexerClusterSpec{
				NodePools: []v1alpha1.IndexerNodePoolSpec{
					{Name: "masters", Replicas: 3, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleClusterManager}},
					{Name: "data", Replicas: 3, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleData}},
				},
			},
			expectValid: true,
		},
		{
			name: "invalid - both replicas and nodePools",
			spec: &v1alpha1.WazuhIndexerClusterSpec{
				Replicas: 3,
				NodePools: []v1alpha1.IndexerNodePoolSpec{
					{Name: "masters", Replicas: 3, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleClusterManager}},
				},
			},
			expectValid: false,
			errorField:  "spec.indexer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateNodePools(tt.spec)
			if result.Valid != tt.expectValid {
				t.Errorf("expected valid=%v, got valid=%v, errors=%v", tt.expectValid, result.Valid, result.Errors)
			}
			if !tt.expectValid && tt.errorField != "" {
				found := false
				for _, err := range result.Errors {
					if err.Field == tt.errorField {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected error on field %s, got errors: %v", tt.errorField, result.Errors)
				}
			}
		})
	}
}

func TestValidateNodePools_ClusterManagerQuorum(t *testing.T) {
	tests := []struct {
		name        string
		spec        *v1alpha1.WazuhIndexerClusterSpec
		expectValid bool
	}{
		{
			name: "valid - 3 cluster_manager nodes",
			spec: &v1alpha1.WazuhIndexerClusterSpec{
				NodePools: []v1alpha1.IndexerNodePoolSpec{
					{Name: "masters", Replicas: 3, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleClusterManager}},
					{Name: "data", Replicas: 5, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleData}},
				},
			},
			expectValid: true,
		},
		{
			name: "valid - 5 cluster_manager nodes",
			spec: &v1alpha1.WazuhIndexerClusterSpec{
				NodePools: []v1alpha1.IndexerNodePoolSpec{
					{Name: "masters", Replicas: 5, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleClusterManager}},
					{Name: "data", Replicas: 3, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleData}},
				},
			},
			expectValid: true,
		},
		{
			name: "valid - split across pools",
			spec: &v1alpha1.WazuhIndexerClusterSpec{
				NodePools: []v1alpha1.IndexerNodePoolSpec{
					{Name: "masters-a", Replicas: 1, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleClusterManager}},
					{Name: "masters-b", Replicas: 1, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleClusterManager}},
					{Name: "masters-c", Replicas: 1, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleClusterManager}},
					{Name: "data", Replicas: 5, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleData}},
				},
			},
			expectValid: true,
		},
		{
			name: "invalid - only 1 cluster_manager node",
			spec: &v1alpha1.WazuhIndexerClusterSpec{
				NodePools: []v1alpha1.IndexerNodePoolSpec{
					{Name: "masters", Replicas: 1, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleClusterManager}},
					{Name: "data", Replicas: 5, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleData}},
				},
			},
			expectValid: false,
		},
		{
			name: "invalid - 2 cluster_manager nodes",
			spec: &v1alpha1.WazuhIndexerClusterSpec{
				NodePools: []v1alpha1.IndexerNodePoolSpec{
					{Name: "masters", Replicas: 2, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleClusterManager}},
					{Name: "data", Replicas: 5, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleData}},
				},
			},
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateNodePools(tt.spec)
			if result.Valid != tt.expectValid {
				t.Errorf("expected valid=%v, got valid=%v, errors=%v", tt.expectValid, result.Valid, result.Errors)
			}
		})
	}
}

func TestValidateNodePools_DataNodeMinimum(t *testing.T) {
	tests := []struct {
		name        string
		spec        *v1alpha1.WazuhIndexerClusterSpec
		expectValid bool
	}{
		{
			name: "valid - has data nodes",
			spec: &v1alpha1.WazuhIndexerClusterSpec{
				NodePools: []v1alpha1.IndexerNodePoolSpec{
					{Name: "masters", Replicas: 3, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleClusterManager}},
					{Name: "data", Replicas: 1, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleData}},
				},
			},
			expectValid: true,
		},
		{
			name: "invalid - no data nodes (0 replicas)",
			spec: &v1alpha1.WazuhIndexerClusterSpec{
				NodePools: []v1alpha1.IndexerNodePoolSpec{
					{Name: "masters", Replicas: 3, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleClusterManager}},
					{Name: "data", Replicas: 0, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleData}},
				},
			},
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateNodePools(tt.spec)
			if result.Valid != tt.expectValid {
				t.Errorf("expected valid=%v, got valid=%v, errors=%v", tt.expectValid, result.Valid, result.Errors)
			}
		})
	}
}

func TestValidateNodePools_UniqueNames(t *testing.T) {
	tests := []struct {
		name        string
		spec        *v1alpha1.WazuhIndexerClusterSpec
		expectValid bool
	}{
		{
			name: "valid - unique names",
			spec: &v1alpha1.WazuhIndexerClusterSpec{
				NodePools: []v1alpha1.IndexerNodePoolSpec{
					{Name: "masters", Replicas: 3, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleClusterManager}},
					{Name: "data-hot", Replicas: 3, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleData}},
					{Name: "data-warm", Replicas: 2, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleData}},
				},
			},
			expectValid: true,
		},
		{
			name: "invalid - duplicate names",
			spec: &v1alpha1.WazuhIndexerClusterSpec{
				NodePools: []v1alpha1.IndexerNodePoolSpec{
					{Name: "masters", Replicas: 3, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleClusterManager}},
					{Name: "data", Replicas: 3, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleData}},
					{Name: "data", Replicas: 2, Roles: []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleData}}, // duplicate
				},
			},
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateNodePools(tt.spec)
			if result.Valid != tt.expectValid {
				t.Errorf("expected valid=%v, got valid=%v, errors=%v", tt.expectValid, result.Valid, result.Errors)
			}
		})
	}
}

func TestValidateNodePoolSpec_NameFormat(t *testing.T) {
	tests := []struct {
		name        string
		pool        *v1alpha1.IndexerNodePoolSpec
		expectValid bool
	}{
		{
			name:        "valid - lowercase alphanumeric",
			pool:        &v1alpha1.IndexerNodePoolSpec{Name: "masters", Replicas: 3},
			expectValid: true,
		},
		{
			name:        "valid - with hyphens",
			pool:        &v1alpha1.IndexerNodePoolSpec{Name: "data-hot", Replicas: 3},
			expectValid: true,
		},
		{
			name:        "valid - numbers",
			pool:        &v1alpha1.IndexerNodePoolSpec{Name: "data1", Replicas: 3},
			expectValid: true,
		},
		{
			name:        "invalid - uppercase",
			pool:        &v1alpha1.IndexerNodePoolSpec{Name: "MASTERS", Replicas: 3},
			expectValid: false,
		},
		{
			name:        "invalid - starts with hyphen",
			pool:        &v1alpha1.IndexerNodePoolSpec{Name: "-data", Replicas: 3},
			expectValid: false,
		},
		{
			name:        "invalid - ends with hyphen",
			pool:        &v1alpha1.IndexerNodePoolSpec{Name: "data-", Replicas: 3},
			expectValid: false,
		},
		{
			name:        "invalid - contains underscore",
			pool:        &v1alpha1.IndexerNodePoolSpec{Name: "data_hot", Replicas: 3},
			expectValid: false,
		},
		{
			name:        "invalid - empty name",
			pool:        &v1alpha1.IndexerNodePoolSpec{Name: "", Replicas: 3},
			expectValid: false,
		},
		{
			name:        "invalid - too long (>15 chars)",
			pool:        &v1alpha1.IndexerNodePoolSpec{Name: "thisnameistoolong", Replicas: 3},
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateNodePoolSpec(tt.pool, "test")
			if result.Valid != tt.expectValid {
				t.Errorf("expected valid=%v, got valid=%v, errors=%v", tt.expectValid, result.Valid, result.Errors)
			}
		})
	}
}

func TestValidateNodePoolSpec_Roles(t *testing.T) {
	tests := []struct {
		name        string
		pool        *v1alpha1.IndexerNodePoolSpec
		expectValid bool
	}{
		{
			name: "valid - cluster_manager role",
			pool: &v1alpha1.IndexerNodePoolSpec{
				Name:     "masters",
				Replicas: 3,
				Roles:    []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleClusterManager},
			},
			expectValid: true,
		},
		{
			name: "valid - multiple roles",
			pool: &v1alpha1.IndexerNodePoolSpec{
				Name:     "data",
				Replicas: 3,
				Roles:    []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleData, v1alpha1.IndexerNodeRoleIngest},
			},
			expectValid: true,
		},
		{
			name: "valid - empty roles (coordinating only)",
			pool: &v1alpha1.IndexerNodePoolSpec{
				Name:     "coord",
				Replicas: 2,
				Roles:    []v1alpha1.IndexerNodeRole{},
			},
			expectValid: true,
		},
		{
			name: "valid - coordinating_only explicit",
			pool: &v1alpha1.IndexerNodePoolSpec{
				Name:     "coord",
				Replicas: 2,
				Roles:    []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleCoordinatingOnly},
			},
			expectValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateNodePoolSpec(tt.pool, "test")
			if result.Valid != tt.expectValid {
				t.Errorf("expected valid=%v, got valid=%v, errors=%v", tt.expectValid, result.Valid, result.Errors)
			}
		})
	}
}

func TestValidateModeTransition(t *testing.T) {
	tests := []struct {
		name        string
		currentMode string
		newMode     string
		expectError bool
	}{
		{
			name:        "no transition - same mode (simple)",
			currentMode: "simple",
			newMode:     "simple",
			expectError: false,
		},
		{
			name:        "no transition - same mode (advanced)",
			currentMode: "advanced",
			newMode:     "advanced",
			expectError: false,
		},
		{
			name:        "invalid transition - simple to advanced",
			currentMode: "simple",
			newMode:     "advanced",
			expectError: true,
		},
		{
			name:        "invalid transition - advanced to simple",
			currentMode: "advanced",
			newMode:     "simple",
			expectError: true,
		},
		{
			name:        "initial setup - empty to simple",
			currentMode: "",
			newMode:     "simple",
			expectError: false,
		},
		{
			name:        "initial setup - empty to advanced",
			currentMode: "",
			newMode:     "advanced",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateModeTransition(tt.currentMode, tt.newMode)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error=%v, got error=%v", tt.expectError, err)
			}
		})
	}
}

func TestValidateScaleDown_QuorumProtection(t *testing.T) {
	tests := []struct {
		name                 string
		pool                 *v1alpha1.IndexerNodePoolSpec
		currentReplicas      int32
		desiredReplicas      int32
		totalClusterManagers int32
		expectValid          bool
	}{
		{
			name: "valid - scale down data nodes",
			pool: &v1alpha1.IndexerNodePoolSpec{
				Name:     "data",
				Replicas: 5,
				Roles:    []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleData},
			},
			currentReplicas:      5,
			desiredReplicas:      3,
			totalClusterManagers: 3,
			expectValid:          true,
		},
		{
			name: "valid - scale down cluster_manager but keep quorum",
			pool: &v1alpha1.IndexerNodePoolSpec{
				Name:     "masters",
				Replicas: 5,
				Roles:    []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleClusterManager},
			},
			currentReplicas:      5,
			desiredReplicas:      3,
			totalClusterManagers: 5,
			expectValid:          true,
		},
		{
			name: "invalid - scale down would break quorum",
			pool: &v1alpha1.IndexerNodePoolSpec{
				Name:     "masters",
				Replicas: 3,
				Roles:    []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleClusterManager},
			},
			currentReplicas:      3,
			desiredReplicas:      1,
			totalClusterManagers: 3,
			expectValid:          false,
		},
		{
			name: "not a scale-down",
			pool: &v1alpha1.IndexerNodePoolSpec{
				Name:     "masters",
				Replicas: 3,
				Roles:    []v1alpha1.IndexerNodeRole{v1alpha1.IndexerNodeRoleClusterManager},
			},
			currentReplicas:      3,
			desiredReplicas:      5,
			totalClusterManagers: 3,
			expectValid:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateScaleDown(tt.pool, tt.currentReplicas, tt.desiredReplicas, tt.totalClusterManagers)
			if result.Valid != tt.expectValid {
				t.Errorf("expected valid=%v, got valid=%v, errors=%v", tt.expectValid, result.Valid, result.Errors)
			}
		})
	}
}
