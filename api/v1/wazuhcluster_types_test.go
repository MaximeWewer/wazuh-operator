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

package v1

import (
	"testing"
)

// Helper function for creating int32 pointer
func int32Ptr(i int32) *int32 {
	return &i
}

// TestWazuhManagerClusterSpec_GetTotalReplicas tests total replica count calculation
func TestWazuhManagerClusterSpec_GetTotalReplicas(t *testing.T) {
	tests := []struct {
		name     string
		spec     *WazuhManagerClusterSpec
		expected int32
	}{
		{
			name:     "nil spec returns 0",
			spec:     nil,
			expected: 0,
		},
		{
			name: "default workers (2) = 3 total",
			spec: &WazuhManagerClusterSpec{
				Master:  WazuhMasterSpec{StorageSize: "10Gi"},
				Workers: WazuhWorkerSpec{},
			},
			expected: 3, // 1 master + 2 workers (default)
		},
		{
			name: "0 workers = 1 total (master only)",
			spec: &WazuhManagerClusterSpec{
				Master:  WazuhMasterSpec{StorageSize: "10Gi"},
				Workers: WazuhWorkerSpec{Replicas: int32Ptr(0)},
			},
			expected: 1, // 1 master + 0 workers
		},
		{
			name: "2 workers = 3 total",
			spec: &WazuhManagerClusterSpec{
				Master:  WazuhMasterSpec{StorageSize: "10Gi"},
				Workers: WazuhWorkerSpec{Replicas: int32Ptr(2)},
			},
			expected: 3, // 1 master + 2 workers
		},
		{
			name: "5 workers = 6 total",
			spec: &WazuhManagerClusterSpec{
				Master:  WazuhMasterSpec{StorageSize: "10Gi"},
				Workers: WazuhWorkerSpec{Replicas: int32Ptr(5)},
			},
			expected: 6, // 1 master + 5 workers
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.spec.GetTotalReplicas()
			if got != tt.expected {
				t.Errorf("GetTotalReplicas() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestWazuhManagerClusterSpec_IsHA tests high availability detection
func TestWazuhManagerClusterSpec_IsHA(t *testing.T) {
	tests := []struct {
		name     string
		spec     *WazuhManagerClusterSpec
		expected bool
	}{
		{
			name:     "nil spec is not HA",
			spec:     nil,
			expected: false,
		},
		{
			name: "0 workers (1 total) is not HA",
			spec: &WazuhManagerClusterSpec{
				Master:  WazuhMasterSpec{StorageSize: "10Gi"},
				Workers: WazuhWorkerSpec{Replicas: int32Ptr(0)},
			},
			expected: false,
		},
		{
			name: "1 worker (2 total) is not HA",
			spec: &WazuhManagerClusterSpec{
				Master:  WazuhMasterSpec{StorageSize: "10Gi"},
				Workers: WazuhWorkerSpec{Replicas: int32Ptr(1)},
			},
			expected: false,
		},
		{
			name: "2 workers (3 total) is HA",
			spec: &WazuhManagerClusterSpec{
				Master:  WazuhMasterSpec{StorageSize: "10Gi"},
				Workers: WazuhWorkerSpec{Replicas: int32Ptr(2)},
			},
			expected: true,
		},
		{
			name: "default workers (3 total) is HA",
			spec: &WazuhManagerClusterSpec{
				Master:  WazuhMasterSpec{StorageSize: "10Gi"},
				Workers: WazuhWorkerSpec{},
			},
			expected: true, // Default is 2 workers = 3 total
		},
		{
			name: "5 workers (6 total) is HA",
			spec: &WazuhManagerClusterSpec{
				Master:  WazuhMasterSpec{StorageSize: "10Gi"},
				Workers: WazuhWorkerSpec{Replicas: int32Ptr(5)},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.spec.IsHA()
			if got != tt.expected {
				t.Errorf("IsHA() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestWazuhIndexerClusterSpec_IsHA tests high availability detection for indexer
func TestWazuhIndexerClusterSpec_IsHA(t *testing.T) {
	tests := []struct {
		name     string
		spec     *WazuhIndexerClusterSpec
		expected bool
	}{
		{
			name:     "nil spec is not HA",
			spec:     nil,
			expected: false,
		},
		{
			name: "simple mode: 1 replica is not HA",
			spec: &WazuhIndexerClusterSpec{
				Replicas:    1,
				StorageSize: "50Gi",
			},
			expected: false,
		},
		{
			name: "simple mode: 2 replicas is not HA",
			spec: &WazuhIndexerClusterSpec{
				Replicas:    2,
				StorageSize: "50Gi",
			},
			expected: false,
		},
		{
			name: "simple mode: 3 replicas is HA",
			spec: &WazuhIndexerClusterSpec{
				Replicas:    3,
				StorageSize: "50Gi",
			},
			expected: true,
		},
		{
			name: "simple mode: 5 replicas is HA",
			spec: &WazuhIndexerClusterSpec{
				Replicas:    5,
				StorageSize: "50Gi",
			},
			expected: true,
		},
		{
			name: "advanced mode: single nodePool with 1 replica is not HA",
			spec: &WazuhIndexerClusterSpec{
				NodePools: []IndexerNodePoolSpec{
					{Name: "data", Replicas: 1, Roles: []IndexerNodeRole{IndexerNodeRoleData}},
				},
			},
			expected: false,
		},
		{
			name: "advanced mode: single nodePool with 3 replicas is HA",
			spec: &WazuhIndexerClusterSpec{
				NodePools: []IndexerNodePoolSpec{
					{Name: "data", Replicas: 3, Roles: []IndexerNodeRole{IndexerNodeRoleData, IndexerNodeRoleClusterManager}},
				},
			},
			expected: true,
		},
		{
			name: "advanced mode: multiple nodePools totaling 3 is HA",
			spec: &WazuhIndexerClusterSpec{
				NodePools: []IndexerNodePoolSpec{
					{Name: "master", Replicas: 1, Roles: []IndexerNodeRole{IndexerNodeRoleClusterManager}},
					{Name: "data", Replicas: 2, Roles: []IndexerNodeRole{IndexerNodeRoleData}},
				},
			},
			expected: true,
		},
		{
			name: "advanced mode: multiple nodePools totaling 2 is not HA",
			spec: &WazuhIndexerClusterSpec{
				NodePools: []IndexerNodePoolSpec{
					{Name: "master", Replicas: 1, Roles: []IndexerNodeRole{IndexerNodeRoleClusterManager}},
					{Name: "data", Replicas: 1, Roles: []IndexerNodeRole{IndexerNodeRoleData}},
				},
			},
			expected: false,
		},
		{
			name: "advanced mode: 3 master + 3 data = 6 total is HA",
			spec: &WazuhIndexerClusterSpec{
				NodePools: []IndexerNodePoolSpec{
					{Name: "master", Replicas: 3, Roles: []IndexerNodeRole{IndexerNodeRoleClusterManager}},
					{Name: "data", Replicas: 3, Roles: []IndexerNodeRole{IndexerNodeRoleData, IndexerNodeRoleIngest}},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.spec.IsHA()
			if got != tt.expected {
				t.Errorf("IsHA() = %v, want %v", got, tt.expected)
			}
		})
	}
}
