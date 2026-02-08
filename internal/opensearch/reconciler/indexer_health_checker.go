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
	"context"
	"fmt"

	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// IndexerHealthChecker verifies OpenSearch cluster health before allowing
// a pod restart. It checks cluster status, shard movement, and node count.
type IndexerHealthChecker struct {
	osClient         *api.Client
	desiredNodeCount int
}

// NewIndexerHealthChecker creates a new IndexerHealthChecker.
func NewIndexerHealthChecker(osClient *api.Client, desiredNodeCount int) *IndexerHealthChecker {
	return &IndexerHealthChecker{
		osClient:         osClient,
		desiredNodeCount: desiredNodeCount,
	}
}

// IsHealthyForRestart checks if the OpenSearch cluster can safely tolerate a node restart.
// Conditions for healthy:
//   - Cluster status is NOT red
//   - No relocating shards (shard movement in progress)
//   - No initializing shards (shards still recovering)
//   - Number of nodes >= desired node count
func (c *IndexerHealthChecker) IsHealthyForRestart(ctx context.Context) (bool, string, error) {
	health, err := c.osClient.GetClusterHealth(ctx)
	if err != nil {
		return false, "", fmt.Errorf("failed to get cluster health: %w", err)
	}

	if health.Status == constants.OpenSearchHealthRed {
		return false, fmt.Sprintf("cluster status is RED (%d unassigned shards)", health.UnassignedShards), nil
	}

	if health.RelocatingShards > 0 {
		return false, fmt.Sprintf("cluster has %d relocating shards", health.RelocatingShards), nil
	}

	if health.InitializingShards > 0 {
		return false, fmt.Sprintf("cluster has %d initializing shards", health.InitializingShards), nil
	}

	if health.NumberOfNodes < c.desiredNodeCount {
		return false, fmt.Sprintf("cluster has %d nodes, expected %d", health.NumberOfNodes, c.desiredNodeCount), nil
	}

	return true, fmt.Sprintf("cluster is %s with %d nodes", health.Status, health.NumberOfNodes), nil
}
