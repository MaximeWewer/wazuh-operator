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

package constants

// OpenSearch Node Roles
// These follow OpenSearch 2.x naming conventions where "master" became "cluster_manager"
const (
	// OpenSearchRoleClusterManager is the cluster manager (master) role
	// Responsible for cluster-wide operations like creating/deleting indices,
	// tracking cluster nodes, and allocating shards
	OpenSearchRoleClusterManager = "cluster_manager"

	// OpenSearchRoleData is the data node role
	// Stores data and executes data-related operations like CRUD, search, aggregations
	OpenSearchRoleData = "data"

	// OpenSearchRoleIngest is the ingest node role
	// Pre-processes documents before indexing using ingest pipelines
	OpenSearchRoleIngest = "ingest"

	// OpenSearchRoleSearch is the search node role
	// Dedicated nodes for search operations, reducing load on data nodes
	OpenSearchRoleSearch = "search"

	// OpenSearchRoleCoordinatingOnly represents a coordinating-only node
	// In OpenSearch, this is represented by an empty roles array
	// Routes requests, handles search reduce phase, and distributes bulk indexing
	OpenSearchRoleCoordinatingOnly = "coordinating_only"

	// OpenSearchRoleML is the machine learning node role
	// Runs ML jobs and handles ML API requests
	OpenSearchRoleML = "ml"

	// OpenSearchRoleRemoteClusterClient is for cross-cluster operations
	// Enables cross-cluster search and cross-cluster replication
	OpenSearchRoleRemoteClusterClient = "remote_cluster_client"
)

// OpenSearchRoleList is the list of all valid OpenSearch node roles
var OpenSearchRoleList = []string{
	OpenSearchRoleClusterManager,
	OpenSearchRoleData,
	OpenSearchRoleIngest,
	OpenSearchRoleSearch,
	OpenSearchRoleCoordinatingOnly,
	OpenSearchRoleML,
	OpenSearchRoleRemoteClusterClient,
}

// NodePool topology mode constants
const (
	// TopologyModeSimple indicates the cluster uses a single replicas field
	// All nodes have all roles (cluster_manager, data, ingest)
	TopologyModeSimple = "simple"

	// TopologyModeAdvanced indicates the cluster uses nodePools
	// Each nodePool can have different roles, resources, and storage
	TopologyModeAdvanced = "advanced"
)

// NodePool validation constants
const (
	// MinClusterManagerNodes is the minimum number of cluster_manager nodes
	// Required for quorum-based leader election (split-brain prevention)
	MinClusterManagerNodes int32 = 3

	// MinDataNodes is the minimum number of data nodes
	// Required to store and serve data
	MinDataNodes int32 = 1

	// MaxNodePoolNameLength is the maximum length for nodePool names
	// Constrained by StatefulSet naming limits
	MaxNodePoolNameLength = 15
)

// IsValidOpenSearchRole checks if a role string is a valid OpenSearch role
func IsValidOpenSearchRole(role string) bool {
	for _, validRole := range OpenSearchRoleList {
		if role == validRole {
			return true
		}
	}
	return false
}

// HasClusterManagerRole checks if a list of roles contains cluster_manager
func HasClusterManagerRole(roles []string) bool {
	for _, role := range roles {
		if role == OpenSearchRoleClusterManager {
			return true
		}
	}
	return false
}

// HasDataRole checks if a list of roles contains data
func HasDataRole(roles []string) bool {
	for _, role := range roles {
		if role == OpenSearchRoleData {
			return true
		}
	}
	return false
}

// IsCoordinatingOnly checks if a roles list represents a coordinating-only node
// In OpenSearch, coordinating-only nodes have an empty roles array
func IsCoordinatingOnly(roles []string) bool {
	if len(roles) == 0 {
		return true
	}
	// Also check if only coordinating_only is specified (for CRD clarity)
	return len(roles) == 1 && roles[0] == OpenSearchRoleCoordinatingOnly
}
