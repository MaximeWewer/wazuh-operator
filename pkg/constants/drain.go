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

import "time"

// Drain phase constants
const (
	// DrainPhaseIdle indicates no drain operation in progress
	DrainPhaseIdle = "Idle"

	// DrainPhasePending indicates a scale-down was detected but drain not started
	DrainPhasePending = "Pending"

	// DrainPhaseDraining indicates drain is actively in progress
	DrainPhaseDraining = "Draining"

	// DrainPhaseVerifying indicates drain is complete and being verified
	DrainPhaseVerifying = "Verifying"

	// DrainPhaseComplete indicates drain completed successfully
	DrainPhaseComplete = "Complete"

	// DrainPhaseFailed indicates drain operation failed
	DrainPhaseFailed = "Failed"

	// DrainPhaseRollingBack indicates a rollback is in progress
	DrainPhaseRollingBack = "RollingBack"
)

// Indexer drain defaults
const (
	// DefaultIndexerDrainTimeout is the default timeout for shard relocation
	DefaultIndexerDrainTimeout = 30 * time.Minute

	// DefaultIndexerHealthCheckInterval is the interval between shard status checks
	DefaultIndexerHealthCheckInterval = 10 * time.Second

	// DefaultIndexerMinGreenHealthTimeout is the wait time for cluster green health
	DefaultIndexerMinGreenHealthTimeout = 5 * time.Minute
)

// Manager drain defaults
const (
	// DefaultManagerDrainTimeout is the default timeout for queue drain
	DefaultManagerDrainTimeout = 15 * time.Minute

	// DefaultManagerQueueCheckInterval is the interval between queue depth checks
	DefaultManagerQueueCheckInterval = 5 * time.Second

	// DefaultManagerGracePeriod is the wait time after queue is empty
	DefaultManagerGracePeriod = 30 * time.Second
)

// Retry defaults
const (
	// DefaultDrainRetryMaxAttempts is the maximum number of retry attempts
	DefaultDrainRetryMaxAttempts int32 = 3

	// DefaultDrainRetryInitialDelay is the initial delay before first retry
	DefaultDrainRetryInitialDelay = 5 * time.Minute

	// DefaultDrainRetryBackoffMultiplier is the exponential backoff factor
	DefaultDrainRetryBackoffMultiplier float64 = 2.0

	// DefaultDrainRetryMaxDelay is the maximum delay between retries
	DefaultDrainRetryMaxDelay = 30 * time.Minute
)

// Dashboard PDB defaults
const (
	// DefaultDashboardPDBMinAvailable is the minimum available Dashboard pods
	DefaultDashboardPDBMinAvailable int32 = 1
)

// Drain event reasons
const (
	// DrainEventReasonStarted is emitted when a drain operation starts
	DrainEventReasonStarted = "DrainStarted"

	// DrainEventReasonProgress is emitted at drain progress milestones
	DrainEventReasonProgress = "DrainProgress"

	// DrainEventReasonCompleted is emitted when drain completes successfully
	DrainEventReasonCompleted = "DrainCompleted"

	// DrainEventReasonFailed is emitted when drain fails
	DrainEventReasonFailed = "DrainFailed"

	// DrainEventReasonRollback is emitted when a rollback is triggered
	DrainEventReasonRollback = "DrainRollback"

	// DrainEventReasonRollbackFailed is emitted when a rollback fails
	DrainEventReasonRollbackFailed = "DrainRollbackFailed"

	// DrainEventReasonRollbackComplete is emitted when a rollback completes
	DrainEventReasonRollbackComplete = "DrainRollbackComplete"

	// DrainEventReasonRetry is emitted when a retry is scheduled
	DrainEventReasonRetry = "DrainRetry"

	// DrainEventReasonTimeout is emitted when drain times out
	DrainEventReasonTimeout = "DrainTimeout"

	// DrainEventReasonMaxRetries is emitted when max retries are reached
	DrainEventReasonMaxRetries = "DrainMaxRetries"

	// DrainEventReasonDryRun is emitted with dry-run results
	DrainEventReasonDryRun = "DryRunResult"

	// DrainEventReasonShardsRelocated is emitted when all shards are relocated
	DrainEventReasonShardsRelocated = "ShardsRelocated"

	// DrainEventReasonQueueDrained is emitted when manager queue is drained
	DrainEventReasonQueueDrained = "QueueDrained"
)

// Drain component identifiers
const (
	// DrainComponentIndexer identifies indexer drain operations
	DrainComponentIndexer = "indexer"

	// DrainComponentManager identifies manager drain operations
	DrainComponentManager = "manager"

	// DrainComponentDashboard identifies dashboard (PDB only)
	DrainComponentDashboard = "dashboard"
)

// OpenSearch allocation exclusion settings key
const (
	// OpenSearchAllocationExcludeNameKey is the cluster setting for node exclusion
	OpenSearchAllocationExcludeNameKey = "cluster.routing.allocation.exclude._name"
)

// OpenSearch cluster health status values
const (
	// OpenSearchHealthGreen indicates all primary and replica shards are active
	OpenSearchHealthGreen = "green"

	// OpenSearchHealthYellow indicates all primary shards are active, some replicas are not
	OpenSearchHealthYellow = "yellow"

	// OpenSearchHealthRed indicates some primary shards are not active
	OpenSearchHealthRed = "red"
)

// Wazuh manager queue paths for monitoring
var (
	// WazuhManagerQueuePaths are the paths to check for pending events
	WazuhManagerQueuePaths = []string{
		"/var/ossec/queue/sockets/",
		"/var/ossec/queue/alerts/ar/",
		"/var/ossec/queue/cluster/",
	}
)
