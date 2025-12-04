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

package drain

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// ManagerDrainer handles queue draining for safe manager worker scale-down
type ManagerDrainer interface {
	// StartDrain initiates the drain process for a worker node
	StartDrain(ctx context.Context, nodeName string) error

	// MonitorQueueDepth checks and returns the current queue depth
	MonitorQueueDepth(ctx context.Context, nodeName string) (ManagerDrainProgress, error)

	// VerifyQueueEmpty checks if the queue is empty with grace period
	VerifyQueueEmpty(ctx context.Context, nodeName string) (bool, error)

	// CancelDrain cancels an in-progress drain
	CancelDrain(ctx context.Context) error

	// EvaluateFeasibility checks if drain is feasible without executing (for dry-run)
	EvaluateFeasibility(ctx context.Context, nodeName string) (*v1alpha1.DryRunResult, error)
}

// ManagerDrainProgress represents the current state of a manager drain operation
type ManagerDrainProgress struct {
	// Percent completion (0-100)
	Percent int32

	// QueueDepth is the remaining events in the queue
	QueueDepth int64

	// InitialQueueDepth is the queue depth when drain started
	InitialQueueDepth int64

	// Message describing current status
	Message string

	// IsComplete indicates if drain is finished
	IsComplete bool

	// Error if any occurred
	Error error
}

// ManagerDrainerImpl implements ManagerDrainer
type ManagerDrainerImpl struct {
	client             *adapters.WazuhAPIAdapter
	log                logr.Logger
	timeout            time.Duration
	queueCheckInterval time.Duration
	gracePeriod        time.Duration
	initialQueueDepth  int64
	emptyQueueSeenTime *time.Time
}

// NewManagerDrainer creates a new ManagerDrainer instance
func NewManagerDrainer(client *adapters.WazuhAPIAdapter, log logr.Logger, config *v1alpha1.ManagerDrainConfig) *ManagerDrainerImpl {
	timeout := constants.DefaultManagerDrainTimeout
	queueCheckInterval := constants.DefaultManagerQueueCheckInterval

	// Default grace period: queue must be empty for at least 10 seconds
	gracePeriod := 10 * time.Second

	if config != nil {
		if config.Timeout != nil {
			timeout = config.Timeout.Duration
		}
		if config.QueueCheckInterval != nil {
			queueCheckInterval = config.QueueCheckInterval.Duration
		}
		if config.GracePeriod != nil {
			gracePeriod = config.GracePeriod.Duration
		}
	}

	return &ManagerDrainerImpl{
		client:             client,
		log:                log.WithName("manager-drainer"),
		timeout:            timeout,
		queueCheckInterval: queueCheckInterval,
		gracePeriod:        gracePeriod,
	}
}

// StartDrain initiates the drain process for a worker node
func (d *ManagerDrainerImpl) StartDrain(ctx context.Context, nodeName string) error {
	d.log.Info("Starting manager worker drain", "node", nodeName)

	// Get initial queue depth
	queueStatus, err := d.client.GetQueueStatus(ctx, nodeName)
	if err != nil {
		return fmt.Errorf("failed to get initial queue status: %w", err)
	}

	d.initialQueueDepth = queueStatus.TotalEvents
	d.emptyQueueSeenTime = nil

	d.log.Info("Initial queue depth recorded", "node", nodeName, "depth", d.initialQueueDepth)

	// Note: Unlike OpenSearch, Wazuh doesn't have a built-in "drain mode"
	// The drain process simply monitors the queue until it's empty
	// The worker will naturally process events as they come in

	return nil
}

// MonitorQueueDepth checks the current queue depth
func (d *ManagerDrainerImpl) MonitorQueueDepth(ctx context.Context, nodeName string) (ManagerDrainProgress, error) {
	progress := ManagerDrainProgress{
		InitialQueueDepth: d.initialQueueDepth,
	}

	// Get current queue status
	queueStatus, err := d.client.GetQueueStatus(ctx, nodeName)
	if err != nil {
		progress.Error = fmt.Errorf("failed to get queue status: %w", err)
		return progress, progress.Error
	}

	progress.QueueDepth = queueStatus.TotalEvents

	// Calculate progress percentage
	if d.initialQueueDepth > 0 {
		processedEvents := d.initialQueueDepth - progress.QueueDepth
		if processedEvents < 0 {
			// New events came in, reset initial count
			d.initialQueueDepth = progress.QueueDepth
			processedEvents = 0
		}
		progress.Percent = int32((processedEvents * 100) / d.initialQueueDepth)
	} else {
		progress.Percent = 100 // No events to process
	}

	// Track when queue first becomes empty for grace period
	if progress.QueueDepth == 0 {
		if d.emptyQueueSeenTime == nil {
			now := time.Now()
			d.emptyQueueSeenTime = &now
			d.log.Info("Queue empty, starting grace period", "node", nodeName)
		}

		gracePeriodElapsed := time.Since(*d.emptyQueueSeenTime) >= d.gracePeriod
		if gracePeriodElapsed {
			progress.IsComplete = true
			progress.Percent = 100
			progress.Message = "Queue drained successfully (grace period elapsed)"
		} else {
			remaining := d.gracePeriod - time.Since(*d.emptyQueueSeenTime)
			progress.Message = fmt.Sprintf("Queue empty, waiting for grace period (%v remaining)", remaining.Round(time.Second))
		}
	} else {
		// Queue has events, reset empty time tracking
		d.emptyQueueSeenTime = nil
		progress.Message = fmt.Sprintf("Processing queue: %d events remaining", progress.QueueDepth)
	}

	d.log.V(1).Info("Queue depth progress",
		"node", nodeName,
		"depth", progress.QueueDepth,
		"percent", progress.Percent,
		"complete", progress.IsComplete,
	)

	return progress, nil
}

// VerifyQueueEmpty checks if the queue is empty with grace period
func (d *ManagerDrainerImpl) VerifyQueueEmpty(ctx context.Context, nodeName string) (bool, error) {
	queueStatus, err := d.client.GetQueueStatus(ctx, nodeName)
	if err != nil {
		return false, fmt.Errorf("failed to verify queue empty: %w", err)
	}

	if queueStatus.TotalEvents > 0 {
		d.log.Info("Queue not empty, events remaining", "node", nodeName, "events", queueStatus.TotalEvents)
		return false, nil
	}

	// Check grace period
	if d.emptyQueueSeenTime == nil {
		now := time.Now()
		d.emptyQueueSeenTime = &now
		return false, nil
	}

	if time.Since(*d.emptyQueueSeenTime) < d.gracePeriod {
		d.log.Info("Queue empty but grace period not elapsed", "node", nodeName)
		return false, nil
	}

	d.log.Info("Queue drain verified complete", "node", nodeName)
	return true, nil
}

// CancelDrain cancels an in-progress drain
func (d *ManagerDrainerImpl) CancelDrain(ctx context.Context) error {
	d.log.Info("Canceling manager drain")
	// Reset internal state
	d.initialQueueDepth = 0
	d.emptyQueueSeenTime = nil
	return nil
}

// EvaluateFeasibility checks if drain is feasible without executing (dry-run mode)
func (d *ManagerDrainerImpl) EvaluateFeasibility(ctx context.Context, nodeName string) (*v1alpha1.DryRunResult, error) {
	result := &v1alpha1.DryRunResult{
		Feasible:    true,
		EvaluatedAt: metav1.Now(),
		Component:   constants.DrainComponentManager,
	}

	// Check if we can connect to the Wazuh API
	if !d.client.IsHealthy(ctx) {
		result.Feasible = false
		result.Blockers = append(result.Blockers, "Cannot connect to Wazuh API")
		return result, nil
	}

	// Check cluster status
	clusterStatus, err := d.client.GetClusterStatus(ctx)
	if err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Cannot check cluster status: %v", err))
	} else if !clusterStatus.Running {
		result.Feasible = false
		result.Blockers = append(result.Blockers,
			"Wazuh cluster is not running")
	}

	// Check node status
	nodeStatus, err := d.client.GetClusterNodeStatus(ctx, nodeName)
	if err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Cannot check node %s status: %v", nodeName, err))
	} else if nodeStatus.Status == "disconnected" {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Node %s is disconnected from cluster", nodeName))
	}

	// Check queue depth
	queueStatus, err := d.client.GetQueueStatus(ctx, nodeName)
	if err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Cannot check queue status: %v", err))
	} else if queueStatus.TotalEvents > 0 {
		// Estimate duration based on queue depth
		// Rough estimate: 1000 events per second
		estimatedSeconds := int64(queueStatus.TotalEvents / 1000)
		if estimatedSeconds < 60 {
			estimatedSeconds = 60 // Minimum 1 minute
		}
		// Add grace period
		estimatedSeconds += int64(d.gracePeriod.Seconds())
		result.EstimatedDuration = &metav1.Duration{Duration: time.Duration(estimatedSeconds) * time.Second}
	} else {
		// Queue is already empty
		result.EstimatedDuration = &metav1.Duration{Duration: d.gracePeriod + 30*time.Second}
	}

	// Get all nodes to check if we have enough workers
	allNodes, err := d.client.GetAllNodesStatus(ctx)
	if err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Cannot check all nodes: %v", err))
	} else {
		workerCount := 0
		for _, node := range allNodes {
			if node.Type == "worker" {
				workerCount++
			}
		}
		if workerCount <= 1 {
			result.Feasible = false
			result.Blockers = append(result.Blockers,
				"Cannot drain: only one worker node in cluster")
		}
	}

	d.log.Info("Dry-run evaluation complete",
		"node", nodeName,
		"feasible", result.Feasible,
		"blockers", len(result.Blockers),
		"warnings", len(result.Warnings),
	)

	return result, nil
}

// WaitForDrainComplete blocks until drain completes or timeout
func (d *ManagerDrainerImpl) WaitForDrainComplete(ctx context.Context, nodeName string, status *v1alpha1.ComponentDrainStatus) error {
	startTime := time.Now()
	ticker := time.NewTicker(d.queueCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// Check timeout
			if time.Since(startTime) > d.timeout {
				return fmt.Errorf("drain timeout after %v", d.timeout)
			}

			// Get progress
			progress, err := d.MonitorQueueDepth(ctx, nodeName)
			if err != nil {
				d.log.Error(err, "Error monitoring queue depth", "node", nodeName)
				continue
			}

			// Update status
			if status != nil {
				UpdateProgress(status, progress.Percent, progress.Message)
				UpdateQueueDepth(status, progress.QueueDepth)
			}

			if progress.IsComplete {
				d.log.Info("Manager drain complete", "node", nodeName, "duration", time.Since(startTime))
				return nil
			}
		}
	}
}

// GetTimeout returns the configured timeout for drain operations
func (d *ManagerDrainerImpl) GetTimeout() time.Duration {
	return d.timeout
}

// GetQueueCheckInterval returns the configured queue check interval
func (d *ManagerDrainerImpl) GetQueueCheckInterval() time.Duration {
	return d.queueCheckInterval
}
