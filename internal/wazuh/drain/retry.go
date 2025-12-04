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
	"strconv"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// RetryManager handles retry logic for failed drain operations
type RetryManager interface {
	// ShouldRetry determines if another retry attempt should be made
	ShouldRetry(status *v1alpha1.ComponentDrainStatus, config *v1alpha1.DrainRetryConfig) bool

	// CalculateNextRetryTime calculates when the next retry should occur
	CalculateNextRetryTime(status *v1alpha1.ComponentDrainStatus, config *v1alpha1.DrainRetryConfig) time.Time

	// IncrementAttempt updates the attempt count and sets next retry time
	IncrementAttempt(status *v1alpha1.ComponentDrainStatus, config *v1alpha1.DrainRetryConfig)

	// IsRetryDue checks if it's time to retry
	IsRetryDue(status *v1alpha1.ComponentDrainStatus) bool

	// ResetRetryState clears retry-related state
	ResetRetryState(status *v1alpha1.ComponentDrainStatus)
}

// RetryManagerImpl implements RetryManager
type RetryManagerImpl struct {
	log logr.Logger
}

// NewRetryManager creates a new RetryManager
func NewRetryManager(log logr.Logger) *RetryManagerImpl {
	return &RetryManagerImpl{
		log: log.WithName("retry-manager"),
	}
}

// ShouldRetry determines if another retry attempt should be made
func (r *RetryManagerImpl) ShouldRetry(status *v1alpha1.ComponentDrainStatus, config *v1alpha1.DrainRetryConfig) bool {
	// If no config, use defaults
	maxAttempts := int32(constants.DefaultDrainRetryMaxAttempts)
	if config != nil && config.MaxAttempts > 0 {
		maxAttempts = config.MaxAttempts
	}

	// Check if max attempts reached
	if status.AttemptCount >= maxAttempts {
		r.log.Info("Max retry attempts reached",
			"attempts", status.AttemptCount,
			"maxAttempts", maxAttempts)
		return false
	}

	// Only retry if in Failed state
	if status.Phase != v1alpha1.DrainPhaseFailed {
		return false
	}

	return true
}

// CalculateNextRetryTime calculates when the next retry should occur using exponential backoff
func (r *RetryManagerImpl) CalculateNextRetryTime(status *v1alpha1.ComponentDrainStatus, config *v1alpha1.DrainRetryConfig) time.Time {
	// Get configuration values with defaults
	initialDelay := constants.DefaultDrainRetryInitialDelay
	if config != nil && config.InitialDelay != nil {
		initialDelay = config.InitialDelay.Duration
	}

	backoffMultiplier := constants.DefaultDrainRetryBackoffMultiplier
	if config != nil && config.BackoffMultiplier != "" {
		if mult, err := strconv.ParseFloat(config.BackoffMultiplier, 64); err == nil {
			backoffMultiplier = mult
		}
	}

	maxDelay := constants.DefaultDrainRetryMaxDelay
	if config != nil && config.MaxDelay != nil {
		maxDelay = config.MaxDelay.Duration
	}

	// Calculate delay with exponential backoff
	// delay = initialDelay * (backoffMultiplier ^ attemptCount)
	attempt := status.AttemptCount
	if attempt == 0 {
		attempt = 1
	}

	delay := initialDelay
	for i := int32(1); i < attempt; i++ {
		delay = time.Duration(float64(delay) * backoffMultiplier)
		if delay > maxDelay {
			delay = maxDelay
			break
		}
	}

	nextRetry := time.Now().Add(delay)
	r.log.Info("Calculated next retry time",
		"attempt", status.AttemptCount,
		"delay", delay,
		"nextRetry", nextRetry)

	return nextRetry
}

// IncrementAttempt updates the attempt count and sets next retry time
func (r *RetryManagerImpl) IncrementAttempt(status *v1alpha1.ComponentDrainStatus, config *v1alpha1.DrainRetryConfig) {
	status.AttemptCount++

	// Calculate and set next retry time
	nextRetry := r.CalculateNextRetryTime(status, config)
	status.NextRetryTime = &metav1.Time{Time: nextRetry}

	r.log.Info("Incremented retry attempt",
		"attemptCount", status.AttemptCount,
		"nextRetryTime", nextRetry)
}

// IsRetryDue checks if it's time to retry
func (r *RetryManagerImpl) IsRetryDue(status *v1alpha1.ComponentDrainStatus) bool {
	if status.NextRetryTime == nil {
		return false
	}

	return time.Now().After(status.NextRetryTime.Time)
}

// ResetRetryState clears retry-related state
func (r *RetryManagerImpl) ResetRetryState(status *v1alpha1.ComponentDrainStatus) {
	status.AttemptCount = 0
	status.NextRetryTime = nil
	r.log.Info("Reset retry state")
}

// GetRetryStatus returns human-readable retry status
func (r *RetryManagerImpl) GetRetryStatus(status *v1alpha1.ComponentDrainStatus, config *v1alpha1.DrainRetryConfig) string {
	maxAttempts := int32(constants.DefaultDrainRetryMaxAttempts)
	if config != nil && config.MaxAttempts > 0 {
		maxAttempts = config.MaxAttempts
	}

	if status.AttemptCount >= maxAttempts {
		return "max attempts reached, manual intervention required"
	}

	if status.NextRetryTime != nil {
		remaining := time.Until(status.NextRetryTime.Time)
		if remaining > 0 {
			return "retry scheduled in " + remaining.Round(time.Second).String()
		}
		return "retry due"
	}

	return "no retry scheduled"
}

// RetryDecision represents the outcome of a retry evaluation
type RetryDecision struct {
	// ShouldRetry indicates if a retry should be attempted
	ShouldRetry bool
	// IsDue indicates if the retry time has passed
	IsDue bool
	// AttemptNumber is the next attempt number (1-based)
	AttemptNumber int32
	// RemainingAttempts is how many attempts are left
	RemainingAttempts int32
	// NextRetryTime is when the next retry will occur
	NextRetryTime *time.Time
	// Reason explains the decision
	Reason string
}

// EvaluateRetry provides a comprehensive retry decision
func (r *RetryManagerImpl) EvaluateRetry(status *v1alpha1.ComponentDrainStatus, config *v1alpha1.DrainRetryConfig) *RetryDecision {
	maxAttempts := int32(constants.DefaultDrainRetryMaxAttempts)
	if config != nil && config.MaxAttempts > 0 {
		maxAttempts = config.MaxAttempts
	}

	decision := &RetryDecision{
		AttemptNumber:     status.AttemptCount + 1,
		RemainingAttempts: maxAttempts - status.AttemptCount,
	}

	// Check if max attempts reached
	if status.AttemptCount >= maxAttempts {
		decision.ShouldRetry = false
		decision.Reason = "max attempts reached"
		return decision
	}

	// Check if in correct state for retry
	if status.Phase != v1alpha1.DrainPhaseFailed {
		decision.ShouldRetry = false
		decision.Reason = "not in failed state"
		return decision
	}

	decision.ShouldRetry = true

	// Check if retry is due
	if status.NextRetryTime != nil {
		nextRetry := status.NextRetryTime.Time
		decision.NextRetryTime = &nextRetry
		decision.IsDue = time.Now().After(nextRetry)
		if decision.IsDue {
			decision.Reason = "retry time has passed"
		} else {
			decision.Reason = "waiting for retry time"
		}
	} else {
		// No retry time set, calculate one
		nextRetry := r.CalculateNextRetryTime(status, config)
		decision.NextRetryTime = &nextRetry
		decision.IsDue = false
		decision.Reason = "retry scheduled"
	}

	return decision
}
