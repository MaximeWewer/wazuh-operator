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

// API and HTTP request timeouts
const (
	// TimeoutAPIRequest is the default timeout for API requests
	TimeoutAPIRequest = 30 * time.Second

	// TimeoutOpenSearchRequest is the timeout for OpenSearch HTTP requests
	TimeoutOpenSearchRequest = 30 * time.Second

	// TimeoutHealthCheck is the timeout for health check operations
	TimeoutHealthCheck = 10 * time.Second
)

// Polling and retry intervals
const (
	// PollIntervalHealthCheck is the interval between health check polls
	PollIntervalHealthCheck = 5 * time.Second

	// PollIntervalRollout is the interval between rollout status checks
	PollIntervalRollout = 5 * time.Second

	// TimeoutRollout is the timeout for waiting for rollout completion
	TimeoutRollout = 5 * time.Minute
)

// Retry configuration
const (
	// RetryInitialInterval is the initial interval for retry operations
	RetryInitialInterval = 1 * time.Second

	// RetryMaxInterval is the maximum interval for retry operations
	RetryMaxInterval = 30 * time.Second
)

// Token and session durations
const (
	// TokenValidityDuration is the validity duration for API tokens
	TokenValidityDuration = 15 * time.Minute
)

// CronJob configuration
const (
	// CronJobBackoffLimit is the default backoff limit for CronJobs
	CronJobBackoffLimit int32 = 3

	// CronJobSuccessHistoryLimit is the number of successful job history to keep
	CronJobSuccessHistoryLimit int32 = 3

	// CronJobFailedHistoryLimit is the number of failed job history to keep
	CronJobFailedHistoryLimit int32 = 1
)
