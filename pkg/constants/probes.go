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

// Kubernetes probe configuration defaults
const (
	// ProbeStartupInitialDelaySeconds is the initial delay for startup probes
	ProbeStartupInitialDelaySeconds int32 = 30

	// ProbeStartupPeriodSeconds is the period for startup probes
	ProbeStartupPeriodSeconds int32 = 10

	// ProbeStartupFailureThreshold is the failure threshold for startup probes
	ProbeStartupFailureThreshold int32 = 30

	// ProbeLivenessInitialDelaySeconds is the initial delay for liveness probes
	ProbeLivenessInitialDelaySeconds int32 = 60

	// ProbeLivenessPeriodSeconds is the period for liveness probes
	ProbeLivenessPeriodSeconds int32 = 30

	// ProbeTimeoutSeconds is the default timeout for probes
	ProbeTimeoutSeconds int32 = 10

	// ProbeLivenessFailureThreshold is the failure threshold for liveness probes
	ProbeLivenessFailureThreshold int32 = 3
)

// ServiceMonitor configuration defaults
const (
	// ServiceMonitorIntervalDefault is the default scrape interval for ServiceMonitors
	ServiceMonitorIntervalDefault = "30s"

	// ServiceMonitorScrapeTimeoutDefault is the default scrape timeout for ServiceMonitors
	ServiceMonitorScrapeTimeoutDefault = "10s"
)

// API readiness check defaults
const (
	// APIReadinessCheckIntervalSeconds is the interval between API readiness checks
	APIReadinessCheckIntervalSeconds = 5

	// APIReadinessMaxAttempts is the maximum number of API readiness check attempts
	APIReadinessMaxAttempts = 60
)
