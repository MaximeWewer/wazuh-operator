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

package conditions

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OpenSearch condition types
const (
	// OpenSearchConditionReady indicates the OpenSearch component is ready
	OpenSearchConditionReady = "Ready"

	// OpenSearchConditionClusterHealthy indicates the cluster is healthy
	OpenSearchConditionClusterHealthy = "ClusterHealthy"

	// OpenSearchConditionSecurityInitialized indicates security plugin is initialized
	OpenSearchConditionSecurityInitialized = "SecurityInitialized"

	// OpenSearchConditionSynced indicates the resource is synced with OpenSearch
	OpenSearchConditionSynced = "Synced"

	// OpenSearchConditionDriftDetected indicates drift was detected
	OpenSearchConditionDriftDetected = "DriftDetected"

	// OpenSearchConditionConflict indicates a resource ownership conflict
	OpenSearchConditionConflict = "Conflict"

	// OpenSearchConditionIndexerReady indicates indexer nodes are ready
	OpenSearchConditionIndexerReady = "IndexerReady"

	// OpenSearchConditionDashboardReady indicates dashboard is ready
	OpenSearchConditionDashboardReady = "DashboardReady"
)

// OpenSearch condition reasons
const (
	OpenSearchReasonReconciling    = "Reconciling"
	OpenSearchReasonReady          = "Ready"
	OpenSearchReasonNotReady       = "NotReady"
	OpenSearchReasonFailed         = "Failed"
	OpenSearchReasonSyncError      = "SyncError"
	OpenSearchReasonSynced         = "Synced"
	OpenSearchReasonDriftDetected  = "DriftDetected"
	OpenSearchReasonDriftCorrected = "DriftCorrected"
	OpenSearchReasonConflict       = "ResourceConflict"
	OpenSearchReasonAPIError       = "APIError"
	OpenSearchReasonClusterRed     = "ClusterRed"
	OpenSearchReasonClusterYellow  = "ClusterYellow"
	OpenSearchReasonClusterGreen   = "ClusterGreen"
)

// NewOpenSearchCondition creates a new OpenSearch condition
func NewOpenSearchCondition(conditionType string, status metav1.ConditionStatus, reason, message string) metav1.Condition {
	return metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	}
}

// SetOpenSearchCondition sets or updates a condition in the conditions slice
func SetOpenSearchCondition(conditions *[]metav1.Condition, condition metav1.Condition) {
	if conditions == nil {
		return
	}

	existingCondition := FindOpenSearchCondition(*conditions, condition.Type)
	if existingCondition == nil {
		*conditions = append(*conditions, condition)
		return
	}

	if existingCondition.Status != condition.Status {
		existingCondition.LastTransitionTime = metav1.Now()
	}
	existingCondition.Status = condition.Status
	existingCondition.Reason = condition.Reason
	existingCondition.Message = condition.Message
}

// FindOpenSearchCondition finds a condition by type
func FindOpenSearchCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}

// IsOpenSearchConditionTrue checks if a condition is true
func IsOpenSearchConditionTrue(conditions []metav1.Condition, conditionType string) bool {
	condition := FindOpenSearchCondition(conditions, conditionType)
	return condition != nil && condition.Status == metav1.ConditionTrue
}

// SetOpenSearchReadyCondition sets the Ready condition
func SetOpenSearchReadyCondition(conditions *[]metav1.Condition, ready bool, reason, message string) {
	status := metav1.ConditionFalse
	if ready {
		status = metav1.ConditionTrue
	}
	SetOpenSearchCondition(conditions, NewOpenSearchCondition(OpenSearchConditionReady, status, reason, message))
}

// SetOpenSearchSyncedCondition sets the Synced condition
func SetOpenSearchSyncedCondition(conditions *[]metav1.Condition, synced bool, reason, message string) {
	status := metav1.ConditionFalse
	if synced {
		status = metav1.ConditionTrue
	}
	SetOpenSearchCondition(conditions, NewOpenSearchCondition(OpenSearchConditionSynced, status, reason, message))
}

// SetOpenSearchDriftCondition sets the DriftDetected condition
func SetOpenSearchDriftCondition(conditions *[]metav1.Condition, driftDetected bool, reason, message string) {
	status := metav1.ConditionFalse
	if driftDetected {
		status = metav1.ConditionTrue
	}
	SetOpenSearchCondition(conditions, NewOpenSearchCondition(OpenSearchConditionDriftDetected, status, reason, message))
}

// SetOpenSearchConflictCondition sets the Conflict condition
func SetOpenSearchConflictCondition(conditions *[]metav1.Condition, hasConflict bool, reason, message string) {
	status := metav1.ConditionFalse
	if hasConflict {
		status = metav1.ConditionTrue
	}
	SetOpenSearchCondition(conditions, NewOpenSearchCondition(OpenSearchConditionConflict, status, reason, message))
}

// SetOpenSearchClusterHealthyCondition sets the ClusterHealthy condition
func SetOpenSearchClusterHealthyCondition(conditions *[]metav1.Condition, health string, message string) {
	var status metav1.ConditionStatus
	var reason string

	switch health {
	case "green":
		status = metav1.ConditionTrue
		reason = OpenSearchReasonClusterGreen
	case "yellow":
		status = metav1.ConditionTrue
		reason = OpenSearchReasonClusterYellow
	default:
		status = metav1.ConditionFalse
		reason = OpenSearchReasonClusterRed
	}

	SetOpenSearchCondition(conditions, NewOpenSearchCondition(OpenSearchConditionClusterHealthy, status, reason, message))
}
