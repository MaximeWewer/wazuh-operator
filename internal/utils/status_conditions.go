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

package utils

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConditionType represents the type of a condition
type ConditionType string

// Common condition types
const (
	// ConditionTypeReady indicates the resource is ready
	ConditionTypeReady ConditionType = "Ready"

	// ConditionTypeProgressing indicates the resource is being reconciled
	ConditionTypeProgressing ConditionType = "Progressing"

	// ConditionTypeDegraded indicates the resource is in a degraded state
	ConditionTypeDegraded ConditionType = "Degraded"

	// ConditionTypeSynced indicates the resource is synced with external system
	ConditionTypeSynced ConditionType = "Synced"

	// ConditionTypeInitialized indicates initialization is complete
	ConditionTypeInitialized ConditionType = "Initialized"

	// ConditionTypeAvailable indicates the resource is available for use
	ConditionTypeAvailable ConditionType = "Available"
)

// ConditionReason represents the reason for a condition
type ConditionReason string

// Common condition reasons
const (
	// ReasonReconciling indicates reconciliation is in progress
	ReasonReconciling ConditionReason = "Reconciling"

	// ReasonSucceeded indicates the operation succeeded
	ReasonSucceeded ConditionReason = "Succeeded"

	// ReasonFailed indicates the operation failed
	ReasonFailed ConditionReason = "Failed"

	// ReasonWaiting indicates the resource is waiting for something
	ReasonWaiting ConditionReason = "Waiting"

	// ReasonDeleting indicates the resource is being deleted
	ReasonDeleting ConditionReason = "Deleting"

	// ReasonConfigurationError indicates a configuration error
	ReasonConfigurationError ConditionReason = "ConfigurationError"

	// ReasonDependencyNotReady indicates a dependency is not ready
	ReasonDependencyNotReady ConditionReason = "DependencyNotReady"

	// ReasonClusterNotHealthy indicates the cluster is not healthy
	ReasonClusterNotHealthy ConditionReason = "ClusterNotHealthy"

	// ReasonSyncError indicates a sync error with external system
	ReasonSyncError ConditionReason = "SyncError"
)

// NewCondition creates a new condition
func NewCondition(
	conditionType ConditionType,
	status metav1.ConditionStatus,
	reason ConditionReason,
	message string,
) metav1.Condition {
	return metav1.Condition{
		Type:               string(conditionType),
		Status:             status,
		Reason:             string(reason),
		Message:            message,
		LastTransitionTime: metav1.Now(),
	}
}

// SetCondition sets a condition in a slice of conditions
func SetCondition(conditions *[]metav1.Condition, condition metav1.Condition) {
	if conditions == nil {
		return
	}

	existingCondition := FindCondition(*conditions, ConditionType(condition.Type))
	if existingCondition == nil {
		// Condition doesn't exist, append it
		*conditions = append(*conditions, condition)
		return
	}

	// Condition exists, update it
	if existingCondition.Status != condition.Status {
		existingCondition.LastTransitionTime = metav1.Now()
	}
	existingCondition.Status = condition.Status
	existingCondition.Reason = condition.Reason
	existingCondition.Message = condition.Message
}

// FindCondition finds a condition by type in a slice of conditions
func FindCondition(conditions []metav1.Condition, conditionType ConditionType) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == string(conditionType) {
			return &conditions[i]
		}
	}
	return nil
}

// IsConditionTrue checks if a condition is true
func IsConditionTrue(conditions []metav1.Condition, conditionType ConditionType) bool {
	condition := FindCondition(conditions, conditionType)
	return condition != nil && condition.Status == metav1.ConditionTrue
}

// IsConditionFalse checks if a condition is false
func IsConditionFalse(conditions []metav1.Condition, conditionType ConditionType) bool {
	condition := FindCondition(conditions, conditionType)
	return condition != nil && condition.Status == metav1.ConditionFalse
}

// IsConditionUnknown checks if a condition is unknown
func IsConditionUnknown(conditions []metav1.Condition, conditionType ConditionType) bool {
	condition := FindCondition(conditions, conditionType)
	return condition == nil || condition.Status == metav1.ConditionUnknown
}

// RemoveCondition removes a condition from a slice of conditions
func RemoveCondition(conditions *[]metav1.Condition, conditionType ConditionType) {
	if conditions == nil {
		return
	}
	for i := range *conditions {
		if (*conditions)[i].Type == string(conditionType) {
			*conditions = append((*conditions)[:i], (*conditions)[i+1:]...)
			return
		}
	}
}

// SetReadyCondition sets the Ready condition
func SetReadyCondition(conditions *[]metav1.Condition, status metav1.ConditionStatus, reason ConditionReason, message string) {
	SetCondition(conditions, NewCondition(ConditionTypeReady, status, reason, message))
}

// SetProgressingCondition sets the Progressing condition
func SetProgressingCondition(conditions *[]metav1.Condition, status metav1.ConditionStatus, reason ConditionReason, message string) {
	SetCondition(conditions, NewCondition(ConditionTypeProgressing, status, reason, message))
}

// SetDegradedCondition sets the Degraded condition
func SetDegradedCondition(conditions *[]metav1.Condition, status metav1.ConditionStatus, reason ConditionReason, message string) {
	SetCondition(conditions, NewCondition(ConditionTypeDegraded, status, reason, message))
}
