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

// Package conditions provides standard Kubernetes condition helpers for the Wazuh Operator
package conditions

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Wazuh condition types
const (
	// WazuhConditionReady indicates the Wazuh component is ready
	WazuhConditionReady = "Ready"

	// WazuhConditionManagerReady indicates the manager component is ready
	WazuhConditionManagerReady = "ManagerReady"

	// WazuhConditionWorkersReady indicates all workers are ready
	WazuhConditionWorkersReady = "WorkersReady"

	// WazuhConditionClusterJoined indicates the node has joined the cluster
	WazuhConditionClusterJoined = "ClusterJoined"

	// WazuhConditionCertificatesReady indicates certificates are generated
	WazuhConditionCertificatesReady = "CertificatesReady"

	// WazuhConditionConfigApplied indicates configuration is applied
	WazuhConditionConfigApplied = "ConfigApplied"

	// WazuhConditionRulesApplied indicates rules are applied
	WazuhConditionRulesApplied = "RulesApplied"

	// WazuhConditionDecodersApplied indicates decoders are applied
	WazuhConditionDecodersApplied = "DecodersApplied"
)

// Wazuh condition reasons
const (
	WazuhReasonReconciling       = "Reconciling"
	WazuhReasonReady             = "Ready"
	WazuhReasonNotReady          = "NotReady"
	WazuhReasonFailed            = "Failed"
	WazuhReasonCertificateError  = "CertificateError"
	WazuhReasonConfigError       = "ConfigurationError"
	WazuhReasonClusterError      = "ClusterError"
	WazuhReasonWaitingDependency = "WaitingForDependency"
)

// NewWazuhCondition creates a new Wazuh condition
func NewWazuhCondition(conditionType string, status metav1.ConditionStatus, reason, message string) metav1.Condition {
	return metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	}
}

// SetWazuhCondition sets or updates a condition in the conditions slice
func SetWazuhCondition(conditions *[]metav1.Condition, condition metav1.Condition) {
	if conditions == nil {
		return
	}

	existingCondition := FindWazuhCondition(*conditions, condition.Type)
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

// FindWazuhCondition finds a condition by type
func FindWazuhCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}

// IsWazuhConditionTrue checks if a condition is true
func IsWazuhConditionTrue(conditions []metav1.Condition, conditionType string) bool {
	condition := FindWazuhCondition(conditions, conditionType)
	return condition != nil && condition.Status == metav1.ConditionTrue
}

// SetWazuhReadyCondition sets the Ready condition
func SetWazuhReadyCondition(conditions *[]metav1.Condition, ready bool, reason, message string) {
	status := metav1.ConditionFalse
	if ready {
		status = metav1.ConditionTrue
	}
	SetWazuhCondition(conditions, NewWazuhCondition(WazuhConditionReady, status, reason, message))
}

// SetWazuhManagerReadyCondition sets the ManagerReady condition
func SetWazuhManagerReadyCondition(conditions *[]metav1.Condition, ready bool, reason, message string) {
	status := metav1.ConditionFalse
	if ready {
		status = metav1.ConditionTrue
	}
	SetWazuhCondition(conditions, NewWazuhCondition(WazuhConditionManagerReady, status, reason, message))
}

// SetWazuhWorkersReadyCondition sets the WorkersReady condition
func SetWazuhWorkersReadyCondition(conditions *[]metav1.Condition, ready bool, reason, message string) {
	status := metav1.ConditionFalse
	if ready {
		status = metav1.ConditionTrue
	}
	SetWazuhCondition(conditions, NewWazuhCondition(WazuhConditionWorkersReady, status, reason, message))
}

// SetWazuhCertificatesReadyCondition sets the CertificatesReady condition
func SetWazuhCertificatesReadyCondition(conditions *[]metav1.Condition, ready bool, reason, message string) {
	status := metav1.ConditionFalse
	if ready {
		status = metav1.ConditionTrue
	}
	SetWazuhCondition(conditions, NewWazuhCondition(WazuhConditionCertificatesReady, status, reason, message))
}
