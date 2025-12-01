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

// WazuhCluster condition types
const (
	// ClusterConditionReady indicates the entire cluster is ready
	ClusterConditionReady = "Ready"

	// ClusterConditionProgressing indicates the cluster is being reconciled
	ClusterConditionProgressing = "Progressing"

	// ClusterConditionDegraded indicates the cluster is degraded
	ClusterConditionDegraded = "Degraded"

	// ClusterConditionManagerReady indicates the manager component is ready
	ClusterConditionManagerReady = "ManagerReady"

	// ClusterConditionIndexerReady indicates the indexer component is ready
	ClusterConditionIndexerReady = "IndexerReady"

	// ClusterConditionDashboardReady indicates the dashboard component is ready
	ClusterConditionDashboardReady = "DashboardReady"

	// ClusterConditionCertificatesReady indicates certificates are ready
	ClusterConditionCertificatesReady = "CertificatesReady"

	// ClusterConditionSecurityInitialized indicates security is initialized
	ClusterConditionSecurityInitialized = "SecurityInitialized"
)

// Cluster condition reasons
const (
	ClusterReasonReconciling       = "Reconciling"
	ClusterReasonReady             = "AllComponentsReady"
	ClusterReasonNotReady          = "ComponentsNotReady"
	ClusterReasonDegraded          = "SomeComponentsDegraded"
	ClusterReasonFailed            = "Failed"
	ClusterReasonManagerNotReady   = "ManagerNotReady"
	ClusterReasonIndexerNotReady   = "IndexerNotReady"
	ClusterReasonDashboardNotReady = "DashboardNotReady"
	ClusterReasonCertsNotReady     = "CertificatesNotReady"
	ClusterReasonUpdating          = "Updating"
	ClusterReasonScaling           = "Scaling"
)

// ClusterPhase represents the phase of a WazuhCluster
type ClusterPhase string

const (
	// ClusterPhasePending indicates the cluster is pending creation
	ClusterPhasePending ClusterPhase = "Pending"

	// ClusterPhaseDeploying indicates the cluster is being deployed
	ClusterPhaseDeploying ClusterPhase = "Deploying"

	// ClusterPhaseReady indicates the cluster is ready
	ClusterPhaseReady ClusterPhase = "Ready"

	// ClusterPhaseDegraded indicates the cluster is degraded
	ClusterPhaseDegraded ClusterPhase = "Degraded"

	// ClusterPhaseFailed indicates the cluster has failed
	ClusterPhaseFailed ClusterPhase = "Failed"

	// ClusterPhaseUpdating indicates the cluster is being updated
	ClusterPhaseUpdating ClusterPhase = "Updating"
)

// NewClusterCondition creates a new cluster condition
func NewClusterCondition(conditionType string, status metav1.ConditionStatus, reason, message string) metav1.Condition {
	return metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	}
}

// SetClusterCondition sets or updates a condition in the conditions slice
func SetClusterCondition(conditions *[]metav1.Condition, condition metav1.Condition) {
	if conditions == nil {
		return
	}

	existingCondition := FindClusterCondition(*conditions, condition.Type)
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

// FindClusterCondition finds a condition by type
func FindClusterCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}

// IsClusterConditionTrue checks if a condition is true
func IsClusterConditionTrue(conditions []metav1.Condition, conditionType string) bool {
	condition := FindClusterCondition(conditions, conditionType)
	return condition != nil && condition.Status == metav1.ConditionTrue
}

// SetClusterReadyCondition sets the Ready condition
func SetClusterReadyCondition(conditions *[]metav1.Condition, ready bool, reason, message string) {
	status := metav1.ConditionFalse
	if ready {
		status = metav1.ConditionTrue
	}
	SetClusterCondition(conditions, NewClusterCondition(ClusterConditionReady, status, reason, message))
}

// SetClusterProgressingCondition sets the Progressing condition
func SetClusterProgressingCondition(conditions *[]metav1.Condition, progressing bool, reason, message string) {
	status := metav1.ConditionFalse
	if progressing {
		status = metav1.ConditionTrue
	}
	SetClusterCondition(conditions, NewClusterCondition(ClusterConditionProgressing, status, reason, message))
}

// SetClusterDegradedCondition sets the Degraded condition
func SetClusterDegradedCondition(conditions *[]metav1.Condition, degraded bool, reason, message string) {
	status := metav1.ConditionFalse
	if degraded {
		status = metav1.ConditionTrue
	}
	SetClusterCondition(conditions, NewClusterCondition(ClusterConditionDegraded, status, reason, message))
}

// DetermineClusterPhase determines the cluster phase based on conditions
func DetermineClusterPhase(conditions []metav1.Condition) ClusterPhase {
	// Check if progressing
	if IsClusterConditionTrue(conditions, ClusterConditionProgressing) {
		return ClusterPhaseDeploying
	}

	// Check if degraded
	if IsClusterConditionTrue(conditions, ClusterConditionDegraded) {
		return ClusterPhaseDegraded
	}

	// Check if ready
	if IsClusterConditionTrue(conditions, ClusterConditionReady) {
		return ClusterPhaseReady
	}

	// Check component readiness
	managerReady := IsClusterConditionTrue(conditions, ClusterConditionManagerReady)
	indexerReady := IsClusterConditionTrue(conditions, ClusterConditionIndexerReady)
	dashboardReady := IsClusterConditionTrue(conditions, ClusterConditionDashboardReady)

	if !managerReady || !indexerReady || !dashboardReady {
		if managerReady || indexerReady || dashboardReady {
			return ClusterPhaseDeploying
		}
		return ClusterPhasePending
	}

	return ClusterPhasePending
}
