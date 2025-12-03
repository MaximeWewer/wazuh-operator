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

package storage

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// ExpansionStatusUpdate contains the information needed to update expansion status
type ExpansionStatusUpdate struct {
	// Phase is the current expansion phase
	Phase string

	// RequestedSize is the target storage size
	RequestedSize string

	// CurrentSize is the current actual storage size
	CurrentSize string

	// Message is a human-readable description of the current status
	Message string

	// PVCsExpanded is the list of PVCs that have completed expansion
	PVCsExpanded []string

	// PVCsPending is the list of PVCs that are still pending expansion
	PVCsPending []string
}

// NewComponentExpansionStatus creates a new ComponentExpansionStatus from an update
func NewComponentExpansionStatus(update ExpansionStatusUpdate) *v1alpha1.ComponentExpansionStatus {
	return &v1alpha1.ComponentExpansionStatus{
		Phase:              update.Phase,
		RequestedSize:      update.RequestedSize,
		CurrentSize:        update.CurrentSize,
		Message:            update.Message,
		LastTransitionTime: metav1.Now(),
		PVCsExpanded:       update.PVCsExpanded,
		PVCsPending:        update.PVCsPending,
	}
}

// UpdateComponentExpansionStatus updates an existing ComponentExpansionStatus.
// It only updates the LastTransitionTime if the phase has changed.
func UpdateComponentExpansionStatus(existing *v1alpha1.ComponentExpansionStatus, update ExpansionStatusUpdate) *v1alpha1.ComponentExpansionStatus {
	if existing == nil {
		return NewComponentExpansionStatus(update)
	}

	// Create a copy
	result := existing.DeepCopy()

	// Check if phase changed
	phaseChanged := result.Phase != update.Phase

	// Update fields
	result.Phase = update.Phase
	result.RequestedSize = update.RequestedSize
	result.CurrentSize = update.CurrentSize
	result.Message = update.Message
	result.PVCsExpanded = update.PVCsExpanded
	result.PVCsPending = update.PVCsPending

	// Only update LastTransitionTime if phase changed
	if phaseChanged {
		result.LastTransitionTime = metav1.Now()
	}

	return result
}

// CreatePendingStatus creates a status update for the Pending phase
func CreatePendingStatus(requestedSize, currentSize string, pvcsPending []string) ExpansionStatusUpdate {
	return ExpansionStatusUpdate{
		Phase:         constants.VolumeExpansionPhasePending,
		RequestedSize: requestedSize,
		CurrentSize:   currentSize,
		Message:       fmt.Sprintf("Waiting to expand %d PVC(s) from %s to %s", len(pvcsPending), currentSize, requestedSize),
		PVCsPending:   pvcsPending,
	}
}

// CreateInProgressStatus creates a status update for the InProgress phase
func CreateInProgressStatus(requestedSize, currentSize string, pvcsExpanded, pvcsPending []string) ExpansionStatusUpdate {
	return ExpansionStatusUpdate{
		Phase:         constants.VolumeExpansionPhaseInProgress,
		RequestedSize: requestedSize,
		CurrentSize:   currentSize,
		Message:       fmt.Sprintf("Expanding PVCs: %d completed, %d pending", len(pvcsExpanded), len(pvcsPending)),
		PVCsExpanded:  pvcsExpanded,
		PVCsPending:   pvcsPending,
	}
}

// CreateCompletedStatus creates a status update for the Completed phase
func CreateCompletedStatus(requestedSize string, pvcsExpanded []string) ExpansionStatusUpdate {
	return ExpansionStatusUpdate{
		Phase:         constants.VolumeExpansionPhaseCompleted,
		RequestedSize: requestedSize,
		CurrentSize:   requestedSize,
		Message:       fmt.Sprintf("All %d PVC(s) expanded successfully to %s", len(pvcsExpanded), requestedSize),
		PVCsExpanded:  pvcsExpanded,
	}
}

// CreateFailedStatus creates a status update for the Failed phase
func CreateFailedStatus(requestedSize, currentSize, errorMessage string, pvcsExpanded, pvcsPending []string) ExpansionStatusUpdate {
	return ExpansionStatusUpdate{
		Phase:         constants.VolumeExpansionPhaseFailed,
		RequestedSize: requestedSize,
		CurrentSize:   currentSize,
		Message:       errorMessage,
		PVCsExpanded:  pvcsExpanded,
		PVCsPending:   pvcsPending,
	}
}

// ClearExpansionStatus creates an empty status update indicating no expansion is active
func ClearExpansionStatus() *v1alpha1.ComponentExpansionStatus {
	return nil
}

// IsExpansionInProgress returns true if expansion is in progress for any component
func IsExpansionInProgress(status *v1alpha1.VolumeExpansionStatus) bool {
	if status == nil {
		return false
	}

	// Check each component
	for _, component := range []*v1alpha1.ComponentExpansionStatus{
		status.IndexerExpansion,
		status.ManagerMasterExpansion,
		status.ManagerWorkersExpansion,
	} {
		if component != nil {
			switch component.Phase {
			case constants.VolumeExpansionPhasePending, constants.VolumeExpansionPhaseInProgress:
				return true
			}
		}
	}

	return false
}

// IsAnyExpansionFailed returns true if any component expansion has failed
func IsAnyExpansionFailed(status *v1alpha1.VolumeExpansionStatus) bool {
	if status == nil {
		return false
	}

	for _, component := range []*v1alpha1.ComponentExpansionStatus{
		status.IndexerExpansion,
		status.ManagerMasterExpansion,
		status.ManagerWorkersExpansion,
	} {
		if component != nil && component.Phase == constants.VolumeExpansionPhaseFailed {
			return true
		}
	}

	return false
}
