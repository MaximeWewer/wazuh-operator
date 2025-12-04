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

// Volume expansion phase constants
// These represent the phases of a PVC volume expansion operation
const (
	// VolumeExpansionPhasePending indicates expansion has been requested but not yet started
	VolumeExpansionPhasePending = "Pending"

	// VolumeExpansionPhaseInProgress indicates expansion is currently in progress
	// Some PVCs may have been expanded while others are still pending
	VolumeExpansionPhaseInProgress = "InProgress"

	// VolumeExpansionPhaseCompleted indicates all PVCs have been successfully expanded
	VolumeExpansionPhaseCompleted = "Completed"

	// VolumeExpansionPhaseFailed indicates the expansion operation failed
	// Check the Message field for details about the failure
	VolumeExpansionPhaseFailed = "Failed"
)

// Component phase constants
const (
	// ComponentPhasePending indicates the component is pending creation
	ComponentPhasePending = "Pending"

	// ComponentPhaseCreating indicates the component is being created
	ComponentPhaseCreating = "Creating"

	// ComponentPhaseRunning indicates the component is running normally
	ComponentPhaseRunning = "Running"

	// ComponentPhaseUpdating indicates the component is being updated
	ComponentPhaseUpdating = "Updating"

	// ComponentPhaseFailed indicates the component has failed
	ComponentPhaseFailed = "Failed"

	// ComponentPhaseDeleting indicates the component is being deleted
	ComponentPhaseDeleting = "Deleting"
)

// Filebeat condition type constants
const (
	// ConditionTypeConfigMapReady indicates ConfigMap has been created/updated
	ConditionTypeConfigMapReady = "ConfigMapReady"

	// ConditionTypeTemplateApplied indicates index template configuration is valid
	ConditionTypeTemplateApplied = "TemplateApplied"

	// ConditionTypePipelineApplied indicates pipeline configuration is valid
	ConditionTypePipelineApplied = "PipelineApplied"

	// ConditionTypeReconciled indicates overall reconciliation status
	ConditionTypeReconciled = "Reconciled"
)
