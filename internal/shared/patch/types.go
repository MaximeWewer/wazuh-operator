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

package patch

// ChangeReason describes why a resource needs updating
type ChangeReason string

const (
	// ReasonNoChange indicates no changes were detected
	ReasonNoChange ChangeReason = "no-change"

	// ReasonSpecChange indicates spec fields changed (version, resources, etc.)
	ReasonSpecChange ChangeReason = "spec-change"

	// ReasonConfigChange indicates ConfigMap/Secret content changed
	ReasonConfigChange ChangeReason = "config-change"

	// ReasonCertChange indicates certificate content changed
	ReasonCertChange ChangeReason = "cert-change"

	// ReasonReplicaChange indicates replica count changed
	ReasonReplicaChange ChangeReason = "replica-change"

	// ReasonVersionChange indicates version/image changed
	ReasonVersionChange ChangeReason = "version-change"

	// ReasonResourceChange indicates resource requirements changed
	ReasonResourceChange ChangeReason = "resource-change"

	// ReasonDriftDetected indicates external modification was detected
	ReasonDriftDetected ChangeReason = "drift-detected"

	// ReasonNotFound indicates the resource doesn't exist yet
	ReasonNotFound ChangeReason = "not-found"

	// ReasonGenerationChange indicates CRD generation changed
	ReasonGenerationChange ChangeReason = "generation-change"
)

// ChangeResult describes what changed between desired and current state
type ChangeResult struct {
	// NeedsUpdate indicates whether the resource needs to be updated
	NeedsUpdate bool

	// NeedsCreate indicates the resource doesn't exist and needs to be created
	NeedsCreate bool

	// NeedsRestart indicates pods need to be restarted (config/cert change)
	NeedsRestart bool

	// Reason describes why the update is needed
	Reason ChangeReason

	// ChangedFields lists which fields changed (for logging/events)
	ChangedFields []string

	// OldHash is the hash from the current resource annotation
	OldHash string

	// NewHash is the computed hash from the desired spec
	NewHash string

	// Message provides a human-readable description of the change
	Message string
}

// NoChangeResult returns a ChangeResult indicating no changes are needed
func NoChangeResult() *ChangeResult {
	return &ChangeResult{
		NeedsUpdate: false,
		Reason:      ReasonNoChange,
		Message:     "No changes detected",
	}
}

// CreateResult returns a ChangeResult indicating the resource needs to be created
func CreateResult() *ChangeResult {
	return &ChangeResult{
		NeedsCreate: true,
		NeedsUpdate: true,
		Reason:      ReasonNotFound,
		Message:     "Resource does not exist, will be created",
	}
}

// UpdateResult creates a ChangeResult for an update with the given reason
func UpdateResult(reason ChangeReason, changedFields []string, oldHash, newHash, message string) *ChangeResult {
	return &ChangeResult{
		NeedsUpdate:   true,
		Reason:        reason,
		ChangedFields: changedFields,
		OldHash:       oldHash,
		NewHash:       newHash,
		Message:       message,
	}
}

// RestartResult creates a ChangeResult that requires pod restart
func RestartResult(reason ChangeReason, oldHash, newHash, message string) *ChangeResult {
	return &ChangeResult{
		NeedsUpdate:  true,
		NeedsRestart: true,
		Reason:       reason,
		OldHash:      oldHash,
		NewHash:      newHash,
		Message:      message,
	}
}

// String returns a string representation of the ChangeResult
func (r *ChangeResult) String() string {
	if !r.NeedsUpdate && !r.NeedsCreate {
		return "no changes needed"
	}
	action := "update"
	if r.NeedsCreate {
		action = "create"
	}
	restart := ""
	if r.NeedsRestart {
		restart = " (restart required)"
	}
	return action + " needed: " + r.Message + restart
}
