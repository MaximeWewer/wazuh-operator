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

import (
	"errors"
	"fmt"
)

// ErrImmutableFieldChanged indicates an attempt to modify an immutable field
type ErrImmutableFieldChanged struct {
	// Field is the name of the immutable field that was attempted to be changed
	Field string

	// Resource is the resource type (e.g., "StatefulSet")
	Resource string

	// Name is the resource name
	Name string

	// OldValue is the current value of the field
	OldValue string

	// NewValue is the attempted new value
	NewValue string
}

// Error implements the error interface
func (e *ErrImmutableFieldChanged) Error() string {
	msg := fmt.Sprintf("cannot update immutable field %q on %s/%s", e.Field, e.Resource, e.Name)
	if e.OldValue != "" || e.NewValue != "" {
		msg += fmt.Sprintf(" (current: %q, desired: %q)", e.OldValue, e.NewValue)
	}
	return msg
}

// IsImmutableFieldError checks if an error is an ErrImmutableFieldChanged
func IsImmutableFieldError(err error) bool {
	var immutableErr *ErrImmutableFieldChanged
	return errors.As(err, &immutableErr)
}

// ErrDriftDetected indicates that managed resources were modified externally
type ErrDriftDetected struct {
	// Resources lists the resources that have drifted
	Resources []string

	// Details provides additional information about the drift
	Details string
}

// Error implements the error interface
func (e *ErrDriftDetected) Error() string {
	return fmt.Sprintf("drift detected on %d resource(s): %v - %s", len(e.Resources), e.Resources, e.Details)
}

// IsDriftError checks if an error is an ErrDriftDetected
func IsDriftError(err error) bool {
	var driftErr *ErrDriftDetected
	return errors.As(err, &driftErr)
}

// ErrConflict indicates multiple CRDs are trying to manage the same resource
type ErrConflict struct {
	// Resource is the resource being contested
	Resource string

	// Owner is the current owner (namespace/name)
	Owner string

	// Requester is the CRD trying to claim ownership
	Requester string
}

// Error implements the error interface
func (e *ErrConflict) Error() string {
	return fmt.Sprintf("conflict: resource %q is already managed by %s, cannot be claimed by %s",
		e.Resource, e.Owner, e.Requester)
}

// IsConflictError checks if an error is an ErrConflict
func IsConflictError(err error) bool {
	var conflictErr *ErrConflict
	return errors.As(err, &conflictErr)
}

// ErrUpdateFailed indicates a resource update operation failed
type ErrUpdateFailed struct {
	// Resource is the resource type
	Resource string

	// Name is the resource name
	Name string

	// Cause is the underlying error
	Cause error
}

// Error implements the error interface
func (e *ErrUpdateFailed) Error() string {
	return fmt.Sprintf("failed to update %s/%s: %v", e.Resource, e.Name, e.Cause)
}

// Unwrap returns the underlying cause
func (e *ErrUpdateFailed) Unwrap() error {
	return e.Cause
}

// NewImmutableFieldError creates a new ErrImmutableFieldChanged
func NewImmutableFieldError(field, resource, name, oldValue, newValue string) *ErrImmutableFieldChanged {
	return &ErrImmutableFieldChanged{
		Field:    field,
		Resource: resource,
		Name:     name,
		OldValue: oldValue,
		NewValue: newValue,
	}
}

// NewDriftError creates a new ErrDriftDetected
func NewDriftError(resources []string, details string) *ErrDriftDetected {
	return &ErrDriftDetected{
		Resources: resources,
		Details:   details,
	}
}

// NewConflictError creates a new ErrConflict
func NewConflictError(resource, owner, requester string) *ErrConflict {
	return &ErrConflict{
		Resource:  resource,
		Owner:     owner,
		Requester: requester,
	}
}

// NewUpdateFailedError creates a new ErrUpdateFailed
func NewUpdateFailedError(resource, name string, cause error) *ErrUpdateFailed {
	return &ErrUpdateFailed{
		Resource: resource,
		Name:     name,
		Cause:    cause,
	}
}
