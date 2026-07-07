/*
Copyright 2026.

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

package validation

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

// CDBListValidator validates WazuhCDBList resources.
type CDBListValidator struct {
	client client.Client
}

// NewCDBListValidator creates a new CDBListValidator.
func NewCDBListValidator(c client.Client) *CDBListValidator {
	return &CDBListValidator{client: c}
}

var cdbListNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Validate performs validation of a WazuhCDBList.
func (v *CDBListValidator) Validate(ctx context.Context, list *wazuhv1.WazuhCDBList) *ValidationResult {
	result := &ValidationResult{Valid: true, Errors: []string{}}

	// List name must be a safe filename.
	name := list.Spec.ListName
	switch {
	case name == "":
		result.addError("listName cannot be empty")
	case len(name) > 64:
		result.addError(fmt.Sprintf("listName '%s' is too long (max 64 characters)", name))
	case !cdbListNameRegex.MatchString(name):
		result.addError(fmt.Sprintf("listName '%s' contains invalid characters (only alphanumeric, underscores, and hyphens allowed)", name))
	}

	// Exactly one content source must be provided.
	sources := 0
	if len(list.Spec.Entries) > 0 {
		sources++
	}
	if strings.TrimSpace(list.Spec.Content) != "" {
		sources++
	}
	if list.Spec.Source != nil {
		sources++
	}
	switch sources {
	case 0:
		result.addError("exactly one content source is required: set entries, content, or source")
	case 1:
		// ok
	default:
		result.addError("entries, content, and source are mutually exclusive: set exactly one")
	}

	// Validate static entries.
	for i, e := range list.Spec.Entries {
		if strings.TrimSpace(e.Key) == "" {
			result.addError(fmt.Sprintf("entries[%d].key cannot be empty", i))
			continue
		}
		if strings.ContainsAny(e.Key, ":\n\r") {
			result.addError(fmt.Sprintf("entries[%d].key '%s' must not contain ':' or newlines", i, e.Key))
		}
		if strings.ContainsAny(e.Value, "\n\r") {
			result.addError(fmt.Sprintf("entries[%d].value must not contain newlines", i))
		}
	}

	// Format and skipLines apply only to raw content/source, not structured entries.
	if len(list.Spec.Entries) > 0 {
		if list.Spec.Format != "" && list.Spec.Format != wazuhv1.CDBListFormatCDB {
			result.addError(fmt.Sprintf("format '%s' cannot be used with entries; use content or source", list.Spec.Format))
		}
		if list.Spec.SkipLines > 0 {
			result.addError("skipLines cannot be used with entries; use content or source")
		}
	}

	// Validate source URL scheme.
	if src := list.Spec.Source; src != nil {
		if !strings.HasPrefix(src.URL, "http://") && !strings.HasPrefix(src.URL, "https://") {
			result.addError(fmt.Sprintf("source.url '%s' must start with http:// or https://", src.URL))
		}
	}

	return result
}

// addError records a validation error and marks the result invalid.
func (r *ValidationResult) addError(msg string) {
	r.Valid = false
	r.Errors = append(r.Errors, msg)
}
