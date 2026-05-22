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

// integrationNameRegex matches the logical integration name (without the
// operator-forced "custom-" prefix).
var integrationNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// IntegrationValidator validates WazuhIntegration resources.
type IntegrationValidator struct {
	client client.Client
}

// NewIntegrationValidator creates a new IntegrationValidator.
func NewIntegrationValidator(c client.Client) *IntegrationValidator {
	return &IntegrationValidator{client: c}
}

// IntegrationValidationResult contains the validation results.
type IntegrationValidationResult struct {
	Valid  bool
	Errors []string
}

// Validate performs comprehensive validation of a WazuhIntegration.
func (v *IntegrationValidator) Validate(ctx context.Context, integration *wazuhv1.WazuhIntegration) *IntegrationValidationResult {
	result := &IntegrationValidationResult{Valid: true, Errors: []string{}}

	if err := v.validateName(integration.Spec.Name); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, err.Error())
	}

	if err := v.validateScript(integration.Spec.Script); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, err.Error())
	}

	// Check for duplicate integration names across CRs targeting the same cluster.
	if v.client != nil {
		if errs := v.checkDuplicateNames(ctx, integration); len(errs) > 0 {
			result.Valid = false
			result.Errors = append(result.Errors, errs...)
		}
	}

	return result
}

// validateName validates the logical integration name. The operator forces the
// "custom-" prefix, so the user must NOT include it.
func (v *IntegrationValidator) validateName(name string) error {
	if name == "" {
		return fmt.Errorf("name cannot be empty")
	}
	if strings.HasPrefix(name, "custom-") {
		return fmt.Errorf("name '%s' must not include the 'custom-' prefix; it is added automatically", name)
	}
	if !integrationNameRegex.MatchString(name) {
		return fmt.Errorf("name '%s' is invalid: only alphanumeric, underscores, and hyphens are allowed", name)
	}
	if len(name) > 50 {
		return fmt.Errorf("name '%s' is too long (max 50 characters)", name)
	}
	return nil
}

// validateScript validates the integration script content.
func (v *IntegrationValidator) validateScript(script string) error {
	if strings.TrimSpace(script) == "" {
		return fmt.Errorf("script cannot be empty")
	}
	if !strings.HasPrefix(script, "#!") {
		return fmt.Errorf("script must start with a shebang line (e.g. '#!/usr/bin/env python3')")
	}
	return nil
}

// checkDuplicateNames checks for duplicate integration names across WazuhIntegrations
// that target an overlapping set of clusters.
func (v *IntegrationValidator) checkDuplicateNames(ctx context.Context, integration *wazuhv1.WazuhIntegration) []string {
	var errors []string

	list := &wazuhv1.WazuhIntegrationList{}
	if err := v.client.List(ctx, list, client.InNamespace(integration.Namespace)); err != nil {
		// If we can't list, skip the duplicate check but don't fail.
		return errors
	}

	for _, existing := range list.Items {
		if existing.Name == integration.Name {
			continue
		}
		if !overlapsClusterRefs(existing.Spec.ClusterRefs, integration.Spec.ClusterRefs) {
			continue
		}
		if existing.Spec.ScriptName() == integration.Spec.ScriptName() {
			errors = append(errors, fmt.Sprintf("integration script name '%s' already used by WazuhIntegration '%s' on an overlapping cluster", integration.Spec.ScriptName(), existing.Name))
		}
	}

	return errors
}
