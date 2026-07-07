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

// activeResponseNameRegex matches the active response / command name.
var activeResponseNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// ActiveResponseValidator validates WazuhActiveResponse resources.
type ActiveResponseValidator struct {
	client client.Client
}

// NewActiveResponseValidator creates a new ActiveResponseValidator.
func NewActiveResponseValidator(c client.Client) *ActiveResponseValidator {
	return &ActiveResponseValidator{client: c}
}

// Validate performs validation of a WazuhActiveResponse.
func (v *ActiveResponseValidator) Validate(ctx context.Context, ar *wazuhv1.WazuhActiveResponse) *ValidationResult {
	result := &ValidationResult{Valid: true, Errors: []string{}}

	name := ar.Spec.Name
	switch {
	case name == "":
		result.addError("name cannot be empty")
	case len(name) > 50:
		result.addError(fmt.Sprintf("name '%s' is too long (max 50 characters)", name))
	case !activeResponseNameRegex.MatchString(name):
		result.addError(fmt.Sprintf("name '%s' is invalid: only alphanumeric, underscores, and hyphens are allowed", name))
	}

	if strings.TrimSpace(ar.Spec.Script) == "" {
		result.addError("script cannot be empty")
	} else if !strings.HasPrefix(ar.Spec.Script, "#!") {
		result.addError("script must start with a shebang line (e.g. '#!/usr/bin/env python3')")
	}

	if ar.Spec.Location == "defined-agent" && strings.TrimSpace(ar.Spec.AgentID) == "" {
		result.addError("agentID is required when location is 'defined-agent'")
	}
	if ar.Spec.AgentID != "" && ar.Spec.Location != "defined-agent" {
		result.addError("agentID may only be set when location is 'defined-agent'")
	}

	// A trigger must be selectable: at least one of level, rulesID, or rulesGroup.
	if ar.Spec.Level == nil && len(ar.Spec.RulesID) == 0 && strings.TrimSpace(ar.Spec.RulesGroup) == "" {
		result.addError("at least one trigger is required: set level, rulesID, or rulesGroup")
	}

	if ar.Spec.Timeout != nil && !ar.Spec.TimeoutAllowed {
		result.addError("timeout requires timeoutAllowed: true (Wazuh ignores <timeout> without <timeout_allowed>)")
	}

	// Command names must be unique across CRs targeting overlapping clusters.
	if v.client != nil {
		if errs := v.checkDuplicateNames(ctx, ar); len(errs) > 0 {
			result.Errors = append(result.Errors, errs...)
			result.Valid = false
		}
	}

	return result
}

// checkDuplicateNames checks for duplicate command names across WazuhActiveResponses
// that target an overlapping set of clusters.
func (v *ActiveResponseValidator) checkDuplicateNames(ctx context.Context, ar *wazuhv1.WazuhActiveResponse) []string {
	var errors []string

	list := &wazuhv1.WazuhActiveResponseList{}
	if err := v.client.List(ctx, list, client.InNamespace(ar.Namespace)); err != nil {
		return errors
	}

	for _, existing := range list.Items {
		if existing.Name == ar.Name {
			continue
		}
		if !overlapsClusterRefs(existing.Spec.ClusterRefs, ar.Spec.ClusterRefs) {
			continue
		}
		if existing.Spec.Name == ar.Spec.Name {
			errors = append(errors, fmt.Sprintf("active response command name '%s' already used by WazuhActiveResponse '%s' on an overlapping cluster", ar.Spec.Name, existing.Name))
		}
	}

	return errors
}
