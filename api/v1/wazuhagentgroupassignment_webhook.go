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

package v1

import (
	"context"
	"fmt"
	"path"
	"regexp"

	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var wazuhagentgroupassignmentlog = logf.Log.WithName("wazuhagentgroupassignment-webhook")

// wazuhGroupNamePattern is the accepted Wazuh agent-group name pattern.
var wazuhGroupNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// SetupWazuhAgentGroupAssignmentWebhookWithManager registers the webhook for
// WazuhAgentGroupAssignment in the manager.
func SetupWazuhAgentGroupAssignmentWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &WazuhAgentGroupAssignment{}).
		WithValidator(&WazuhAgentGroupAssignmentCustomValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-resources-wazuh-com-v1-wazuhagentgroupassignment,mutating=false,failurePolicy=fail,sideEffects=None,groups=resources.wazuh.com,resources=wazuhagentgroupassignments,verbs=create;update,versions=v1,name=vwazuhagentgroupassignment.kb.io,admissionReviewVersions=v1

// WazuhAgentGroupAssignmentCustomValidator handles validation for
// WazuhAgentGroupAssignment.
type WazuhAgentGroupAssignmentCustomValidator struct{}

var _ admission.Validator[*WazuhAgentGroupAssignment] = &WazuhAgentGroupAssignmentCustomValidator{}

// ValidateCreate implements webhook.CustomValidator.
func (v *WazuhAgentGroupAssignmentCustomValidator) ValidateCreate(_ context.Context, assignment *WazuhAgentGroupAssignment) (admission.Warnings, error) {
	wazuhagentgroupassignmentlog.Info("validate create", "name", assignment.Name, "namespace", assignment.Namespace)
	return v.validate(assignment)
}

// ValidateUpdate implements webhook.CustomValidator.
func (v *WazuhAgentGroupAssignmentCustomValidator) ValidateUpdate(_ context.Context, _, newAssignment *WazuhAgentGroupAssignment) (admission.Warnings, error) {
	wazuhagentgroupassignmentlog.Info("validate update", "name", newAssignment.Name, "namespace", newAssignment.Namespace)
	return v.validate(newAssignment)
}

// ValidateDelete implements webhook.CustomValidator.
func (v *WazuhAgentGroupAssignmentCustomValidator) ValidateDelete(_ context.Context, assignment *WazuhAgentGroupAssignment) (admission.Warnings, error) {
	wazuhagentgroupassignmentlog.Info("validate delete", "name", assignment.Name, "namespace", assignment.Namespace)
	return nil, nil
}

// validate validates the WazuhAgentGroupAssignment spec.
func (v *WazuhAgentGroupAssignmentCustomValidator) validate(assignment *WazuhAgentGroupAssignment) (admission.Warnings, error) {
	var allErrors []string
	spec := &assignment.Spec

	// ClusterRefs non-empty with name+namespace set.
	if len(spec.ClusterRefs) == 0 {
		allErrors = append(allErrors, "spec.clusterRefs: at least one cluster reference is required")
	}
	for i, ref := range spec.ClusterRefs {
		if ref.Name == "" {
			allErrors = append(allErrors, fmt.Sprintf("spec.clusterRefs[%d].name: must not be empty", i))
		}
		if ref.Namespace == "" {
			allErrors = append(allErrors, fmt.Sprintf("spec.clusterRefs[%d].namespace: must not be empty", i))
		}
	}

	// Groups non-empty and each a valid Wazuh group name.
	if len(spec.Groups) == 0 {
		allErrors = append(allErrors, "spec.groups: at least one group is required")
	}
	for i, g := range spec.Groups {
		if g == "000" {
			allErrors = append(allErrors, fmt.Sprintf("spec.groups[%d]: %q is not a valid group name", i, g))
			continue
		}
		if len(g) > 255 || !wazuhGroupNamePattern.MatchString(g) {
			allErrors = append(allErrors, fmt.Sprintf("spec.groups[%d]: %q is not a valid Wazuh group name (must match %s, length <= 255)", i, g, wazuhGroupNamePattern.String()))
		}
	}

	// Selector must have at least one non-empty list.
	sel := spec.Selector
	if len(sel.AgentNames) == 0 && len(sel.NamePatterns) == 0 && len(sel.NameRegex) == 0 && len(sel.OSPlatforms) == 0 {
		allErrors = append(allErrors, "spec.selector: at least one of agentNames, namePatterns, nameRegex or osPlatforms must be non-empty")
	}

	// Each glob pattern must be valid.
	for i, p := range sel.NamePatterns {
		if _, err := path.Match(p, "probe"); err != nil {
			allErrors = append(allErrors, fmt.Sprintf("spec.selector.namePatterns[%d]: invalid glob %q: %v", i, p, err))
		}
	}

	// Each regex must compile.
	for i, re := range sel.NameRegex {
		if _, err := regexp.Compile(re); err != nil {
			allErrors = append(allErrors, fmt.Sprintf("spec.selector.nameRegex[%d]: invalid regex %q: %v", i, re, err))
		}
	}

	if len(allErrors) > 0 {
		return nil, fmt.Errorf("validation failed: %v", allErrors)
	}
	return nil, nil
}
