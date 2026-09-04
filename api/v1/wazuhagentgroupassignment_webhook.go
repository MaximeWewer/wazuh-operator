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
	spec := &assignment.Spec

	var allErrors []string
	allErrors = append(allErrors, validateAssignmentClusterRefs(spec.ClusterRefs)...)
	allErrors = append(allErrors, validateAssignmentGroups(spec.Groups)...)
	allErrors = append(allErrors, validateAssignmentSelector(&spec.Selector)...)

	if len(allErrors) > 0 {
		return nil, fmt.Errorf("validation failed: %v", allErrors)
	}
	return nil, nil
}

// validateAssignmentClusterRefs requires a non-empty list of fully qualified refs.
func validateAssignmentClusterRefs(refs []WazuhClusterRef) []string {
	var errs []string
	if len(refs) == 0 {
		errs = append(errs, "spec.clusterRefs: at least one cluster reference is required")
	}
	for i, ref := range refs {
		if ref.Name == "" {
			errs = append(errs, fmt.Sprintf("spec.clusterRefs[%d].name: must not be empty", i))
		}
		if ref.Namespace == "" {
			errs = append(errs, fmt.Sprintf("spec.clusterRefs[%d].namespace: must not be empty", i))
		}
	}
	return errs
}

// validateAssignmentGroups requires a non-empty list of valid Wazuh group names.
// "000" is the built-in default group and cannot be assigned explicitly.
func validateAssignmentGroups(groups []string) []string {
	var errs []string
	if len(groups) == 0 {
		errs = append(errs, "spec.groups: at least one group is required")
	}
	for i, g := range groups {
		if g == "000" {
			errs = append(errs, fmt.Sprintf("spec.groups[%d]: %q is not a valid group name", i, g))
			continue
		}
		if len(g) > 255 || !wazuhGroupNamePattern.MatchString(g) {
			errs = append(errs, fmt.Sprintf("spec.groups[%d]: %q is not a valid Wazuh group name (must match %s, length <= 255)", i, g, wazuhGroupNamePattern.String()))
		}
	}
	return errs
}

// validateAssignmentSelector requires at least one match criterion and checks that
// every glob and regex - in the selector and in its exclusion block - is well formed.
func validateAssignmentSelector(sel *AgentSelector) []string {
	var errs []string

	if len(sel.AgentNames) == 0 && len(sel.NamePatterns) == 0 && len(sel.NameRegex) == 0 && len(sel.OSPlatforms) == 0 {
		errs = append(errs, "spec.selector: at least one of agentNames, namePatterns, nameRegex or osPlatforms must be non-empty")
	}

	errs = append(errs, validateGlobsAndRegexes("spec.selector", sel.NamePatterns, sel.NameRegex)...)

	// requireOsPlatform is meaningless without osPlatforms to filter on.
	if sel.RequireOSPlatform && len(sel.OSPlatforms) == 0 {
		errs = append(errs, "spec.selector.requireOsPlatform: requires osPlatforms to be non-empty")
	}

	if sel.Exclude != nil {
		errs = append(errs, validateGlobsAndRegexes("spec.selector.exclude", sel.Exclude.NamePatterns, sel.Exclude.NameRegex)...)
	}

	return errs
}

// validateGlobsAndRegexes reports malformed glob patterns and regexes under the
// given spec field prefix.
func validateGlobsAndRegexes(fieldPrefix string, patterns, regexes []string) []string {
	var errs []string
	for i, p := range patterns {
		if _, err := path.Match(p, "probe"); err != nil {
			errs = append(errs, fmt.Sprintf("%s.namePatterns[%d]: invalid glob %q: %v", fieldPrefix, i, p, err))
		}
	}
	for i, re := range regexes {
		if _, err := regexp.Compile(re); err != nil {
			errs = append(errs, fmt.Sprintf("%s.nameRegex[%d]: invalid regex %q: %v", fieldPrefix, i, re, err))
		}
	}
	return errs
}
