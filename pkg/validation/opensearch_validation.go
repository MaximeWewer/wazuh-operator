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

package validation

import (
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation/field"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
)

// ValidateOpenSearchIndex validates an OpenSearchIndex resource
func ValidateOpenSearchIndex(index *wazuhv1alpha1.OpenSearchIndex) field.ErrorList {
	var allErrs field.ErrorList

	specPath := field.NewPath("spec")
	metaPath := field.NewPath("metadata")

	// Validate index name (CR name is used as the index name)
	if index.Name == "" {
		allErrs = append(allErrs, field.Required(metaPath.Child("name"), "index name is required"))
	} else if !isValidIndexName(index.Name) {
		allErrs = append(allErrs, field.Invalid(metaPath.Child("name"), index.Name, "invalid index name format"))
	}

	// Validate shards if settings are provided
	if index.Spec.Settings != nil {
		if index.Spec.Settings.NumberOfShards != nil && *index.Spec.Settings.NumberOfShards < 1 {
			allErrs = append(allErrs, field.Invalid(specPath.Child("settings").Child("numberOfShards"),
				*index.Spec.Settings.NumberOfShards, "shards must be at least 1"))
		}

		// Validate replicas
		if index.Spec.Settings.NumberOfReplicas != nil && *index.Spec.Settings.NumberOfReplicas < 0 {
			allErrs = append(allErrs, field.Invalid(specPath.Child("settings").Child("numberOfReplicas"),
				*index.Spec.Settings.NumberOfReplicas, "replicas must be non-negative"))
		}
	}

	return allErrs
}

// ValidateOpenSearchIndexTemplate validates an OpenSearchIndexTemplate resource
func ValidateOpenSearchIndexTemplate(template *wazuhv1alpha1.OpenSearchIndexTemplate) field.ErrorList {
	var allErrs field.ErrorList

	specPath := field.NewPath("spec")
	metaPath := field.NewPath("metadata")

	// Validate template name (CR name is used as the template name)
	if template.Name == "" {
		allErrs = append(allErrs, field.Required(metaPath.Child("name"), "template name is required"))
	}

	// Validate index patterns
	if len(template.Spec.IndexPatterns) == 0 {
		allErrs = append(allErrs, field.Required(specPath.Child("indexPatterns"), "at least one index pattern is required"))
	}

	return allErrs
}

// ValidateOpenSearchUser validates an OpenSearchUser resource
func ValidateOpenSearchUser(user *wazuhv1alpha1.OpenSearchUser) field.ErrorList {
	var allErrs field.ErrorList

	metaPath := field.NewPath("metadata")
	specPath := field.NewPath("spec")

	// Validate user name (CR name is used as the username)
	if user.Name == "" {
		allErrs = append(allErrs, field.Required(metaPath.Child("name"), "username is required"))
	} else if !isValidUsername(user.Name) {
		allErrs = append(allErrs, field.Invalid(metaPath.Child("name"), user.Name, "invalid username format"))
	}

	// Validate password source - either hash or secret must be provided
	if user.Spec.Hash == "" && user.Spec.PasswordSecret == nil {
		allErrs = append(allErrs, field.Required(specPath, "either hash or passwordSecret must be specified"))
	}

	return allErrs
}

// ValidateOpenSearchRole validates an OpenSearchRole resource
func ValidateOpenSearchRole(role *wazuhv1alpha1.OpenSearchRole) field.ErrorList {
	var allErrs field.ErrorList

	metaPath := field.NewPath("metadata")

	// Validate role name (CR name is used as the role name)
	if role.Name == "" {
		allErrs = append(allErrs, field.Required(metaPath.Child("name"), "role name is required"))
	}

	return allErrs
}

// ValidateOpenSearchRoleMapping validates an OpenSearchRoleMapping resource
func ValidateOpenSearchRoleMapping(mapping *wazuhv1alpha1.OpenSearchRoleMapping) field.ErrorList {
	var allErrs field.ErrorList

	specPath := field.NewPath("spec")
	metaPath := field.NewPath("metadata")

	// Validate role name (CR name is used as the role name for mapping)
	if mapping.Name == "" {
		allErrs = append(allErrs, field.Required(metaPath.Child("name"), "role mapping name is required"))
	}

	// Validate that at least one mapping type is specified
	if len(mapping.Spec.Users) == 0 && len(mapping.Spec.BackendRoles) == 0 && len(mapping.Spec.Hosts) == 0 {
		allErrs = append(allErrs, field.Required(specPath, "at least one of users, backendRoles, or hosts must be specified"))
	}

	return allErrs
}

// ValidateOpenSearchTenant validates an OpenSearchTenant resource
func ValidateOpenSearchTenant(tenant *wazuhv1alpha1.OpenSearchTenant) field.ErrorList {
	var allErrs field.ErrorList

	metaPath := field.NewPath("metadata")

	// Validate tenant name (CR name is used as the tenant name)
	if tenant.Name == "" {
		allErrs = append(allErrs, field.Required(metaPath.Child("name"), "tenant name is required"))
	}

	return allErrs
}

// ValidateOpenSearchActionGroup validates an OpenSearchActionGroup resource
func ValidateOpenSearchActionGroup(ag *wazuhv1alpha1.OpenSearchActionGroup) field.ErrorList {
	var allErrs field.ErrorList

	specPath := field.NewPath("spec")
	metaPath := field.NewPath("metadata")

	// Validate action group name (CR name is used as the action group name)
	if ag.Name == "" {
		allErrs = append(allErrs, field.Required(metaPath.Child("name"), "action group name is required"))
	}

	// Validate that actions are provided
	if len(ag.Spec.AllowedActions) == 0 {
		allErrs = append(allErrs, field.Required(specPath.Child("allowedActions"), "at least one action is required"))
	}

	return allErrs
}

// ValidateOpenSearchISMPolicy validates an OpenSearchISMPolicy resource
func ValidateOpenSearchISMPolicy(policy *wazuhv1alpha1.OpenSearchISMPolicy) field.ErrorList {
	var allErrs field.ErrorList

	specPath := field.NewPath("spec")
	metaPath := field.NewPath("metadata")

	// Validate policy name (CR name is used as the policy ID)
	if policy.Name == "" {
		allErrs = append(allErrs, field.Required(metaPath.Child("name"), "policy name is required"))
	}

	// Validate default state
	if policy.Spec.DefaultState == "" {
		allErrs = append(allErrs, field.Required(specPath.Child("defaultState"), "default state is required"))
	}

	// Validate states
	if len(policy.Spec.States) == 0 {
		allErrs = append(allErrs, field.Required(specPath.Child("states"), "at least one state is required"))
	}

	return allErrs
}

// ValidateOpenSearchSnapshotPolicy validates an OpenSearchSnapshotPolicy resource
func ValidateOpenSearchSnapshotPolicy(policy *wazuhv1alpha1.OpenSearchSnapshotPolicy) field.ErrorList {
	var allErrs field.ErrorList

	specPath := field.NewPath("spec")
	metaPath := field.NewPath("metadata")

	// Validate policy name (CR name is used as the policy name)
	if policy.Name == "" {
		allErrs = append(allErrs, field.Required(metaPath.Child("name"), "policy name is required"))
	}

	// Validate repository
	if policy.Spec.Repository.Name == "" {
		allErrs = append(allErrs, field.Required(specPath.Child("repository").Child("name"), "repository name is required"))
	}

	return allErrs
}

// isValidIndexName validates an OpenSearch index name
func isValidIndexName(name string) bool {
	// Index names cannot:
	// - Start with _, -, or +
	// - Contain uppercase letters
	// - Contain special characters except - and _
	if len(name) == 0 || len(name) > 255 {
		return false
	}
	if strings.HasPrefix(name, "_") || strings.HasPrefix(name, "-") || strings.HasPrefix(name, "+") {
		return false
	}
	if name != strings.ToLower(name) {
		return false
	}
	validRegex := regexp.MustCompile(`^[a-z0-9][a-z0-9_\-\.]*$`)
	return validRegex.MatchString(name)
}

// isValidUsername validates an OpenSearch username
func isValidUsername(username string) bool {
	if len(username) == 0 || len(username) > 64 {
		return false
	}
	validRegex := regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)
	return validRegex.MatchString(username)
}
