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

// Package validation provides validation functions for CRDs
package validation

import (
	"fmt"
	"regexp"

	"k8s.io/apimachinery/pkg/util/validation/field"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

// ValidateWazuhCluster validates a WazuhCluster resource
func ValidateWazuhCluster(cluster *wazuhv1.WazuhCluster) field.ErrorList {
	var allErrs field.ErrorList

	// Validate name
	if cluster.Name == "" {
		allErrs = append(allErrs, field.Required(field.NewPath("metadata").Child("name"), "name is required"))
	}

	// Validate version
	specPath := field.NewPath("spec")
	if cluster.Spec.Version != "" {
		if !isValidVersion(cluster.Spec.Version) {
			allErrs = append(allErrs, field.Invalid(specPath.Child("version"), cluster.Spec.Version, "invalid version format"))
		}
	}

	// Validate Manager if inline mode is used
	if cluster.Spec.Manager != nil {
		// Validate Workers replicas
		if cluster.Spec.Manager.Workers.Replicas != nil && *cluster.Spec.Manager.Workers.Replicas < 0 {
			allErrs = append(allErrs, field.Invalid(specPath.Child("manager").Child("workers").Child("replicas"),
				*cluster.Spec.Manager.Workers.Replicas, "replicas must be non-negative"))
		}
	}

	// Validate Indexer if inline mode is used
	if cluster.Spec.Indexer != nil {
		if cluster.Spec.Indexer.Replicas < 1 {
			allErrs = append(allErrs, field.Invalid(specPath.Child("indexer").Child("replicas"),
				cluster.Spec.Indexer.Replicas, "indexer replicas must be at least 1"))
		}
	}

	// Validate Dashboard if inline mode is used
	if cluster.Spec.Dashboard != nil {
		if cluster.Spec.Dashboard.Replicas < 0 {
			allErrs = append(allErrs, field.Invalid(specPath.Child("dashboard").Child("replicas"),
				cluster.Spec.Dashboard.Replicas, "dashboard replicas must be non-negative"))
		}
	}

	return allErrs
}

// ValidateWazuhRule validates a WazuhRule resource
func ValidateWazuhRule(rule *wazuhv1.WazuhRule) field.ErrorList {
	var allErrs field.ErrorList

	specPath := field.NewPath("spec")

	// Validate that rules content is provided
	if rule.Spec.Rules == "" {
		allErrs = append(allErrs, field.Required(specPath.Child("rules"), "rule content is required"))
	}

	// Validate rule name
	if rule.Spec.RuleName == "" {
		allErrs = append(allErrs, field.Required(specPath.Child("ruleName"), "rule name is required"))
	}

	return allErrs
}

// ValidateWazuhDecoder validates a WazuhDecoder resource
func ValidateWazuhDecoder(decoder *wazuhv1.WazuhDecoder) field.ErrorList {
	var allErrs field.ErrorList

	specPath := field.NewPath("spec")

	// Validate that decoders content is provided
	if decoder.Spec.Decoders == "" {
		allErrs = append(allErrs, field.Required(specPath.Child("decoders"), "decoder content is required"))
	}

	// Validate decoder name
	if decoder.Spec.DecoderName == "" {
		allErrs = append(allErrs, field.Required(specPath.Child("decoderName"), "decoder name is required"))
	}

	return allErrs
}

// ValidateWazuhCertificate validates a WazuhCertificate resource
func ValidateWazuhCertificate(cert *wazuhv1.WazuhCertificate) field.ErrorList {
	var allErrs field.ErrorList

	specPath := field.NewPath("spec")

	// Validate certificate type
	validTypes := []wazuhv1.CertificateType{
		wazuhv1.CertificateTypeCA,
		wazuhv1.CertificateTypeNode,
		wazuhv1.CertificateTypeAdmin,
		wazuhv1.CertificateTypeFilebeat,
		wazuhv1.CertificateTypeIndexer,
		wazuhv1.CertificateTypeDashboard,
	}
	if !isValidCertificateType(cert.Spec.Type, validTypes) {
		allErrs = append(allErrs, field.NotSupported(specPath.Child("type"), string(cert.Spec.Type), toStringSlice(validTypes)))
	}

	return allErrs
}

// toStringSlice converts CertificateType slice to string slice
func toStringSlice(types []wazuhv1.CertificateType) []string {
	result := make([]string, len(types))
	for i, t := range types {
		result[i] = string(t)
	}
	return result
}

// isValidCertificateType checks if a certificate type is valid
func isValidCertificateType(certType wazuhv1.CertificateType, validTypes []wazuhv1.CertificateType) bool {
	for _, t := range validTypes {
		if t == certType {
			return true
		}
	}
	return false
}

// isValidVersion checks if a version string is valid
func isValidVersion(version string) bool {
	// Allow semantic versioning patterns like 4.7.0, 4.7.0-1, etc.
	versionRegex := regexp.MustCompile(`^\d+\.\d+\.\d+(-\d+)?$`)
	return versionRegex.MatchString(version)
}

// ValidationError wraps field errors for easy display
type ValidationError struct {
	Errors field.ErrorList
}

func (e *ValidationError) Error() string {
	if len(e.Errors) == 0 {
		return ""
	}
	return fmt.Sprintf("validation failed: %v", e.Errors.ToAggregate().Error())
}

// NewValidationError creates a new validation error
func NewValidationError(errs field.ErrorList) error {
	if len(errs) == 0 {
		return nil
	}
	return &ValidationError{Errors: errs}
}
