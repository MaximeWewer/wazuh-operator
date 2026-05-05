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

// Package validation provides validation logic for Wazuh resources
package validation

import (
	"context"
	"encoding/xml"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

// RuleValidator validates WazuhRule resources
type RuleValidator struct {
	client client.Client
}

// NewRuleValidator creates a new RuleValidator
func NewRuleValidator(c client.Client) *RuleValidator {
	return &RuleValidator{
		client: c,
	}
}

// ValidationResult contains the validation results
type ValidationResult struct {
	Valid  bool
	Errors []string
}

// RuleGroup represents a Wazuh rule group in XML
type RuleGroup struct {
	XMLName xml.Name `xml:"group"`
	Name    string   `xml:"name,attr"`
	Rules   []Rule   `xml:"rule"`
}

// Rule represents a Wazuh rule in XML
type Rule struct {
	XMLName     xml.Name `xml:"rule"`
	ID          string   `xml:"id,attr"`
	Level       string   `xml:"level,attr"`
	Description string   `xml:"description"`
}

// Validate performs comprehensive validation of a WazuhRule
func (v *RuleValidator) Validate(ctx context.Context, rule *wazuhv1.WazuhRule) *ValidationResult {
	result := &ValidationResult{
		Valid:  true,
		Errors: []string{},
	}

	// Validate XML syntax
	if err := v.validateXMLSyntax(rule.Spec.Rules); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("invalid XML syntax: %v", err))
	}

	// Validate rule IDs
	if errs := v.validateRuleIDs(rule.Spec.Rules, rule.Spec.RuleID); len(errs) > 0 {
		result.Valid = false
		result.Errors = append(result.Errors, errs...)
	}

	// Validate rule name
	if err := v.validateRuleName(rule.Spec.RuleName); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, err.Error())
	}

	// Check for duplicate rule IDs in the same cluster
	if v.client != nil {
		if errs := v.checkDuplicateRuleIDs(ctx, rule); len(errs) > 0 {
			result.Valid = false
			result.Errors = append(result.Errors, errs...)
		}
	}

	return result
}

// validateXMLSyntax validates that the rule content is valid XML
func (v *RuleValidator) validateXMLSyntax(content string) error {
	if content == "" {
		return fmt.Errorf("rule content cannot be empty")
	}

	// Check if content looks like XML (starts with < after trimming whitespace)
	trimmed := strings.TrimSpace(content)
	if !strings.HasPrefix(trimmed, "<") {
		return fmt.Errorf("content does not appear to be XML (must start with '<')")
	}

	// Try to parse as a group element (most common structure)
	var group RuleGroup
	if err := xml.Unmarshal([]byte(content), &group); err != nil {
		// Try wrapping in a root element if it fails (for multiple elements)
		wrapped := "<root>" + content + "</root>"
		var root struct {
			XMLName xml.Name `xml:"root"`
			Content []byte   `xml:",innerxml"`
		}
		if wrapErr := xml.Unmarshal([]byte(wrapped), &root); wrapErr != nil {
			return fmt.Errorf("failed to parse XML: %w", err)
		}
	}

	// Verify content contains at least one rule or group element
	if !strings.Contains(content, "<rule") && !strings.Contains(content, "<group") {
		return fmt.Errorf("content must contain at least one <rule> or <group> element")
	}

	return nil
}

// validateRuleIDs validates that rule IDs are in the custom range (100000-999999)
func (v *RuleValidator) validateRuleIDs(content string, specRuleID int32) []string {
	var errors []string

	// Extract rule IDs from XML content
	ruleIDRegex := regexp.MustCompile(`<rule[^>]+id\s*=\s*["'](\d+)["']`)
	matches := ruleIDRegex.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			idStr := match[1]
			id, err := strconv.Atoi(idStr)
			if err != nil {
				errors = append(errors, fmt.Sprintf("invalid rule ID format: %s", idStr))
				continue
			}

			// Custom rules should be in range 100000-999999
			if id < 100000 || id > 999999 {
				errors = append(errors, fmt.Sprintf("rule ID %d is outside custom range (100000-999999)", id))
			}
		}
	}

	// If spec.ruleID is set, validate it too
	if specRuleID != 0 && (specRuleID < 100000 || specRuleID > 999999) {
		errors = append(errors, fmt.Sprintf("spec.ruleID %d is outside custom range (100000-999999)", specRuleID))
	}

	return errors
}

// validateRuleName validates the rule name format
func (v *RuleValidator) validateRuleName(name string) error {
	if name == "" {
		return fmt.Errorf("rule name cannot be empty")
	}

	// Rule name should be a valid filename (alphanumeric, underscores, hyphens)
	validName := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !validName.MatchString(name) {
		return fmt.Errorf("rule name '%s' contains invalid characters (only alphanumeric, underscores, and hyphens allowed)", name)
	}

	// Rule name should not be too long
	if len(name) > 64 {
		return fmt.Errorf("rule name '%s' is too long (max 64 characters)", name)
	}

	return nil
}

// checkDuplicateRuleIDs checks for duplicate rule IDs across WazuhRules in the same cluster
func (v *RuleValidator) checkDuplicateRuleIDs(ctx context.Context, rule *wazuhv1.WazuhRule) []string {
	var errors []string

	// List all WazuhRules in the same namespace referencing the same cluster
	ruleList := &wazuhv1.WazuhRuleList{}
	if err := v.client.List(ctx, ruleList, client.InNamespace(rule.Namespace)); err != nil {
		// If we can't list, skip duplicate check but don't fail
		return errors
	}

	// Extract rule IDs from current rule
	currentIDs := v.extractRuleIDs(rule.Spec.Rules)

	for _, existingRule := range ruleList.Items {
		// Skip self
		if existingRule.Name == rule.Name {
			continue
		}

		// Skip rules whose target clusters don't overlap.
		if !overlapsClusterRefs(existingRule.Spec.ClusterRefs, rule.Spec.ClusterRefs) {
			continue
		}

		// Check for duplicate IDs
		existingIDs := v.extractRuleIDs(existingRule.Spec.Rules)
		for _, currentID := range currentIDs {
			for _, existingID := range existingIDs {
				if currentID == existingID {
					errors = append(errors, fmt.Sprintf("rule ID %d already exists in WazuhRule '%s'", currentID, existingRule.Name))
				}
			}
		}
	}

	return errors
}

// extractRuleIDs extracts all rule IDs from XML content
func (v *RuleValidator) extractRuleIDs(content string) []int {
	var ids []int
	ruleIDRegex := regexp.MustCompile(`<rule[^>]+id\s*=\s*["'](\d+)["']`)
	matches := ruleIDRegex.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			if id, err := strconv.Atoi(match[1]); err == nil {
				ids = append(ids, id)
			}
		}
	}

	return ids
}

// ValidateXML is a standalone function for XML validation
func ValidateXML(content string) error {
	v := &RuleValidator{}
	return v.validateXMLSyntax(content)
}

// ExtractRuleIDs is a standalone function to extract rule IDs from XML
func ExtractRuleIDs(content string) []int {
	v := &RuleValidator{}
	return v.extractRuleIDs(content)
}

// FormatValidationErrors formats validation errors into a single string
func FormatValidationErrors(errors []string) string {
	if len(errors) == 0 {
		return ""
	}
	return strings.Join(errors, "; ")
}
