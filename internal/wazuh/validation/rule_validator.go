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

	// Validate the rule structure and options against what wazuh-analysisd accepts
	if errs := validateRuleStructure(rule.Spec.Rules); len(errs) > 0 {
		result.Valid = false
		result.Errors = append(result.Errors, errs...)
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

// ruleOptions are the elements wazuh-analysisd accepts inside a <rule> (the xml_* option
// names in src/analysisd/rules.c, identical in Wazuh 4.9 and 4.14). analysisd compares them
// case-insensitively and rejects any other element, failing the whole ruleset at startup.
var ruleOptions = map[string]bool{
	"regex": true, "match": true, "decoded_as": true, "category": true, "cve": true,
	"info": true, "time": true, "weekday": true, "description": true, "ignore": true,
	"check_if_ignored": true, "srcip": true, "srcgeoip": true, "srcport": true,
	"dstip": true, "dstgeoip": true, "dstport": true, "user": true, "url": true, "id": true,
	"data": true, "extra_data": true, "hostname": true, "program_name": true, "status": true,
	"protocol": true, "system_name": true, "action": true, "compiled_rule": true,
	"field": true, "location": true, "list": true, "group": true, "options": true,
	"mitre":  true,
	"if_sid": true, "if_group": true, "if_level": true, "if_fts": true,
	"if_matched_regex": true, "if_matched_group": true, "if_matched_sid": true,
	"same_source_ip": true, "same_srcip": true, "same_src_port": true, "same_srcport": true,
	"same_dst_port": true, "same_dstport": true, "same_srcuser": true, "same_user": true,
	"same_location": true, "same_id": true, "check_diff": true, "same_field": true,
	"same_dstip": true, "same_agent": true, "same_url": true, "same_srcgeoip": true,
	"same_protocol": true, "same_action": true, "same_data": true, "same_extra_data": true,
	"same_status": true, "same_system_name": true, "same_dstgeoip": true,
	"different_url": true, "different_srcip": true, "different_srcgeoip": true,
	"different_dstip": true, "different_src_port": true, "different_srcport": true,
	"different_dst_port": true, "different_dstport": true, "different_location": true,
	"different_protocol": true, "different_action": true, "different_srcuser": true,
	"different_user": true, "different_id": true, "different_data": true,
	"different_extra_data": true, "different_status": true, "different_system_name": true,
	"different_dstgeoip": true, "different_field": true,
	"not_same_source_ip": true, "not_same_user": true, "not_same_agent": true,
	"not_same_id": true, "not_same_field": true, "global_frequency": true,
}

// mitreOptions are the elements analysisd accepts inside a rule's <mitre> block.
var mitreOptions = map[string]bool{"id": true, "tacticid": true, "techniqueid": true}

// validateRuleStructure mirrors the structural checks wazuh-analysisd applies when loading a
// rule file: root elements must be <group> (<var> definitions are expanded beforehand), a
// group may only contain <rule> elements and at least one of them, and a rule may only use
// known options. Any of these errors stops analysisd, so the manager crash-loops while the
// CR would otherwise report Applied. Malformed XML is left to validateXMLSyntax.
func validateRuleStructure(content string) []string {
	var errs []string
	dec := xml.NewDecoder(strings.NewReader(content))
	var stack []string // lowercased open elements
	ruleID := ""
	rulesInGroup := 0

	for {
		tok, err := dec.Token()
		if err != nil {
			// io.EOF ends the walk; syntax errors are reported by validateXMLSyntax.
			return errs
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name := strings.ToLower(t.Name.Local)
			switch {
			case len(stack) == 0:
				if name == "var" {
					if err := dec.Skip(); err != nil {
						return errs
					}
					continue
				}
				if name != "group" {
					errs = append(errs, fmt.Sprintf("invalid root element <%s>: only <group> is allowed", t.Name.Local))
				}
				rulesInGroup = 0
			case len(stack) == 1 && stack[0] == "group":
				if name != "rule" {
					errs = append(errs, fmt.Sprintf("invalid element <%s> in group: only <rule> is allowed", t.Name.Local))
					break
				}
				rulesInGroup++
				ruleID = ""
				for _, a := range t.Attr {
					if strings.EqualFold(a.Name.Local, "id") {
						ruleID = a.Value
					}
				}
			case len(stack) == 2 && stack[1] == "rule":
				if !ruleOptions[name] {
					errs = append(errs, fmt.Sprintf("rule %s: invalid option <%s>", ruleID, t.Name.Local))
				}
			case len(stack) == 3 && stack[1] == "rule" && stack[2] == "mitre":
				if !mitreOptions[name] {
					errs = append(errs, fmt.Sprintf("rule %s: invalid option <%s> in <mitre>", ruleID, t.Name.Local))
				}
			}
			stack = append(stack, name)
		case xml.EndElement:
			if len(stack) == 0 {
				return errs
			}
			if len(stack) == 1 && stack[0] == "group" && rulesInGroup == 0 {
				errs = append(errs, "group without any rule")
			}
			stack = stack[:len(stack)-1]
		}
	}
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
