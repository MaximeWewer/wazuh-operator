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
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

// DecoderValidator validates WazuhDecoder resources
type DecoderValidator struct {
	client client.Client
}

// NewDecoderValidator creates a new DecoderValidator
func NewDecoderValidator(c client.Client) *DecoderValidator {
	return &DecoderValidator{
		client: c,
	}
}

// DecoderValidationResult contains the validation results
type DecoderValidationResult struct {
	Valid  bool
	Errors []string
}

// DecoderElement represents a Wazuh decoder in XML
type DecoderElement struct {
	XMLName xml.Name `xml:"decoder"`
	Name    string   `xml:"name,attr"`
	Parent  string   `xml:"parent,omitempty"`
}

// ValidateDecoder performs comprehensive validation of a WazuhDecoder
func (v *DecoderValidator) Validate(ctx context.Context, decoder *wazuhv1.WazuhDecoder) *DecoderValidationResult {
	result := &DecoderValidationResult{
		Valid:  true,
		Errors: []string{},
	}

	// Validate XML syntax
	if err := v.validateXMLSyntax(decoder.Spec.Decoders); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("invalid XML syntax: %v", err))
	}

	// Validate decoder name
	if err := v.validateDecoderName(decoder.Spec.DecoderName); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, err.Error())
	}

	// Validate decoder names in XML match naming conventions
	if errs := v.validateDecoderNamesInXML(decoder.Spec.Decoders); len(errs) > 0 {
		result.Valid = false
		result.Errors = append(result.Errors, errs...)
	}

	// Check for duplicate decoder names in the same cluster
	if v.client != nil {
		if errs := v.checkDuplicateDecoderNames(ctx, decoder); len(errs) > 0 {
			result.Valid = false
			result.Errors = append(result.Errors, errs...)
		}
	}

	return result
}

// validateXMLSyntax validates that the decoder content is valid XML
func (v *DecoderValidator) validateXMLSyntax(content string) error {
	if content == "" {
		return fmt.Errorf("decoder content cannot be empty")
	}

	// Check if content looks like XML (starts with < after trimming whitespace)
	trimmed := strings.TrimSpace(content)
	if !strings.HasPrefix(trimmed, "<") {
		return fmt.Errorf("content does not appear to be XML (must start with '<')")
	}

	// Try to parse as XML - wrap in root if needed for multiple decoders
	wrapped := "<root>" + content + "</root>"
	var root struct {
		XMLName xml.Name `xml:"root"`
		Content []byte   `xml:",innerxml"`
	}
	if err := xml.Unmarshal([]byte(wrapped), &root); err != nil {
		return fmt.Errorf("failed to parse XML: %w", err)
	}

	// Verify content contains at least one decoder element
	if !strings.Contains(content, "<decoder") {
		return fmt.Errorf("content must contain at least one <decoder> element")
	}

	return nil
}

// validateDecoderName validates the decoder name format
func (v *DecoderValidator) validateDecoderName(name string) error {
	if name == "" {
		return fmt.Errorf("decoder name cannot be empty")
	}

	// Decoder name should be a valid filename (alphanumeric, underscores, hyphens)
	validName := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !validName.MatchString(name) {
		return fmt.Errorf("decoder name '%s' contains invalid characters (only alphanumeric, underscores, and hyphens allowed)", name)
	}

	// Decoder name should not be too long
	if len(name) > 64 {
		return fmt.Errorf("decoder name '%s' is too long (max 64 characters)", name)
	}

	return nil
}

// validateDecoderNamesInXML validates decoder names defined in XML
func (v *DecoderValidator) validateDecoderNamesInXML(content string) []string {
	var errors []string

	// Extract decoder names from XML content
	decoderNameRegex := regexp.MustCompile(`<decoder[^>]+name\s*=\s*["']([^"']+)["']`)
	matches := decoderNameRegex.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			name := match[1]
			// Validate decoder name format
			validName := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
			if !validName.MatchString(name) {
				errors = append(errors, fmt.Sprintf("decoder name '%s' in XML contains invalid characters", name))
			}
		}
	}

	return errors
}

// checkDuplicateDecoderNames checks for duplicate decoder names across WazuhDecoders in the same cluster
func (v *DecoderValidator) checkDuplicateDecoderNames(ctx context.Context, decoder *wazuhv1.WazuhDecoder) []string {
	var errors []string

	// List all WazuhDecoders in the same namespace referencing the same cluster
	decoderList := &wazuhv1.WazuhDecoderList{}
	if err := v.client.List(ctx, decoderList, client.InNamespace(decoder.Namespace)); err != nil {
		// If we can't list, skip duplicate check but don't fail
		return errors
	}

	// Extract decoder names from current decoder
	currentNames := v.extractDecoderNames(decoder.Spec.Decoders)

	for _, existingDecoder := range decoderList.Items {
		// Skip self
		if existingDecoder.Name == decoder.Name {
			continue
		}

		// Skip decoders for different clusters
		if existingDecoder.Spec.ClusterRef.Name != decoder.Spec.ClusterRef.Name {
			continue
		}

		// Check for duplicate names
		existingNames := v.extractDecoderNames(existingDecoder.Spec.Decoders)
		for _, currentName := range currentNames {
			for _, existingName := range existingNames {
				if currentName == existingName {
					errors = append(errors, fmt.Sprintf("decoder name '%s' already exists in WazuhDecoder '%s'", currentName, existingDecoder.Name))
				}
			}
		}
	}

	return errors
}

// extractDecoderNames extracts all decoder names from XML content
func (v *DecoderValidator) extractDecoderNames(content string) []string {
	var names []string
	decoderNameRegex := regexp.MustCompile(`<decoder[^>]+name\s*=\s*["']([^"']+)["']`)
	matches := decoderNameRegex.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			names = append(names, match[1])
		}
	}

	return names
}

// ValidateDecoderXML is a standalone function for XML validation
func ValidateDecoderXML(content string) error {
	v := &DecoderValidator{}
	return v.validateXMLSyntax(content)
}

// ExtractDecoderNames is a standalone function to extract decoder names from XML
func ExtractDecoderNames(content string) []string {
	v := &DecoderValidator{}
	return v.extractDecoderNames(content)
}
