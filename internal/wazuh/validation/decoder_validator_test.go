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
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

func TestValidateDecoderXML(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{
			name: "valid single decoder",
			content: `<decoder name="test-decoder">
  <prematch>^Test</prematch>
</decoder>`,
			wantErr: false,
		},
		{
			name: "valid multiple decoders",
			content: `<decoder name="parent-decoder">
  <program_name>test-app</program_name>
</decoder>
<decoder name="child-decoder">
  <parent>parent-decoder</parent>
  <regex>^(\d+) (\w+)</regex>
  <order>id,name</order>
</decoder>`,
			wantErr: false,
		},
		{
			name:    "empty content",
			content: "",
			wantErr: true,
		},
		{
			name:    "invalid XML - unclosed tag",
			content: `<decoder name="test"><prematch>^Test</decoder>`,
			wantErr: true,
		},
		{
			name:    "invalid XML - malformed",
			content: "this is not xml at all",
			wantErr: true,
		},
		{
			name:    "no decoder element",
			content: `<rule id="100001" level="5"><description>Test</description></rule>`,
			wantErr: true,
		},
		{
			name: "valid decoder with plugin",
			content: `<decoder name="json-decoder">
  <prematch>^{</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDecoderXML(tt.content)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDecoderXML() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExtractDecoderNames(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected []string
	}{
		{
			name: "single decoder",
			content: `<decoder name="my-decoder">
  <prematch>^Test</prematch>
</decoder>`,
			expected: []string{"my-decoder"},
		},
		{
			name: "multiple decoders",
			content: `<decoder name="parent">
  <program_name>test</program_name>
</decoder>
<decoder name="child">
  <parent>parent</parent>
</decoder>`,
			expected: []string{"parent", "child"},
		},
		{
			name:     "no decoders",
			content:  "<root>no decoders here</root>",
			expected: []string{},
		},
		{
			name: "single quotes",
			content: `<decoder name='single-quote-decoder'>
  <prematch>^Test</prematch>
</decoder>`,
			expected: []string{"single-quote-decoder"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractDecoderNames(tt.content)
			if len(result) != len(tt.expected) {
				t.Errorf("ExtractDecoderNames() got %d names, want %d", len(result), len(tt.expected))
				return
			}
			for i, name := range result {
				if name != tt.expected[i] {
					t.Errorf("ExtractDecoderNames()[%d] = %s, want %s", i, name, tt.expected[i])
				}
			}
		})
	}
}

func TestDecoderValidator_validateDecoderName(t *testing.T) {
	v := &DecoderValidator{}

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid simple name",
			input:   "my_decoder",
			wantErr: false,
		},
		{
			name:    "valid name with hyphen",
			input:   "my-decoder",
			wantErr: false,
		},
		{
			name:    "valid alphanumeric",
			input:   "decoder123",
			wantErr: false,
		},
		{
			name:    "empty name",
			input:   "",
			wantErr: true,
		},
		{
			name:    "name with spaces",
			input:   "my decoder",
			wantErr: true,
		},
		{
			name:    "name with special chars",
			input:   "decoder@123",
			wantErr: true,
		},
		{
			name:    "name too long",
			input:   "this_is_a_very_long_decoder_name_that_exceeds_the_maximum_allowed_length_of_64_characters",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.validateDecoderName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDecoderName(%s) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestDecoderValidator_Validate(t *testing.T) {
	v := NewDecoderValidator(nil) // nil client - skip duplicate check

	tests := []struct {
		name    string
		decoder *wazuhv1.WazuhDecoder
		valid   bool
	}{
		{
			name: "valid decoder",
			decoder: &wazuhv1.WazuhDecoder{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-decoder",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhDecoderSpec{
					ClusterRef: wazuhv1.WazuhClusterReference{
						Name:      "test-cluster",
						Namespace: "default",
					},
					DecoderName: "custom_decoder",
					Decoders: `<decoder name="custom-app">
  <program_name>custom-app</program_name>
</decoder>`,
				},
			},
			valid: true,
		},
		{
			name: "invalid XML",
			decoder: &wazuhv1.WazuhDecoder{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "invalid-decoder",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhDecoderSpec{
					ClusterRef: wazuhv1.WazuhClusterReference{
						Name: "test-cluster",
					},
					DecoderName: "invalid",
					Decoders:    "not xml content",
				},
			},
			valid: false,
		},
		{
			name: "invalid decoder name",
			decoder: &wazuhv1.WazuhDecoder{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "bad-name-decoder",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhDecoderSpec{
					ClusterRef: wazuhv1.WazuhClusterReference{
						Name: "test-cluster",
					},
					DecoderName: "invalid name!",
					Decoders: `<decoder name="test">
  <prematch>^Test</prematch>
</decoder>`,
				},
			},
			valid: false,
		},
		{
			name: "invalid decoder name in XML",
			decoder: &wazuhv1.WazuhDecoder{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "xml-name-decoder",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhDecoderSpec{
					ClusterRef: wazuhv1.WazuhClusterReference{
						Name: "test-cluster",
					},
					DecoderName: "valid_name",
					Decoders: `<decoder name="invalid@name">
  <prematch>^Test</prematch>
</decoder>`,
				},
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.Validate(context.Background(), tt.decoder)
			if result.Valid != tt.valid {
				t.Errorf("Validate() valid = %v, want %v, errors: %v", result.Valid, tt.valid, result.Errors)
			}
		})
	}
}
