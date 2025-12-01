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

// Package config provides configuration builders for Wazuh components
package config

import (
	"bytes"
	"text/template"
)

// WazuhConfigBuilder defines the interface for building Wazuh configuration
type WazuhConfigBuilder interface {
	// Build generates the configuration content
	Build() (string, error)
}

// BaseConfig holds common configuration values
type BaseConfig struct {
	ClusterName string
	Namespace   string
	Version     string
}

// TemplateBuilder is a helper for building configurations from templates
type TemplateBuilder struct {
	tmpl *template.Template
	data interface{}
}

// NewTemplateBuilder creates a new TemplateBuilder
func NewTemplateBuilder(name, tmpl string) (*TemplateBuilder, error) {
	t, err := template.New(name).Parse(tmpl)
	if err != nil {
		return nil, err
	}
	return &TemplateBuilder{tmpl: t}, nil
}

// WithData sets the data for the template
func (b *TemplateBuilder) WithData(data interface{}) *TemplateBuilder {
	b.data = data
	return b
}

// Build executes the template and returns the result
func (b *TemplateBuilder) Build() (string, error) {
	var buf bytes.Buffer
	if err := b.tmpl.Execute(&buf, b.data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ConfigMerger merges multiple configuration sections
type ConfigMerger struct {
	sections []string
}

// NewConfigMerger creates a new ConfigMerger
func NewConfigMerger() *ConfigMerger {
	return &ConfigMerger{
		sections: []string{},
	}
}

// AddSection adds a configuration section
func (m *ConfigMerger) AddSection(section string) *ConfigMerger {
	m.sections = append(m.sections, section)
	return m
}

// Merge combines all sections into a single configuration
func (m *ConfigMerger) Merge() string {
	var buf bytes.Buffer
	for i, section := range m.sections {
		buf.WriteString(section)
		if i < len(m.sections)-1 {
			buf.WriteString("\n")
		}
	}
	return buf.String()
}
