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

package config

import (
	"fmt"
	"strconv"
	"strings"
)

// IntegrationBlockOptions holds the already-resolved values for a single
// <integration> block in ossec.conf. Secret-backed fields (HookURL, APIKey)
// must be resolved by the caller before building the block.
type IntegrationBlockOptions struct {
	// Name is the integration identifier (e.g. "custom-jira"). Rendered as <name>.
	Name string
	// HookURL is rendered as <hook_url> when non-empty.
	HookURL string
	// APIKey is rendered as <api_key> when non-empty.
	APIKey string
	// Level filters alerts by minimum severity (<level>).
	Level *int32
	// RuleID filters alerts by rule IDs (<rule_id>), rendered comma-separated.
	RuleID []int32
	// Group filters alerts by rule group (<group>).
	Group string
	// EventLocation filters alerts by source location (<location>).
	EventLocation string
	// AlertFormat controls the alert payload format (<alert_format>).
	AlertFormat string
	// Options is raw JSON forwarded inside <options>.
	Options string
}

// xmlValueEscaper escapes the characters that are unsafe inside an XML text node.
var xmlValueEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
)

// BuildIntegrationBlock renders a single ossec.conf <integration> block.
// Empty optional fields are omitted. The output is indented two spaces to match
// the surrounding ossec.conf template.
func BuildIntegrationBlock(o IntegrationBlockOptions) string {
	var b strings.Builder
	b.WriteString("  <integration>\n")
	fmt.Fprintf(&b, "    <name>%s</name>\n", xmlValueEscaper.Replace(o.Name))

	if o.HookURL != "" {
		fmt.Fprintf(&b, "    <hook_url>%s</hook_url>\n", xmlValueEscaper.Replace(o.HookURL))
	}
	if o.APIKey != "" {
		fmt.Fprintf(&b, "    <api_key>%s</api_key>\n", xmlValueEscaper.Replace(o.APIKey))
	}
	if o.Level != nil {
		fmt.Fprintf(&b, "    <level>%d</level>\n", *o.Level)
	}
	if len(o.RuleID) > 0 {
		ids := make([]string, 0, len(o.RuleID))
		for _, id := range o.RuleID {
			ids = append(ids, strconv.FormatInt(int64(id), 10))
		}
		fmt.Fprintf(&b, "    <rule_id>%s</rule_id>\n", strings.Join(ids, ","))
	}
	if o.Group != "" {
		fmt.Fprintf(&b, "    <group>%s</group>\n", xmlValueEscaper.Replace(o.Group))
	}
	if o.EventLocation != "" {
		fmt.Fprintf(&b, "    <location>%s</location>\n", xmlValueEscaper.Replace(o.EventLocation))
	}

	alertFormat := o.AlertFormat
	if alertFormat == "" {
		alertFormat = "json"
	}
	fmt.Fprintf(&b, "    <alert_format>%s</alert_format>\n", xmlValueEscaper.Replace(alertFormat))

	if strings.TrimSpace(o.Options) != "" {
		fmt.Fprintf(&b, "    <options>%s</options>\n", strings.TrimSpace(o.Options))
	}

	b.WriteString("  </integration>")
	return b.String()
}
