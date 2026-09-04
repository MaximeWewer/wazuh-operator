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

// ActiveResponseBlockOptions holds the values for a single active response,
// rendered as a paired <command> + <active-response> block in ossec.conf.
type ActiveResponseBlockOptions struct {
	// Name is the command identifier, rendered as <command><name> and referenced
	// by <active-response><command>.
	Name string
	// Executable is the script filename in active-response/bin (<executable>).
	Executable string
	// TimeoutAllowed renders <timeout_allowed>yes|no</timeout_allowed>.
	TimeoutAllowed bool
	// ExtraArgs renders <extra_args> when non-empty.
	ExtraArgs string

	// Disabled renders <disabled>yes</disabled> when true.
	Disabled bool
	// Location renders <location> (defaults to "local").
	Location string
	// AgentID renders <agent_id> when non-empty (required for location defined-agent).
	AgentID string
	// Level renders <level> when non-nil.
	Level *int32
	// RulesID renders <rules_id> comma-separated when non-empty.
	RulesID []int32
	// RulesGroup renders <rules_group> when non-empty.
	RulesGroup string
	// Timeout renders <timeout> when non-nil.
	Timeout *int32
	// RepeatedOffenders renders <repeated_offenders> comma-separated (minutes) when non-empty.
	RepeatedOffenders []int32
}

// BuildActiveResponseBlock renders the ossec.conf <command> and <active-response>
// blocks for a single active response. Empty optional fields are omitted. The output
// is indented two spaces to match the surrounding ossec.conf template.
func BuildActiveResponseBlock(o ActiveResponseBlockOptions) string {
	var b strings.Builder

	// <command> block binds the script.
	b.WriteString("  <command>\n")
	fmt.Fprintf(&b, "    <name>%s</name>\n", xmlValueEscaper.Replace(o.Name))
	fmt.Fprintf(&b, "    <executable>%s</executable>\n", xmlValueEscaper.Replace(o.Executable))
	fmt.Fprintf(&b, "    <timeout_allowed>%s</timeout_allowed>\n", yesNo(o.TimeoutAllowed))
	if strings.TrimSpace(o.ExtraArgs) != "" {
		fmt.Fprintf(&b, "    <extra_args>%s</extra_args>\n", xmlValueEscaper.Replace(o.ExtraArgs))
	}
	b.WriteString("  </command>\n")

	// <active-response> block is the trigger.
	b.WriteString("  <active-response>\n")
	if o.Disabled {
		b.WriteString("    <disabled>yes</disabled>\n")
	}
	fmt.Fprintf(&b, "    <command>%s</command>\n", xmlValueEscaper.Replace(o.Name))

	location := o.Location
	if location == "" {
		location = "local"
	}
	fmt.Fprintf(&b, "    <location>%s</location>\n", xmlValueEscaper.Replace(location))

	if location == "defined-agent" && o.AgentID != "" {
		fmt.Fprintf(&b, "    <agent_id>%s</agent_id>\n", xmlValueEscaper.Replace(o.AgentID))
	}
	if o.Level != nil {
		fmt.Fprintf(&b, "    <level>%d</level>\n", *o.Level)
	}
	if len(o.RulesID) > 0 {
		fmt.Fprintf(&b, "    <rules_id>%s</rules_id>\n", joinInt32(o.RulesID))
	}
	if o.RulesGroup != "" {
		fmt.Fprintf(&b, "    <rules_group>%s</rules_group>\n", xmlValueEscaper.Replace(o.RulesGroup))
	}
	if o.Timeout != nil {
		fmt.Fprintf(&b, "    <timeout>%d</timeout>\n", *o.Timeout)
	}
	if len(o.RepeatedOffenders) > 0 {
		fmt.Fprintf(&b, "    <repeated_offenders>%s</repeated_offenders>\n", joinInt32(o.RepeatedOffenders))
	}
	b.WriteString("  </active-response>")
	return b.String()
}

// yesNo renders a Wazuh boolean tag value.
func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

// joinInt32 renders an int32 slice as a comma-separated string.
func joinInt32(vals []int32) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, strconv.FormatInt(int64(v), 10))
	}
	return strings.Join(parts, ",")
}
