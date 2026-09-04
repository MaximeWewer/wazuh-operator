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
	"strings"
	"testing"
)

func i32(v int32) *int32 { return new(v) }

func TestBuildActiveResponseBlock_Full(t *testing.T) {
	got := BuildActiveResponseBlock(ActiveResponseBlockOptions{
		Name:              "firewall-drop",
		Executable:        "firewall-drop.sh",
		TimeoutAllowed:    true,
		Location:          "local",
		RulesID:           []int32{100100, 100101},
		Timeout:           i32(600),
		RepeatedOffenders: []int32{30, 60, 120},
	})

	want := strings.Join([]string{
		"  <command>",
		"    <name>firewall-drop</name>",
		"    <executable>firewall-drop.sh</executable>",
		"    <timeout_allowed>yes</timeout_allowed>",
		"  </command>",
		"  <active-response>",
		"    <command>firewall-drop</command>",
		"    <location>local</location>",
		"    <rules_id>100100,100101</rules_id>",
		"    <timeout>600</timeout>",
		"    <repeated_offenders>30,60,120</repeated_offenders>",
		"  </active-response>",
	}, "\n")

	if got != want {
		t.Errorf("block mismatch:\n got=%q\nwant=%q", got, want)
	}
}

func TestBuildActiveResponseBlock_DefinedAgentAndDefaults(t *testing.T) {
	got := BuildActiveResponseBlock(ActiveResponseBlockOptions{
		Name:       "restart-svc",
		Executable: "restart-svc.py",
		Disabled:   true,
		Location:   "defined-agent",
		AgentID:    "004",
		Level:      i32(10),
		RulesGroup: "sshd",
	})

	// timeout_allowed defaults to no; disabled rendered; agent_id present; empty location defaults elsewhere.
	for _, want := range []string{
		"<timeout_allowed>no</timeout_allowed>",
		"<disabled>yes</disabled>",
		"<location>defined-agent</location>",
		"<agent_id>004</agent_id>",
		"<level>10</level>",
		"<rules_group>sshd</rules_group>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected block to contain %q, got:\n%s", want, got)
		}
	}
}

func TestBuildActiveResponseBlock_LocationDefault(t *testing.T) {
	got := BuildActiveResponseBlock(ActiveResponseBlockOptions{
		Name:       "x",
		Executable: "x.sh",
		Level:      i32(5),
	})
	if !strings.Contains(got, "<location>local</location>") {
		t.Errorf("expected default location local, got:\n%s", got)
	}
	// agent_id must not appear when location is not defined-agent.
	if strings.Contains(got, "<agent_id>") {
		t.Errorf("agent_id should be omitted, got:\n%s", got)
	}
}
