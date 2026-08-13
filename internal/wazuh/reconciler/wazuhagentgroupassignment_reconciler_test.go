/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package reconciler

import (
	"context"
	"reflect"
	"sort"
	"testing"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
)

func mustCompile(t *testing.T, sel wazuhv1.AgentSelector) compiledSelector {
	t.Helper()
	cs, err := compileSelector(sel)
	if err != nil {
		t.Fatalf("compileSelector: %v", err)
	}
	return cs
}

func waga(groups []string, sel wazuhv1.AgentSelector) wazuhv1.WazuhAgentGroupAssignment {
	return wazuhv1.WazuhAgentGroupAssignment{
		Spec: wazuhv1.WazuhAgentGroupAssignmentSpec{Groups: groups, Selector: sel},
	}
}

func TestMatchAgent(t *testing.T) {
	sel := mustCompile(t, wazuhv1.AgentSelector{
		AgentNames:   []string{"exact-1"},
		NamePatterns: []string{"web-*"},
		NameRegex:    []string{`^db-\d+$`},
		OSPlatforms:  []string{"ubuntu", "windows", "macos"}, // macos alias -> darwin
	})

	tests := []struct {
		name       string
		agent      string
		osPlatform string
		want       bool
	}{
		{"exact match", "exact-1", "", true},
		{"exact no match", "exact-2", "", false},
		{"glob match", "web-server", "", true},
		{"glob no match", "api-server", "", false},
		{"regex match", "db-42", "", true},
		{"regex no match", "db-x", "", false},
		{"platform match", "host-1", "ubuntu", true},
		{"platform case-insensitive", "host-2", "Windows", true},
		{"platform macos alias to darwin", "host-3", "darwin", true},
		{"platform no match", "host-4", "centos", false},
		{"empty platform not matched by platform", "host-5", "", false},
		{"empty platform still matched by name", "exact-1", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchAgent(tt.agent, tt.osPlatform, sel); got != tt.want {
				t.Errorf("matchAgent(%q, %q) = %v, want %v", tt.agent, tt.osPlatform, got, tt.want)
			}
		})
	}
}

func TestMatchAgent_PlatformAliasesInSpec(t *testing.T) {
	// A "darwin" agent must be matched whether the spec says darwin, macos, or osx.
	for _, spec := range []string{"darwin", "macos", "osx", "MacOS", " OSX "} {
		sel := mustCompile(t, wazuhv1.AgentSelector{OSPlatforms: []string{spec}})
		if !matchAgent("mac-1", "darwin", sel) {
			t.Errorf("osPlatforms:[%q] should match a darwin agent", spec)
		}
	}
}

func TestCompileSelectorErrors(t *testing.T) {
	if _, err := compileSelector(wazuhv1.AgentSelector{NameRegex: []string{"("}}); err == nil {
		t.Error("expected error for invalid regex")
	}
	if _, err := compileSelector(wazuhv1.AgentSelector{NamePatterns: []string{"[a-"}}); err == nil {
		t.Error("expected error for invalid glob")
	}
}

func TestComputeAddRemove(t *testing.T) {
	tests := []struct {
		name       string
		current    []string
		desired    []string
		wantAdd    []string
		wantRemove []string
	}{
		{"add and remove", []string{"a", "default"}, []string{"a", "b"}, []string{"b"}, []string{"default"}},
		{"nothing to do", []string{"a", "b"}, []string{"b", "a"}, nil, nil},
		{"all add", []string{}, []string{"x", "y"}, []string{"x", "y"}, nil},
		{"all remove", []string{"x", "y"}, []string{}, nil, []string{"x", "y"}},
		{"dedup desired", []string{"a"}, []string{"b", "b"}, []string{"b"}, []string{"a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAdd, gotRemove := computeAddRemove(tt.current, tt.desired)
			if !reflect.DeepEqual(gotAdd, tt.wantAdd) {
				t.Errorf("toAdd = %v, want %v", gotAdd, tt.wantAdd)
			}
			if !reflect.DeepEqual(gotRemove, tt.wantRemove) {
				t.Errorf("toRemove = %v, want %v", gotRemove, tt.wantRemove)
			}
		})
	}
}

func TestComputeDesiredAgentGroups_UnionAndUntouched(t *testing.T) {
	agents := []adapters.WazuhAgent{
		{ID: "000", Name: "web-manager", Groups: []string{"default"}}, // manager, must be excluded
		{ID: "001", Name: "web-1", Groups: []string{"default"}},       // matched by both CRs -> union
		{ID: "002", Name: "db-1", Groups: []string{"default"}},        // matched by CR2 only
		{ID: "003", Name: "misc-1", Groups: []string{"default"}},      // matched by nobody
	}
	crs := []wazuhv1.WazuhAgentGroupAssignment{
		waga([]string{"web", "monitored"}, wazuhv1.AgentSelector{NamePatterns: []string{"web-*"}}),
		waga([]string{"monitored", "db"}, wazuhv1.AgentSelector{NamePatterns: []string{"web-*", "db-*"}}),
	}

	got := computeDesiredAgentGroups(agents, crs)

	// 000 excluded, 003 untouched (absent).
	if _, ok := got["000"]; ok {
		t.Errorf("manager 000 must be excluded, got %v", got["000"])
	}
	if _, ok := got["003"]; ok {
		t.Errorf("unmatched agent 003 must be absent, got %v", got["003"])
	}
	// 001 = union of {web,monitored} and {monitored,db}.
	if !reflect.DeepEqual(got["001"], []string{"db", "monitored", "web"}) {
		t.Errorf("agent 001 union = %v, want [db monitored web]", got["001"])
	}
	// 002 matched only by CR2.
	if !reflect.DeepEqual(got["002"], []string{"db", "monitored"}) {
		t.Errorf("agent 002 = %v, want [db monitored]", got["002"])
	}
}

func TestComputeDesiredAgentGroups_PlatformUnion(t *testing.T) {
	agents := []adapters.WazuhAgent{
		{ID: "001", Name: "web-1", Groups: []string{"default"}, OSPlatform: "ubuntu"}, // name (CR1) + platform (CR2)
		{ID: "002", Name: "db-1", Groups: []string{"default"}, OSPlatform: "Windows"}, // platform only (CR3, case-insensitive)
		{ID: "003", Name: "misc-1", Groups: []string{"default"}, OSPlatform: ""},       // no name/platform match -> untouched
	}
	crs := []wazuhv1.WazuhAgentGroupAssignment{
		waga([]string{"web"}, wazuhv1.AgentSelector{NamePatterns: []string{"web-*"}}),
		waga([]string{"linux"}, wazuhv1.AgentSelector{OSPlatforms: []string{"ubuntu", "debian"}}),
		waga([]string{"win"}, wazuhv1.AgentSelector{OSPlatforms: []string{"windows"}}),
	}

	got := computeDesiredAgentGroups(agents, crs)

	// 001 matched by name (CR1 -> web) unioned with platform (CR2 -> linux).
	if !reflect.DeepEqual(got["001"], []string{"linux", "web"}) {
		t.Errorf("agent 001 union = %v, want [linux web]", got["001"])
	}
	// 002 matched by platform only (case-insensitive Windows -> windows).
	if !reflect.DeepEqual(got["002"], []string{"win"}) {
		t.Errorf("agent 002 = %v, want [win]", got["002"])
	}
	// 003 empty platform, no name match -> absent.
	if _, ok := got["003"]; ok {
		t.Errorf("agent 003 must be absent, got %v", got["003"])
	}
}

// fakeAgentGroupAPI records the ordered operations performed.
type fakeAgentGroupAPI struct {
	assigns []string // "agentID:group"
	removes []string // "agentID:group"
	ops     []string // ordered: "assign:agentID:group" / "remove:agentID:group"
}

func (f *fakeAgentGroupAPI) AssignAgentToGroup(_ context.Context, agentID, group string) error {
	f.assigns = append(f.assigns, agentID+":"+group)
	f.ops = append(f.ops, "assign:"+agentID+":"+group)
	return nil
}

func (f *fakeAgentGroupAPI) RemoveAgentFromGroup(_ context.Context, agentID, group string) error {
	f.removes = append(f.removes, agentID+":"+group)
	f.ops = append(f.ops, "remove:"+agentID+":"+group)
	return nil
}

func TestApplyDesiredAgentGroups_SkipsManagerAndUnmatched(t *testing.T) {
	agents := []adapters.WazuhAgent{
		{ID: "000", Name: "web-manager", Groups: []string{"default"}}, // manager: never touched
		{ID: "001", Name: "web-1", Groups: []string{"default"}},       // managed
		{ID: "002", Name: "db-1", Groups: []string{"default"}},        // NOT in desired: untouched
	}
	desired := map[string][]string{
		"000": {"web"}, // even if present, 000 must be skipped
		"001": {"web", "monitored"},
	}

	api := &fakeAgentGroupAPI{}
	if err := applyDesiredAgentGroups(context.Background(), api, agents, desired); err != nil {
		t.Fatalf("applyDesiredAgentGroups: %v", err)
	}

	for _, op := range append(append([]string{}, api.assigns...), api.removes...) {
		if op[:3] == "000" {
			t.Errorf("manager agent 000 was modified: %v", api.ops)
		}
		if op[:3] == "002" {
			t.Errorf("unmatched agent 002 was modified: %v", api.ops)
		}
	}

	wantAssigns := []string{"001:monitored", "001:web"}
	gotAssigns := append([]string{}, api.assigns...)
	sort.Strings(gotAssigns)
	if !reflect.DeepEqual(gotAssigns, wantAssigns) {
		t.Errorf("assigns = %v, want %v", gotAssigns, wantAssigns)
	}
	if !reflect.DeepEqual(api.removes, []string{"001:default"}) {
		t.Errorf("removes = %v, want [001:default]", api.removes)
	}
}

func TestApplyDesiredAgentGroups_AddsBeforeRemoves(t *testing.T) {
	agents := []adapters.WazuhAgent{
		{ID: "010", Name: "agent-1", Groups: []string{"old"}},
	}
	desired := map[string][]string{"010": {"target"}}

	api := &fakeAgentGroupAPI{}
	if err := applyDesiredAgentGroups(context.Background(), api, agents, desired); err != nil {
		t.Fatalf("applyDesiredAgentGroups: %v", err)
	}

	// The single add must precede the single remove so the agent keeps >=1 group.
	if !reflect.DeepEqual(api.ops, []string{"assign:010:target", "remove:010:old"}) {
		t.Errorf("ops = %v, want [assign:010:target remove:010:old]", api.ops)
	}
}

// TestDeleteUnion_KeepsGroupsAnotherCRProvides verifies the delete-time diff:
// only groups this CR uniquely provides are removed; groups another matching CR
// still wants are kept.
func TestDeleteUnion_KeepsGroupsAnotherCRProvides(t *testing.T) {
	agents := []adapters.WazuhAgent{
		{ID: "000", Name: "web-manager", Groups: []string{"web"}},
		{ID: "001", Name: "web-1", Groups: []string{"web", "monitored"}},
	}
	// CR being deleted provided {web, monitored}. The remaining CR still wants
	// {monitored} for web-* agents.
	ownGroups := []string{"web", "monitored"}
	otherCRs := []wazuhv1.WazuhAgentGroupAssignment{
		waga([]string{"monitored"}, wazuhv1.AgentSelector{NamePatterns: []string{"web-*"}}),
	}

	sel := mustCompile(t, wazuhv1.AgentSelector{NamePatterns: []string{"web-*"}})
	matched := matchedAgentIDs(agents, sel)
	if !reflect.DeepEqual(matched, []string{"001"}) {
		t.Fatalf("matched = %v, want [001]", matched)
	}

	otherDesired := computeDesiredAgentGroups(agents, otherCRs)

	api := &fakeAgentGroupAPI{}
	for _, agentID := range matched {
		if agentID == managerAgentID {
			t.Fatal("manager agent must not be in matched set")
		}
		keep := toSet(otherDesired[agentID])
		for _, g := range ownGroups {
			if _, wanted := keep[g]; wanted {
				continue
			}
			_ = api.RemoveAgentFromGroup(context.Background(), agentID, g)
		}
	}

	// "monitored" is still wanted by the other CR -> kept. Only "web" removed.
	if !reflect.DeepEqual(api.removes, []string{"001:web"}) {
		t.Errorf("removes = %v, want [001:web]", api.removes)
	}
}
