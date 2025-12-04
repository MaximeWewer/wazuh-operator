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

package security_config

import "github.com/MaximeWewer/wazuh-operator/pkg/constants"

// ISMPolicyBuilder builds OpenSearch ISM policies
type ISMPolicyBuilder struct {
	policyID     string
	description  string
	defaultState string
	states       []ISMState
	ismTemplate  []ISMTemplate
}

// ISMState represents a policy state
type ISMState struct {
	Name        string
	Actions     []ISMAction
	Transitions []ISMTransition
}

// ISMAction represents a policy action
type ISMAction struct {
	Type   string
	Config map[string]interface{}
}

// ISMTransition represents a state transition
type ISMTransition struct {
	StateName  string
	Conditions map[string]interface{}
}

// ISMTemplate represents an ISM template
type ISMTemplate struct {
	IndexPatterns []string
	Priority      int
}

// NewISMPolicyBuilder creates a new ISMPolicyBuilder
func NewISMPolicyBuilder(policyID string) *ISMPolicyBuilder {
	return &ISMPolicyBuilder{
		policyID:    policyID,
		states:      []ISMState{},
		ismTemplate: []ISMTemplate{},
	}
}

// WithDescription sets the description
func (b *ISMPolicyBuilder) WithDescription(description string) *ISMPolicyBuilder {
	b.description = description
	return b
}

// WithDefaultState sets the default state
func (b *ISMPolicyBuilder) WithDefaultState(state string) *ISMPolicyBuilder {
	b.defaultState = state
	return b
}

// AddState adds a state
func (b *ISMPolicyBuilder) AddState(state ISMState) *ISMPolicyBuilder {
	b.states = append(b.states, state)
	return b
}

// AddTemplate adds an ISM template
func (b *ISMPolicyBuilder) AddTemplate(template ISMTemplate) *ISMPolicyBuilder {
	b.ismTemplate = append(b.ismTemplate, template)
	return b
}

// Build builds the ISM policy configuration
func (b *ISMPolicyBuilder) Build() map[string]interface{} {
	policy := map[string]interface{}{
		"policy_id":     b.policyID,
		"description":   b.description,
		"default_state": b.defaultState,
	}

	if len(b.states) > 0 {
		states := make([]map[string]interface{}, len(b.states))
		for i, state := range b.states {
			stateMap := map[string]interface{}{
				"name": state.Name,
			}

			if len(state.Actions) > 0 {
				actions := make([]map[string]interface{}, len(state.Actions))
				for j, action := range state.Actions {
					actions[j] = map[string]interface{}{
						action.Type: action.Config,
					}
				}
				stateMap["actions"] = actions
			}

			if len(state.Transitions) > 0 {
				transitions := make([]map[string]interface{}, len(state.Transitions))
				for j, transition := range state.Transitions {
					transitions[j] = map[string]interface{}{
						"state_name": transition.StateName,
						"conditions": transition.Conditions,
					}
				}
				stateMap["transitions"] = transitions
			}

			states[i] = stateMap
		}
		policy["states"] = states
	}

	if len(b.ismTemplate) > 0 {
		templates := make([]map[string]interface{}, len(b.ismTemplate))
		for i, template := range b.ismTemplate {
			templates[i] = map[string]interface{}{
				"index_patterns": template.IndexPatterns,
				"priority":       template.Priority,
			}
		}
		policy["ism_template"] = templates
	}

	return policy
}

// DefaultWazuhISMPolicy returns the default Wazuh ISM policy for index lifecycle
func DefaultWazuhISMPolicy() map[string]interface{} {
	return NewISMPolicyBuilder(constants.ISMPolicyName).
		WithDescription(constants.ISMPolicyDescription).
		WithDefaultState(constants.ISMDefaultState).
		AddState(ISMState{
			Name: constants.ISMStateHot,
			Actions: []ISMAction{
				{Type: "rollover", Config: map[string]interface{}{
					"min_index_age": constants.ISMHotStateMinIndexAge,
					"min_doc_count": constants.ISMHotStateMinDocCount,
				}},
			},
			Transitions: []ISMTransition{
				{StateName: constants.ISMStateWarm, Conditions: map[string]interface{}{
					"min_index_age": constants.ISMWarmStateMinIndexAge,
				}},
			},
		}).
		AddState(ISMState{
			Name: constants.ISMStateWarm,
			Actions: []ISMAction{
				{Type: "replica_count", Config: map[string]interface{}{
					"number_of_replicas": constants.ISMWarmStateReplicas,
				}},
			},
			Transitions: []ISMTransition{
				{StateName: constants.ISMStateDelete, Conditions: map[string]interface{}{
					"min_index_age": constants.ISMDeleteStateMinIndexAge,
				}},
			},
		}).
		AddState(ISMState{
			Name: constants.ISMStateDelete,
			Actions: []ISMAction{
				{Type: "delete", Config: map[string]interface{}{}},
			},
		}).
		AddTemplate(ISMTemplate{
			IndexPatterns: []string{constants.ISMTemplateIndexPattern},
			Priority:      constants.ISMTemplatePriority,
		}).
		Build()
}
