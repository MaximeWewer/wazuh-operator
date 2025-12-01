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

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// ISMAPI provides ISM (Index State Management) operations
type ISMAPI struct {
	client *Client
}

// NewISMAPI creates a new ISM API client
func NewISMAPI(client *Client) *ISMAPI {
	return &ISMAPI{client: client}
}

// ISMPolicy represents an ISM policy
type ISMPolicy struct {
	Policy ISMPolicySpec `json:"policy"`
}

// ISMPolicySpec represents the ISM policy specification
type ISMPolicySpec struct {
	Description  string               `json:"description,omitempty"`
	DefaultState string               `json:"default_state,omitempty"`
	States       []ISMState           `json:"states,omitempty"`
	ISMTemplate  []ISMTemplatePattern `json:"ism_template,omitempty"`
}

// ISMState represents a state in an ISM policy
type ISMState struct {
	Name        string          `json:"name"`
	Actions     []ISMAction     `json:"actions,omitempty"`
	Transitions []ISMTransition `json:"transitions,omitempty"`
}

// ISMAction represents an action in an ISM state
type ISMAction struct {
	// RawConfig allows passing raw JSON action configuration
	RawConfig     json.RawMessage      `json:"-"`
	Rollover      *RolloverAction      `json:"rollover,omitempty"`
	Delete        *DeleteAction        `json:"delete,omitempty"`
	ReadOnly      *ReadOnlyAction      `json:"read_only,omitempty"`
	ReadWrite     *ReadWriteAction     `json:"read_write,omitempty"`
	ReplicaCount  *ReplicaCountAction  `json:"replica_count,omitempty"`
	ForceMerge    *ForceMergeAction    `json:"force_merge,omitempty"`
	Shrink        *ShrinkAction        `json:"shrink,omitempty"`
	Allocation    *AllocationAction    `json:"allocation,omitempty"`
	Snapshot      *SnapshotAction      `json:"snapshot,omitempty"`
	IndexPriority *IndexPriorityAction `json:"index_priority,omitempty"`
	Close         *CloseAction         `json:"close,omitempty"`
	Open          *OpenAction          `json:"open,omitempty"`
}

// MarshalJSON implements custom JSON marshaling for ISMAction
func (a ISMAction) MarshalJSON() ([]byte, error) {
	// If raw config is provided, use it directly
	if len(a.RawConfig) > 0 {
		return a.RawConfig, nil
	}
	// Otherwise, marshal the structured fields
	type ActionAlias ISMAction
	return json.Marshal(ActionAlias(a))
}

// RolloverAction represents a rollover action
type RolloverAction struct {
	MinSize             string `json:"min_size,omitempty"`
	MinDocCount         int64  `json:"min_doc_count,omitempty"`
	MinIndexAge         string `json:"min_index_age,omitempty"`
	MinPrimaryShardSize string `json:"min_primary_shard_size,omitempty"`
}

// DeleteAction represents a delete action
type DeleteAction struct{}

// ReadOnlyAction represents a read_only action
type ReadOnlyAction struct{}

// ReadWriteAction represents a read_write action
type ReadWriteAction struct{}

// ReplicaCountAction represents a replica_count action
type ReplicaCountAction struct {
	NumberOfReplicas int `json:"number_of_replicas"`
}

// ForceMergeAction represents a force_merge action
type ForceMergeAction struct {
	MaxNumSegments int `json:"max_num_segments"`
}

// ShrinkAction represents a shrink action
type ShrinkAction struct {
	NumNewShards    int    `json:"num_new_shards,omitempty"`
	TargetIndexName string `json:"target_index_name_template,omitempty"`
}

// AllocationAction represents an allocation action
type AllocationAction struct {
	Require map[string]string `json:"require,omitempty"`
	Include map[string]string `json:"include,omitempty"`
	Exclude map[string]string `json:"exclude,omitempty"`
}

// SnapshotAction represents a snapshot action
type SnapshotAction struct {
	Repository string `json:"repository"`
	Snapshot   string `json:"snapshot"`
}

// IndexPriorityAction represents an index_priority action
type IndexPriorityAction struct {
	Priority int `json:"priority"`
}

// CloseAction represents a close action
type CloseAction struct{}

// OpenAction represents an open action
type OpenAction struct{}

// ISMTransition represents a transition in an ISM state
type ISMTransition struct {
	StateName  string         `json:"state_name"`
	Conditions *ISMConditions `json:"conditions,omitempty"`
}

// ISMConditions represents transition conditions
type ISMConditions struct {
	MinIndexAge string         `json:"min_index_age,omitempty"`
	MinDocCount int64          `json:"min_doc_count,omitempty"`
	MinSize     string         `json:"min_size,omitempty"`
	Cron        *CronCondition `json:"cron,omitempty"`
}

// CronCondition represents a cron-based condition
type CronCondition struct {
	Expression string `json:"expression"`
	Timezone   string `json:"timezone,omitempty"`
}

// ISMTemplatePattern represents an ISM template pattern
type ISMTemplatePattern struct {
	IndexPatterns []string `json:"index_patterns"`
	Priority      int      `json:"priority,omitempty"`
}

// Create creates a new ISM policy
func (a *ISMAPI) Create(ctx context.Context, policyID string, policy ISMPolicy) error {
	resp, err := a.client.Put(ctx, fmt.Sprintf("/_plugins/_ism/policies/%s", policyID), policy)
	if err != nil {
		return fmt.Errorf("failed to create ISM policy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create ISM policy: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Get retrieves an ISM policy
func (a *ISMAPI) Get(ctx context.Context, policyID string) (*ISMPolicy, error) {
	resp, err := a.client.Get(ctx, fmt.Sprintf("/_plugins/_ism/policies/%s", policyID))
	if err != nil {
		return nil, fmt.Errorf("failed to get ISM policy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get ISM policy: status %d, body: %s", resp.StatusCode, string(body))
	}

	var policy ISMPolicy
	if err := json.NewDecoder(resp.Body).Decode(&policy); err != nil {
		return nil, fmt.Errorf("failed to decode ISM policy: %w", err)
	}

	return &policy, nil
}

// Update updates an existing ISM policy
func (a *ISMAPI) Update(ctx context.Context, policyID string, policy ISMPolicy, seqNo, primaryTerm int64) error {
	path := fmt.Sprintf("/_plugins/_ism/policies/%s?if_seq_no=%d&if_primary_term=%d", policyID, seqNo, primaryTerm)
	resp, err := a.client.Put(ctx, path, policy)
	if err != nil {
		return fmt.Errorf("failed to update ISM policy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update ISM policy: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Delete deletes an ISM policy
func (a *ISMAPI) Delete(ctx context.Context, policyID string) error {
	resp, err := a.client.Delete(ctx, fmt.Sprintf("/_plugins/_ism/policies/%s", policyID))
	if err != nil {
		return fmt.Errorf("failed to delete ISM policy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete ISM policy: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Exists checks if an ISM policy exists
func (a *ISMAPI) Exists(ctx context.Context, policyID string) (bool, error) {
	policy, err := a.Get(ctx, policyID)
	if err != nil {
		return false, err
	}
	return policy != nil, nil
}
