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

// SnapshotPolicy represents a snapshot management policy
type SnapshotPolicy struct {
	Name           string                  `json:"name,omitempty"`
	Description    string                  `json:"description,omitempty"`
	Creation       *SnapshotCreation       `json:"creation,omitempty"`
	Deletion       *SnapshotDeletion       `json:"deletion,omitempty"`
	SnapshotConfig *SnapshotConfig         `json:"snapshot_config,omitempty"`
	Schedule       *SnapshotPolicySchedule `json:"schedule,omitempty"`
	Enabled        bool                    `json:"enabled"`
}

// SnapshotCreation defines snapshot creation settings
type SnapshotCreation struct {
	Schedule  *SnapshotPolicySchedule `json:"schedule,omitempty"`
	TimeLimit string                  `json:"time_limit,omitempty"`
}

// SnapshotDeletion defines snapshot deletion settings
type SnapshotDeletion struct {
	Schedule  *SnapshotPolicySchedule  `json:"schedule,omitempty"`
	Condition *SnapshotDeleteCondition `json:"condition,omitempty"`
	TimeLimit string                   `json:"time_limit,omitempty"`
}

// SnapshotDeleteCondition defines when to delete snapshots
type SnapshotDeleteCondition struct {
	MaxAge   string `json:"max_age,omitempty"`
	MaxCount int64  `json:"max_count,omitempty"`
	MinCount int64  `json:"min_count,omitempty"`
}

// SnapshotConfig defines snapshot configuration
type SnapshotConfig struct {
	Repository string `json:"repository"`
	Indices    string `json:"indices,omitempty"`
	DateFormat string `json:"date_format,omitempty"`
	Timezone   string `json:"timezone,omitempty"`
}

// SnapshotPolicySchedule defines the schedule for snapshot operations
type SnapshotPolicySchedule struct {
	Cron *CronSchedule `json:"cron,omitempty"`
}

// CronSchedule defines a cron-based schedule
type CronSchedule struct {
	Expression string `json:"expression"`
	Timezone   string `json:"timezone,omitempty"`
}

// SnapshotAPI provides snapshot management operations
type SnapshotAPI struct {
	client *Client
}

// NewSnapshotAPI creates a new SnapshotAPI
func NewSnapshotAPI(client *Client) *SnapshotAPI {
	return &SnapshotAPI{client: client}
}

// CreatePolicy creates a snapshot management policy
func (a *SnapshotAPI) CreatePolicy(ctx context.Context, policyID string, policy SnapshotPolicy) error {
	resp, err := a.client.Put(ctx, "/_plugins/_sm/policies/"+policyID, policy)
	if err != nil {
		return fmt.Errorf("failed to create snapshot policy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create snapshot policy: %s", string(body))
	}

	return nil
}

// GetPolicy retrieves a snapshot management policy
func (a *SnapshotAPI) GetPolicy(ctx context.Context, policyID string) (*SnapshotPolicy, error) {
	resp, err := a.client.Get(ctx, "/_plugins/_sm/policies/"+policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get snapshot policy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get snapshot policy: %s", string(body))
	}

	var result struct {
		Policy SnapshotPolicy `json:"policy"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode snapshot policy: %w", err)
	}

	return &result.Policy, nil
}

// DeletePolicy deletes a snapshot management policy
func (a *SnapshotAPI) DeletePolicy(ctx context.Context, policyID string) error {
	resp, err := a.client.Delete(ctx, "/_plugins/_sm/policies/"+policyID)
	if err != nil {
		return fmt.Errorf("failed to delete snapshot policy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete snapshot policy: %s", string(body))
	}

	return nil
}

// Exists checks if a snapshot policy exists
func (a *SnapshotAPI) Exists(ctx context.Context, policyID string) (bool, error) {
	policy, err := a.GetPolicy(ctx, policyID)
	if err != nil {
		return false, err
	}
	return policy != nil, nil
}
