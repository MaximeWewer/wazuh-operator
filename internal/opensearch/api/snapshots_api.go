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

// Repository represents a snapshot repository
type Repository struct {
	Type     string                 `json:"type"`
	Settings map[string]interface{} `json:"settings,omitempty"`
}

// Snapshot represents a snapshot
type Snapshot struct {
	Snapshot           string   `json:"snapshot"`
	UUID               string   `json:"uuid,omitempty"`
	State              string   `json:"state,omitempty"`
	Indices            []string `json:"indices,omitempty"`
	IncludeGlobalState bool     `json:"include_global_state,omitempty"`
}

// SnapshotsAPI provides snapshot management operations
type SnapshotsAPI struct {
	client *Client
}

// NewSnapshotsAPI creates a new SnapshotsAPI
func NewSnapshotsAPI(client *Client) *SnapshotsAPI {
	return &SnapshotsAPI{client: client}
}

// CreateRepository creates a snapshot repository
func (a *SnapshotsAPI) CreateRepository(ctx context.Context, repoName string, repo Repository) error {
	resp, err := a.client.Put(ctx, "/_snapshot/"+repoName, repo)
	if err != nil {
		return fmt.Errorf("failed to create repository: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create repository: %s", string(body))
	}

	return nil
}

// GetRepository retrieves a snapshot repository
func (a *SnapshotsAPI) GetRepository(ctx context.Context, repoName string) (*Repository, error) {
	resp, err := a.client.Get(ctx, "/_snapshot/"+repoName)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get repository: %s", string(body))
	}

	var repos map[string]Repository
	if err := json.NewDecoder(resp.Body).Decode(&repos); err != nil {
		return nil, fmt.Errorf("failed to decode repository: %w", err)
	}

	if repo, ok := repos[repoName]; ok {
		return &repo, nil
	}

	return nil, nil
}

// DeleteRepository deletes a snapshot repository
func (a *SnapshotsAPI) DeleteRepository(ctx context.Context, repoName string) error {
	resp, err := a.client.Delete(ctx, "/_snapshot/"+repoName)
	if err != nil {
		return fmt.Errorf("failed to delete repository: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete repository: %s", string(body))
	}

	return nil
}

// CreateSnapshot creates a snapshot
func (a *SnapshotsAPI) CreateSnapshot(ctx context.Context, repoName, snapshotName string, snapshot Snapshot) error {
	resp, err := a.client.Put(ctx, fmt.Sprintf("/_snapshot/%s/%s", repoName, snapshotName), snapshot)
	if err != nil {
		return fmt.Errorf("failed to create snapshot: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create snapshot: %s", string(body))
	}

	return nil
}

// GetSnapshot retrieves a snapshot
func (a *SnapshotsAPI) GetSnapshot(ctx context.Context, repoName, snapshotName string) (*Snapshot, error) {
	resp, err := a.client.Get(ctx, fmt.Sprintf("/_snapshot/%s/%s", repoName, snapshotName))
	if err != nil {
		return nil, fmt.Errorf("failed to get snapshot: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get snapshot: %s", string(body))
	}

	var result struct {
		Snapshots []Snapshot `json:"snapshots"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode snapshot: %w", err)
	}

	if len(result.Snapshots) > 0 {
		return &result.Snapshots[0], nil
	}

	return nil, nil
}

// DeleteSnapshot deletes a snapshot
func (a *SnapshotsAPI) DeleteSnapshot(ctx context.Context, repoName, snapshotName string) error {
	resp, err := a.client.Delete(ctx, fmt.Sprintf("/_snapshot/%s/%s", repoName, snapshotName))
	if err != nil {
		return fmt.Errorf("failed to delete snapshot: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete snapshot: %s", string(body))
	}

	return nil
}
