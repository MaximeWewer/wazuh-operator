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

// VerifyRepositoryResult contains the result of repository verification
type VerifyRepositoryResult struct {
	Nodes map[string]struct {
		Name string `json:"name"`
	} `json:"nodes"`
}

// VerifyRepository verifies a snapshot repository
func (a *SnapshotsAPI) VerifyRepository(ctx context.Context, repoName string) (*VerifyRepositoryResult, error) {
	resp, err := a.client.Post(ctx, fmt.Sprintf("/_snapshot/%s/_verify", repoName), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to verify repository: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("repository verification failed: %s", string(body))
	}

	var result VerifyRepositoryResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode verification result: %w", err)
	}

	return &result, nil
}

// ListSnapshotsResult contains the list of snapshots in a repository
type ListSnapshotsResult struct {
	Snapshots []SnapshotInfo `json:"snapshots"`
}

// SnapshotInfo contains detailed snapshot information
type SnapshotInfo struct {
	Snapshot           string      `json:"snapshot"`
	UUID               string      `json:"uuid"`
	VersionID          int         `json:"version_id"`
	Version            string      `json:"version"`
	Indices            []string    `json:"indices"`
	DataStreams        []string    `json:"data_streams,omitempty"`
	IncludeGlobalState bool        `json:"include_global_state"`
	State              string      `json:"state"`
	StartTime          string      `json:"start_time"`
	StartTimeInMillis  int64       `json:"start_time_in_millis"`
	EndTime            string      `json:"end_time,omitempty"`
	EndTimeInMillis    int64       `json:"end_time_in_millis,omitempty"`
	DurationInMillis   int64       `json:"duration_in_millis,omitempty"`
	Failures           []string    `json:"failures,omitempty"`
	Shards             *ShardStats `json:"shards,omitempty"`
}

// ShardStats contains shard statistics
type ShardStats struct {
	Total      int `json:"total"`
	Successful int `json:"successful"`
	Failed     int `json:"failed"`
}

// ListSnapshots lists all snapshots in a repository
func (a *SnapshotsAPI) ListSnapshots(ctx context.Context, repoName string) (*ListSnapshotsResult, error) {
	resp, err := a.client.Get(ctx, fmt.Sprintf("/_snapshot/%s/_all", repoName))
	if err != nil {
		return nil, fmt.Errorf("failed to list snapshots: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &ListSnapshotsResult{Snapshots: []SnapshotInfo{}}, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list snapshots: %s", string(body))
	}

	var result ListSnapshotsResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode snapshots list: %w", err)
	}

	return &result, nil
}

// UpdateRepository updates a snapshot repository (alias for CreateRepository as PUT is idempotent)
func (a *SnapshotsAPI) UpdateRepository(ctx context.Context, repoName string, repo Repository) error {
	return a.CreateRepository(ctx, repoName, repo)
}

// RestoreOptions defines options for restoring a snapshot
type RestoreOptions struct {
	// Indices to restore (empty = all)
	Indices []string `json:"indices,omitempty"`

	// IgnoreUnavailable skips missing indices
	IgnoreUnavailable bool `json:"ignore_unavailable,omitempty"`

	// IncludeGlobalState restores cluster state
	IncludeGlobalState bool `json:"include_global_state,omitempty"`

	// RenamePattern is regex to match index names
	RenamePattern string `json:"rename_pattern,omitempty"`

	// RenameReplacement is the replacement string
	RenameReplacement string `json:"rename_replacement,omitempty"`

	// IndexSettings are settings to override during restore
	IndexSettings map[string]interface{} `json:"index_settings,omitempty"`

	// IgnoreIndexSettings are settings to ignore during restore
	IgnoreIndexSettings []string `json:"ignore_index_settings,omitempty"`

	// Partial allows restoring partial snapshots
	Partial bool `json:"partial,omitempty"`
}

// RestoreResult contains the result of a restore operation
type RestoreResult struct {
	Snapshot struct {
		Snapshot string     `json:"snapshot"`
		Indices  []string   `json:"indices"`
		Shards   ShardStats `json:"shards"`
	} `json:"snapshot"`
}

// RestoreSnapshot restores indices from a snapshot
func (a *SnapshotsAPI) RestoreSnapshot(ctx context.Context, repoName, snapshotName string, opts RestoreOptions) (*RestoreResult, error) {
	resp, err := a.client.Post(ctx, fmt.Sprintf("/_snapshot/%s/%s/_restore", repoName, snapshotName), opts)
	if err != nil {
		return nil, fmt.Errorf("failed to restore snapshot: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to restore snapshot: %s", string(body))
	}

	var result RestoreResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode restore result: %w", err)
	}

	return &result, nil
}

// SnapshotStatusResult contains snapshot status information
type SnapshotStatusResult struct {
	Snapshots []SnapshotStatus `json:"snapshots"`
}

// SnapshotStatus contains status of a snapshot operation
type SnapshotStatus struct {
	Snapshot           string                 `json:"snapshot"`
	Repository         string                 `json:"repository"`
	UUID               string                 `json:"uuid"`
	State              string                 `json:"state"`
	IncludeGlobalState bool                   `json:"include_global_state"`
	ShardsStats        ShardStats             `json:"shards_stats"`
	Stats              SnapshotStats          `json:"stats"`
	Indices            map[string]IndexStatus `json:"indices,omitempty"`
}

// SnapshotStats contains snapshot statistics
type SnapshotStats struct {
	Incremental struct {
		FileCount   int   `json:"file_count"`
		SizeInBytes int64 `json:"size_in_bytes"`
	} `json:"incremental"`
	Processed struct {
		FileCount   int   `json:"file_count"`
		SizeInBytes int64 `json:"size_in_bytes"`
	} `json:"processed"`
	Total struct {
		FileCount   int   `json:"file_count"`
		SizeInBytes int64 `json:"size_in_bytes"`
	} `json:"total"`
	StartTimeInMillis int64 `json:"start_time_in_millis"`
	TimeInMillis      int64 `json:"time_in_millis"`
}

// IndexStatus contains status of an index in a snapshot
type IndexStatus struct {
	ShardsStats ShardStats `json:"shards_stats"`
	Stats       struct {
		Incremental struct {
			FileCount   int   `json:"file_count"`
			SizeInBytes int64 `json:"size_in_bytes"`
		} `json:"incremental"`
		Total struct {
			FileCount   int   `json:"file_count"`
			SizeInBytes int64 `json:"size_in_bytes"`
		} `json:"total"`
	} `json:"stats"`
	Shards map[string]struct {
		Stage string     `json:"stage"`
		Stats ShardStats `json:"stats"`
	} `json:"shards"`
}

// GetSnapshotStatus gets the status of a snapshot
func (a *SnapshotsAPI) GetSnapshotStatus(ctx context.Context, repoName, snapshotName string) (*SnapshotStatusResult, error) {
	resp, err := a.client.Get(ctx, fmt.Sprintf("/_snapshot/%s/%s/_status", repoName, snapshotName))
	if err != nil {
		return nil, fmt.Errorf("failed to get snapshot status: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get snapshot status: %s", string(body))
	}

	var result SnapshotStatusResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode snapshot status: %w", err)
	}

	return &result, nil
}

// RecoveryInfo contains information about a recovery operation
type RecoveryInfo struct {
	Shards []ShardRecoveryInfo `json:"shards"`
}

// ShardRecoveryInfo contains recovery information for a shard
type ShardRecoveryInfo struct {
	ID                int    `json:"id"`
	Type              string `json:"type"`
	Stage             string `json:"stage"`
	Primary           bool   `json:"primary"`
	StartTimeInMillis int64  `json:"start_time_in_millis"`
	StopTimeInMillis  int64  `json:"stop_time_in_millis,omitempty"`
	TotalTimeInMillis int64  `json:"total_time_in_millis"`
	Source            struct {
		Repository string `json:"repository,omitempty"`
		Snapshot   string `json:"snapshot,omitempty"`
		Index      string `json:"index,omitempty"`
	} `json:"source"`
	Target struct {
		ID   string `json:"id"`
		Host string `json:"host"`
		Name string `json:"name"`
	} `json:"target"`
	Index struct {
		Size struct {
			TotalInBytes     int64  `json:"total_in_bytes"`
			RecoveredInBytes int64  `json:"recovered_in_bytes"`
			Percent          string `json:"percent"`
		} `json:"size"`
		Files struct {
			Total     int    `json:"total"`
			Recovered int    `json:"recovered"`
			Percent   string `json:"percent"`
		} `json:"files"`
	} `json:"index"`
}

// GetRestoreStatus gets the status of restore operations for an index
func (a *SnapshotsAPI) GetRestoreStatus(ctx context.Context, indexName string) (map[string]RecoveryInfo, error) {
	endpoint := "/_recovery"
	if indexName != "" {
		endpoint = fmt.Sprintf("/%s/_recovery", indexName)
	}

	resp, err := a.client.Get(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get restore status: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get restore status: %s", string(body))
	}

	var result map[string]RecoveryInfo
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode restore status: %w", err)
	}

	return result, nil
}
