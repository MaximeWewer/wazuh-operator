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

// IndexSettings represents index settings
type IndexSettings struct {
	NumberOfShards   int `json:"number_of_shards,omitempty"`
	NumberOfReplicas int `json:"number_of_replicas,omitempty"`
}

// IndexConfig represents index configuration
type IndexConfig struct {
	Settings IndexSettings          `json:"settings,omitempty"`
	Mappings map[string]interface{} `json:"mappings,omitempty"`
}

// IndexAPI provides index management operations
type IndexAPI struct {
	client *Client
}

// NewIndexAPI creates a new IndexAPI
func NewIndexAPI(client *Client) *IndexAPI {
	return &IndexAPI{client: client}
}

// Create creates a new index
func (a *IndexAPI) Create(ctx context.Context, indexName string, config IndexConfig) error {
	resp, err := a.client.Put(ctx, "/"+indexName, config)
	if err != nil {
		return fmt.Errorf("failed to create index: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create index: %s", string(body))
	}

	return nil
}

// Exists checks if an index exists
func (a *IndexAPI) Exists(ctx context.Context, indexName string) (bool, error) {
	resp, err := a.client.Request(ctx, "HEAD", "/"+indexName, nil)
	if err != nil {
		return false, fmt.Errorf("failed to check index: %w", err)
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}

// Delete deletes an index
func (a *IndexAPI) Delete(ctx context.Context, indexName string) error {
	resp, err := a.client.Delete(ctx, "/"+indexName)
	if err != nil {
		return fmt.Errorf("failed to delete index: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete index: %s", string(body))
	}

	return nil
}

// GetSettings retrieves index settings
func (a *IndexAPI) GetSettings(ctx context.Context, indexName string) (map[string]interface{}, error) {
	resp, err := a.client.Get(ctx, "/"+indexName+"/_settings")
	if err != nil {
		return nil, fmt.Errorf("failed to get index settings: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get index settings: %s", string(body))
	}

	var settings map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&settings); err != nil {
		return nil, fmt.Errorf("failed to decode settings: %w", err)
	}

	return settings, nil
}

// UpdateSettings updates index settings
func (a *IndexAPI) UpdateSettings(ctx context.Context, indexName string, settings map[string]interface{}) error {
	resp, err := a.client.Put(ctx, "/"+indexName+"/_settings", settings)
	if err != nil {
		return fmt.Errorf("failed to update index settings: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update index settings: %s", string(body))
	}

	return nil
}
