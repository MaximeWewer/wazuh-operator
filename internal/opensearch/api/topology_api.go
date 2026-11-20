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

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// ClusterNode is a node of the OpenSearch cluster as _cat/nodes reports it.
type ClusterNode struct {
	Name string `json:"name"`
	// Role holds one letter per role (e.g. "dimr"); "m" means cluster-manager eligible.
	Role string `json:"node.role"`
	// ClusterManager is "*" on the elected cluster manager.
	ClusterManager string `json:"cluster_manager"`
}

// IsClusterManagerEligible reports whether the node may be elected cluster manager.
func (n ClusterNode) IsClusterManagerEligible() bool {
	return strings.Contains(n.Role, "m")
}

// IsDataNode reports whether the node holds data.
func (n ClusterNode) IsDataNode() bool {
	return strings.Contains(n.Role, "d")
}

// IsElectedClusterManager reports whether the node is the elected cluster manager.
func (n ClusterNode) IsElectedClusterManager() bool {
	return n.ClusterManager == "*"
}

// ListNodes returns the nodes that are part of the cluster.
func (c *Client) ListNodes(ctx context.Context) ([]ClusterNode, error) {
	var nodes []ClusterNode
	if err := c.getJSON(ctx, "/_cat/nodes?format=json&h=name,node.role,cluster_manager", &nodes); err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}
	return nodes, nil
}

// AddVotingConfigExclusions removes cluster-manager eligible nodes from the voting
// configuration, so the cluster elects a cluster manager among the other nodes and keeps a
// quorum when they leave. OpenSearch waits for the reconfiguration before answering.
func (c *Client) AddVotingConfigExclusions(ctx context.Context, nodeNames []string) error {
	path := "/_cluster/voting_config_exclusions?timeout=60s&node_names=" + url.QueryEscape(strings.Join(nodeNames, ","))
	return c.expectOK(ctx, http.MethodPost, path, "add voting config exclusions")
}

// ClearVotingConfigExclusions removes every voting configuration exclusion, without
// waiting for the excluded nodes to leave the cluster.
func (c *Client) ClearVotingConfigExclusions(ctx context.Context) error {
	return c.expectOK(ctx, http.MethodDelete, "/_cluster/voting_config_exclusions?wait_for_removal=false", "clear voting config exclusions")
}

// GetVotingConfigExclusions returns the names of the nodes excluded from voting.
func (c *Client) GetVotingConfigExclusions(ctx context.Context) ([]string, error) {
	var state struct {
		Metadata struct {
			ClusterCoordination struct {
				VotingConfigExclusions []struct {
					NodeName string `json:"node_name"`
				} `json:"voting_config_exclusions"`
			} `json:"cluster_coordination"`
		} `json:"metadata"`
	}
	if err := c.getJSON(ctx, "/_cluster/state/metadata?filter_path=metadata.cluster_coordination.voting_config_exclusions", &state); err != nil {
		return nil, fmt.Errorf("failed to get voting config exclusions: %w", err)
	}
	names := make([]string, 0, len(state.Metadata.ClusterCoordination.VotingConfigExclusions))
	for _, e := range state.Metadata.ClusterCoordination.VotingConfigExclusions {
		names = append(names, e.NodeName)
	}
	return names, nil
}

// DataFootprint is the size of the data the cluster stores.
type DataFootprint struct {
	// TotalBytes is the store size of every shard copy, primaries and replicas.
	TotalBytes int64
	// LargestShardBytes is the store size of the largest shard copy.
	LargestShardBytes int64
}

// GetDataFootprint returns the store size of all the shards and of the largest one, the
// space another set of data nodes needs to take them over.
func (c *Client) GetDataFootprint(ctx context.Context) (*DataFootprint, error) {
	var shards []struct {
		Store string `json:"store"`
	}
	if err := c.getJSON(ctx, "/_cat/shards?format=json&bytes=b&h=store", &shards); err != nil {
		return nil, fmt.Errorf("failed to get shard sizes: %w", err)
	}
	fp := &DataFootprint{}
	for _, s := range shards {
		if s.Store == "" {
			continue // unassigned copy
		}
		size, err := strconv.ParseInt(s.Store, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("unexpected shard store size %q: %w", s.Store, err)
		}
		fp.TotalBytes += size
		fp.LargestShardBytes = max(fp.LargestShardBytes, size)
	}
	return fp, nil
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	resp, err := c.Get(ctx, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) expectOK(ctx context.Context, method, path, what string) error {
	resp, err := c.Request(ctx, method, path, nil)
	if err != nil {
		return fmt.Errorf("failed to %s: %w", what, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s failed with status %d: %s", what, resp.StatusCode, string(body))
	}
	return nil
}

// GetShardCountsByNode returns the number of shard copies each node holds, relocating
// copies counted on their source node.
func (c *Client) GetShardCountsByNode(ctx context.Context) (map[string]int, error) {
	var shards []struct {
		Node string `json:"node"`
	}
	if err := c.getJSON(ctx, "/_cat/shards?format=json&h=node", &shards); err != nil {
		return nil, fmt.Errorf("failed to list shards: %w", err)
	}
	counts := map[string]int{}
	for _, s := range shards {
		if s.Node == "" {
			continue // unassigned copy
		}
		// A relocating copy reads "source -> address target_id target".
		node, _, _ := strings.Cut(s.Node, " ")
		counts[node]++
	}
	return counts, nil
}

// IndexPlacement is what constrains where the shards of the cluster's indices may go.
type IndexPlacement struct {
	// MaxReplicas is the highest number_of_replicas among the indices without
	// auto_expand_replicas: their copies need MaxReplicas+1 data nodes.
	MaxReplicas int
	// MaxReplicasIndex is an index with MaxReplicas replicas.
	MaxReplicasIndex string
	// FilteredIndices are the indices with an index.routing.allocation.require or include
	// filter, whose shards only go to the nodes that match it.
	FilteredIndices []string
}

// GetIndexPlacement returns the replica counts and allocation filters of all the indices,
// hidden and system ones included.
func (c *Client) GetIndexPlacement(ctx context.Context) (*IndexPlacement, error) {
	var settings map[string]struct {
		Settings struct {
			Index struct {
				NumberOfReplicas   string `json:"number_of_replicas"`
				AutoExpandReplicas string `json:"auto_expand_replicas"`
				Routing            struct {
					Allocation struct {
						Require map[string]any `json:"require"`
						Include map[string]any `json:"include"`
					} `json:"allocation"`
				} `json:"routing"`
			} `json:"index"`
		} `json:"settings"`
	}
	path := "/_all/_settings?expand_wildcards=all&filter_path=*.settings.index.number_of_replicas," +
		"*.settings.index.auto_expand_replicas,*.settings.index.routing.allocation.require,*.settings.index.routing.allocation.include"
	if err := c.getJSON(ctx, path, &settings); err != nil {
		return nil, fmt.Errorf("failed to get index settings: %w", err)
	}
	p := &IndexPlacement{}
	for name, s := range settings {
		idx := s.Settings.Index
		if len(idx.Routing.Allocation.Require) > 0 || len(idx.Routing.Allocation.Include) > 0 {
			p.FilteredIndices = append(p.FilteredIndices, name)
		}
		if idx.AutoExpandReplicas != "" && idx.AutoExpandReplicas != "false" {
			continue
		}
		replicas, err := strconv.Atoi(idx.NumberOfReplicas)
		if err != nil {
			continue
		}
		if replicas > p.MaxReplicas {
			p.MaxReplicas, p.MaxReplicasIndex = replicas, name
		}
	}
	slices.Sort(p.FilteredIndices)
	return p, nil
}

// GetClusterSetting returns the value of a cluster setting set by the cluster settings API,
// transient first, "" when it is not set.
func (c *Client) GetClusterSetting(ctx context.Context, key string) (string, error) {
	var settings struct {
		Persistent map[string]any `json:"persistent"`
		Transient  map[string]any `json:"transient"`
	}
	if err := c.getJSON(ctx, "/_cluster/settings?flat_settings=true", &settings); err != nil {
		return "", fmt.Errorf("failed to get cluster settings: %w", err)
	}
	for _, scope := range []map[string]any{settings.Transient, settings.Persistent} {
		if v, ok := scope[key]; ok && v != nil {
			return fmt.Sprint(v), nil
		}
	}
	return "", nil
}
