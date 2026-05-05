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
	"fmt"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/security"
)

// PerClusterFn is invoked once per target cluster. Implementations push the
// resource via the OpenSearch API and return the spec hash applied (or an
// empty string when no hash is tracked) plus any error.
type PerClusterFn func(ctx context.Context, apiClient *api.Client, ref wazuhv1.WazuhClusterRef) (specHash string, err error)

// MultiClusterResult aggregates per-cluster outcomes.
type MultiClusterResult struct {
	Statuses     []wazuhv1.OpenSearchClusterStatus
	AnyFailed    bool
	AnyPending   bool
	AllReady     bool
	FirstError   error
	LastSpecHash string
}

// ReconcileMultiCluster iterates each cluster reference, builds a client via
// the factory, runs the per-cluster function and aggregates per-cluster
// statuses. Existing statuses are preserved by (name, namespace) key so
// transient values like LastSyncTime remain stable across reconciles.
func ReconcileMultiCluster(
	ctx context.Context,
	refs []wazuhv1.WazuhClusterRef,
	factory *security.OpenSearchClientFactory,
	existing []wazuhv1.OpenSearchClusterStatus,
	fn PerClusterFn,
) MultiClusterResult {
	res := MultiClusterResult{AllReady: len(refs) > 0}

	byKey := make(map[string]wazuhv1.OpenSearchClusterStatus, len(existing))
	for _, s := range existing {
		byKey[s.Namespace+"/"+s.Name] = s
	}

	for _, ref := range refs {
		st := byKey[ref.Namespace+"/"+ref.Name]
		st.Name = ref.Name
		st.Namespace = ref.Namespace

		if factory == nil {
			st.Phase = wazuhv1.OpenSearchResourcePhasePending
			st.Message = "Waiting for OpenSearch client factory"
			res.AnyPending = true
			res.AllReady = false
			res.Statuses = append(res.Statuses, st)
			continue
		}

		apiClient, err := factory.GetClientForClusterRef(ctx, ref)
		if err != nil {
			st.Phase = wazuhv1.OpenSearchResourcePhasePending
			st.Message = fmt.Sprintf("Failed to get OpenSearch client: %v", err)
			res.AnyPending = true
			res.AllReady = false
			if res.FirstError == nil {
				res.FirstError = err
			}
			res.Statuses = append(res.Statuses, st)
			continue
		}

		hash, err := fn(ctx, apiClient, ref)
		if err != nil {
			st.Phase = wazuhv1.OpenSearchResourcePhaseFailed
			st.Message = err.Error()
			res.AnyFailed = true
			res.AllReady = false
			if res.FirstError == nil {
				res.FirstError = err
			}
			res.Statuses = append(res.Statuses, st)
			continue
		}

		// Success on this cluster
		wasReady := st.Phase == wazuhv1.OpenSearchResourcePhaseReady
		st.Phase = wazuhv1.OpenSearchResourcePhaseReady
		st.Message = ""
		if hash != "" {
			st.LastAppliedHash = hash
			res.LastSpecHash = hash
		}
		if !wasReady {
			now := metav1.Now()
			st.LastSyncTime = &now
		}
		res.Statuses = append(res.Statuses, st)
	}

	sort.Slice(res.Statuses, func(i, j int) bool {
		if res.Statuses[i].Namespace != res.Statuses[j].Namespace {
			return res.Statuses[i].Namespace < res.Statuses[j].Namespace
		}
		return res.Statuses[i].Name < res.Statuses[j].Name
	})

	return res
}

// AggregatePhase returns the aggregate phase for a multi-cluster CR based on
// per-cluster outcomes: Failed if any failed, Pending if any pending, else Ready.
func (r MultiClusterResult) AggregatePhase() wazuhv1.OpenSearchResourcePhase {
	switch {
	case r.AnyFailed:
		return wazuhv1.OpenSearchResourcePhaseFailed
	case r.AnyPending:
		return wazuhv1.OpenSearchResourcePhasePending
	case r.AllReady:
		return wazuhv1.OpenSearchResourcePhaseReady
	default:
		return wazuhv1.OpenSearchResourcePhasePending
	}
}

// AggregateMessage returns a human-readable summary of cluster outcomes.
func (r MultiClusterResult) AggregateMessage() string {
	switch {
	case r.AnyFailed:
		return "One or more target clusters failed to sync"
	case r.AnyPending:
		return "Waiting on one or more target clusters"
	case r.AllReady:
		return "Reconciled on all target clusters"
	default:
		return ""
	}
}
