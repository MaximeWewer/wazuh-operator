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

package pdb

import (
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	v1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// IndexerPDBBuilder builds PodDisruptionBudget resources for Indexer
type IndexerPDBBuilder struct {
	cluster *v1.WazuhCluster
}

// NewIndexerPDBBuilder creates a new IndexerPDBBuilder
func NewIndexerPDBBuilder(cluster *v1.WazuhCluster) *IndexerPDBBuilder {
	return &IndexerPDBBuilder{
		cluster: cluster,
	}
}

// Build creates a PodDisruptionBudget for the Indexer component
func (b *IndexerPDBBuilder) Build() *policyv1.PodDisruptionBudget {
	name := b.cluster.Name + "-indexer"
	namespace := b.cluster.Namespace

	// Build selector to match indexer pods
	// Indexer StatefulSets use constants.ComponentIndexer as component label
	selector := &metav1.LabelSelector{
		MatchLabels: constants.SelectorLabels(b.cluster.Name, constants.ComponentIndexer),
	}

	// Build the PDB
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    b.buildLabels(),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			Selector: selector,
		},
	}

	// Check for PDB configuration - MaxUnavailable takes priority over MinAvailable
	// (only one can be set on a PDB, not both)
	if b.cluster.Spec.Indexer != nil && b.cluster.Spec.Indexer.PodDisruptionBudget != nil {
		pdbSpec := b.cluster.Spec.Indexer.PodDisruptionBudget
		if pdbSpec.MaxUnavailable != nil {
			// Use MaxUnavailable if explicitly set (takes priority)
			pdb.Spec.MaxUnavailable = &intstr.IntOrString{
				Type:   intstr.Int,
				IntVal: *pdbSpec.MaxUnavailable,
			}
			return pdb
		}
		if pdbSpec.MinAvailable != nil {
			// Use custom MinAvailable if set
			pdb.Spec.MinAvailable = &intstr.IntOrString{
				Type:   intstr.Int,
				IntVal: *pdbSpec.MinAvailable,
			}
			return pdb
		}
	}

	// Default to MinAvailable if no explicit configuration
	pdb.Spec.MinAvailable = &intstr.IntOrString{
		Type:   intstr.Int,
		IntVal: constants.DefaultIndexerPDBMinAvailable,
	}

	return pdb
}

// BuildWithMaxUnavailable creates a PDB using maxUnavailable instead of minAvailable
func (b *IndexerPDBBuilder) BuildWithMaxUnavailable(maxUnavailable int32) *policyv1.PodDisruptionBudget {
	name := b.cluster.Name + "-indexer"
	namespace := b.cluster.Namespace

	// Build selector to match indexer pods
	selector := &metav1.LabelSelector{
		MatchLabels: constants.SelectorLabels(b.cluster.Name, constants.ComponentIndexer),
	}

	// Build the PDB
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    b.buildLabels(),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable: &intstr.IntOrString{
				Type:   intstr.Int,
				IntVal: maxUnavailable,
			},
			Selector: selector,
		},
	}

	return pdb
}

// buildLabels returns standard labels for the PDB
func (b *IndexerPDBBuilder) buildLabels() map[string]string {
	version := ""
	if b.cluster.Spec.Version != "" {
		version = b.cluster.Spec.Version
	}
	return constants.CommonLabels(b.cluster.Name, constants.ComponentIndexer, version)
}

// GetIndexerPDBName returns the expected PDB name for a cluster
func GetIndexerPDBName(clusterName string) string {
	return clusterName + "-indexer"
}

// ShouldCreateIndexerPDB determines if a PDB should be created for the indexer
func ShouldCreateIndexerPDB(cluster *v1.WazuhCluster) bool {
	// Don't create PDB if indexer is not configured
	if cluster.Spec.Indexer == nil {
		return false
	}

	// Check if PDB is explicitly disabled
	if cluster.Spec.Indexer.PodDisruptionBudget != nil {
		if !cluster.Spec.Indexer.PodDisruptionBudget.Enabled {
			return false
		}
	}

	// Get total replicas (works for both simple and advanced mode)
	// Simple mode: uses Replicas field
	// Advanced mode: sums all nodePool replicas
	totalReplicas := cluster.Spec.Indexer.GetTotalReplicas()

	// Only create PDB if there are at least 2 total indexer pods
	// PDB makes no sense for single-replica deployments
	return totalReplicas >= 2
}
