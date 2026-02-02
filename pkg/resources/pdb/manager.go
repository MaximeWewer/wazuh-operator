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

// ManagerPDBBuilder builds PodDisruptionBudget resources for Manager
type ManagerPDBBuilder struct {
	cluster *v1.WazuhCluster
}

// NewManagerPDBBuilder creates a new ManagerPDBBuilder
func NewManagerPDBBuilder(cluster *v1.WazuhCluster) *ManagerPDBBuilder {
	return &ManagerPDBBuilder{
		cluster: cluster,
	}
}

// Build creates a PodDisruptionBudget for the Manager component
func (b *ManagerPDBBuilder) Build() *policyv1.PodDisruptionBudget {
	name := b.cluster.Name + "-manager"
	namespace := b.cluster.Namespace

	// Determine minAvailable value
	minAvailable := constants.DefaultManagerPDBMinAvailable

	// Allow override from cluster spec if manager PDB is configured
	if b.cluster.Spec.Manager != nil && b.cluster.Spec.Manager.PodDisruptionBudget != nil {
		if b.cluster.Spec.Manager.PodDisruptionBudget.MinAvailable != nil {
			minAvailable = *b.cluster.Spec.Manager.PodDisruptionBudget.MinAvailable
		}
	}

	// Build selector to match manager pods
	// Manager StatefulSets use "wazuh-manager" as component label
	selector := &metav1.LabelSelector{
		MatchLabels: constants.SelectorLabels(b.cluster.Name, "wazuh-manager"),
	}

	// Build the PDB
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    b.buildLabels(),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MinAvailable: &intstr.IntOrString{
				Type:   intstr.Int,
				IntVal: minAvailable,
			},
			Selector: selector,
		},
	}

	return pdb
}

// BuildWithMaxUnavailable creates a PDB using maxUnavailable instead of minAvailable
func (b *ManagerPDBBuilder) BuildWithMaxUnavailable(maxUnavailable int32) *policyv1.PodDisruptionBudget {
	name := b.cluster.Name + "-manager"
	namespace := b.cluster.Namespace

	// Build selector to match manager pods
	selector := &metav1.LabelSelector{
		MatchLabels: constants.SelectorLabels(b.cluster.Name, "wazuh-manager"),
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
func (b *ManagerPDBBuilder) buildLabels() map[string]string {
	version := ""
	if b.cluster.Spec.Version != "" {
		version = b.cluster.Spec.Version
	}
	return constants.CommonLabels(b.cluster.Name, constants.ComponentManager, version)
}

// GetManagerPDBName returns the expected PDB name for a cluster
func GetManagerPDBName(clusterName string) string {
	return clusterName + "-manager"
}

// ShouldCreateManagerPDB determines if a PDB should be created for the manager
func ShouldCreateManagerPDB(cluster *v1.WazuhCluster) bool {
	// Don't create PDB if manager is not configured
	if cluster.Spec.Manager == nil {
		return false
	}

	// Check if PDB is explicitly disabled
	if cluster.Spec.Manager.PodDisruptionBudget != nil {
		if !cluster.Spec.Manager.PodDisruptionBudget.Enabled {
			return false
		}
	}

	// Calculate total manager replicas (1 master + workers)
	// Master is always 1 replica
	totalReplicas := int32(1)

	// Add worker replicas if configured
	if cluster.Spec.Manager.Workers.Replicas != nil {
		totalReplicas += *cluster.Spec.Manager.Workers.Replicas
	}

	// Only create PDB if there are at least 2 total manager pods
	// PDB makes no sense for single-replica deployments
	return totalReplicas >= 2
}
