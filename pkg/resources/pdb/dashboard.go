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

package pdb

import (
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// DashboardPDBBuilder builds PodDisruptionBudget resources for Dashboard
type DashboardPDBBuilder struct {
	cluster *v1alpha1.WazuhCluster
}

// NewDashboardPDBBuilder creates a new DashboardPDBBuilder
func NewDashboardPDBBuilder(cluster *v1alpha1.WazuhCluster) *DashboardPDBBuilder {
	return &DashboardPDBBuilder{
		cluster: cluster,
	}
}

// Build creates a PodDisruptionBudget for the Dashboard component
func (b *DashboardPDBBuilder) Build() *policyv1.PodDisruptionBudget {
	name := b.cluster.Name + "-dashboard"
	namespace := b.cluster.Namespace

	// Determine minAvailable value
	minAvailable := constants.DefaultDashboardPDBMinAvailable

	// Allow override from cluster spec if dashboard PDB is configured
	if b.cluster.Spec.Dashboard != nil && b.cluster.Spec.Dashboard.PodDisruptionBudget != nil {
		if b.cluster.Spec.Dashboard.PodDisruptionBudget.MinAvailable != nil {
			minAvailable = *b.cluster.Spec.Dashboard.PodDisruptionBudget.MinAvailable
		}
	}

	// Build selector to match dashboard pods
	selector := &metav1.LabelSelector{
		MatchLabels: constants.SelectorLabels(b.cluster.Name, constants.ComponentDashboard),
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
func (b *DashboardPDBBuilder) BuildWithMaxUnavailable(maxUnavailable int32) *policyv1.PodDisruptionBudget {
	name := b.cluster.Name + "-dashboard"
	namespace := b.cluster.Namespace

	// Build selector to match dashboard pods
	selector := &metav1.LabelSelector{
		MatchLabels: constants.SelectorLabels(b.cluster.Name, constants.ComponentDashboard),
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
func (b *DashboardPDBBuilder) buildLabels() map[string]string {
	version := ""
	if b.cluster.Spec.Version != "" {
		version = b.cluster.Spec.Version
	}
	return constants.CommonLabels(b.cluster.Name, constants.ComponentDashboard, version)
}

// GetPDBName returns the expected PDB name for a cluster
func GetPDBName(clusterName string) string {
	return clusterName + "-dashboard"
}

// ShouldCreatePDB determines if a PDB should be created for the dashboard
func ShouldCreatePDB(cluster *v1alpha1.WazuhCluster) bool {
	// Don't create PDB if dashboard is not configured
	if cluster.Spec.Dashboard == nil {
		return false
	}

	// Check if PDB is explicitly disabled
	if cluster.Spec.Dashboard.PodDisruptionBudget != nil {
		if !cluster.Spec.Dashboard.PodDisruptionBudget.Enabled {
			return false
		}
	}

	// Check if dashboard has at least 1 replica
	replicas := cluster.Spec.Dashboard.Replicas
	if replicas == 0 {
		replicas = 1 // Default
	}

	// Only create PDB if there's at least 1 replica
	return replicas >= 1
}
