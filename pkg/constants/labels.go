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

// Package constants provides shared constants for the Wazuh Operator
package constants

// Standard Kubernetes labels (app.kubernetes.io/*)
const (
	// LabelName is the name of the application
	LabelName = "app.kubernetes.io/name"

	// LabelInstance is the name of the instance (CR name)
	LabelInstance = "app.kubernetes.io/instance"

	// LabelVersion is the version of the application
	LabelVersion = "app.kubernetes.io/version"

	// LabelComponent is the component within the architecture
	LabelComponent = "app.kubernetes.io/component"

	// LabelPartOf is the name of the higher-level application this is part of
	LabelPartOf = "app.kubernetes.io/part-of"

	// LabelManagedBy is the tool being used to manage the operation
	LabelManagedBy = "app.kubernetes.io/managed-by"
)

// Wazuh custom labels (wazuh.com/*)
const (
	// LabelWazuhCluster is the name of the WazuhCluster CR
	LabelWazuhCluster = "wazuh.com/cluster"

	// LabelWazuhNodeType identifies the node type (manager, worker, indexer, dashboard)
	LabelWazuhNodeType = "wazuh.com/node-type"

	// LabelWazuhNodeRole identifies the node role (master, worker, data, client)
	LabelWazuhNodeRole = "wazuh.com/node-role"

	// LabelWazuhManagedBy indicates the resource is managed by the operator
	LabelWazuhManagedBy = "wazuh.com/managed-by"

	// LabelWazuhConfigHash contains a hash of the configuration for change detection
	LabelWazuhConfigHash = "wazuh.com/config-hash"

	// LabelWazuhSecretHash contains a hash of secrets for rotation detection
	LabelWazuhSecretHash = "wazuh.com/secret-hash"

	// LabelManagerNodeType identifies the manager node type (master/worker)
	LabelManagerNodeType = "wazuh.com/manager-node-type"

	// LabelNodePool identifies the nodePool name for advanced indexer topology
	LabelNodePool = "wazuh.com/node-pool"
)

// Wazuh custom annotations (wazuh.com/*)
const (
	// AnnotationCertHash is the annotation for certificate hash to trigger pod restart on cert renewal
	AnnotationCertHash = "wazuh.com/cert-hash"

	// AnnotationLastCertRenewal is the annotation for last certificate renewal timestamp
	AnnotationLastCertRenewal = "wazuh.com/last-cert-renewal"
)

// Application identity constants
const (
	// AppName is the base application name
	AppName = "wazuh"

	// OperatorName is the operator name used in managed-by labels
	OperatorName = "wazuh-operator"
)

// Component values for LabelComponent
const (
	ComponentManager       = "manager"
	ComponentWorker        = "worker"
	ComponentIndexer       = "indexer"
	ComponentDashboard     = "dashboard"
	ComponentManagerMaster = "manager-master"
	ComponentManagerWorker = "manager-worker"
	ComponentLogRotation   = "log-rotation"
	ComponentSecurity      = "security"
	ComponentDashboardAuth = "dashboard-auth"
)

// Node type values for LabelWazuhNodeType
const (
	NodeTypeManager   = "manager"
	NodeTypeWorker    = "worker"
	NodeTypeIndexer   = "indexer"
	NodeTypeDashboard = "dashboard"
)

// Node role values for LabelWazuhNodeRole
const (
	NodeRoleMaster = "master"
	NodeRoleWorker = "worker"
	NodeRoleData   = "data"
	NodeRoleClient = "client"
)

// CommonLabels returns the standard labels for a Wazuh resource
func CommonLabels(clusterName, component, version string) map[string]string {
	return map[string]string{
		LabelName:           AppName + "-" + component,
		LabelInstance:       clusterName,
		LabelVersion:        version,
		LabelComponent:      component,
		LabelPartOf:         AppName,
		LabelManagedBy:      OperatorName,
		LabelWazuhCluster:   clusterName,
		LabelWazuhManagedBy: OperatorName,
	}
}

// SelectorLabels returns the minimal labels for selecting resources
func SelectorLabels(clusterName, component string) map[string]string {
	return map[string]string{
		LabelName:         AppName + "-" + component,
		LabelInstance:     clusterName,
		LabelWazuhCluster: clusterName,
	}
}
