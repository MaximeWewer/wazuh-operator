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

// Package finalizers provides consistent finalizer management across all CRDs.
package finalizers

// Domain is the base domain for all finalizers
const Domain = "resources.wazuh.com"

// Wazuh Core CRDs
const (
	// WazuhCluster finalizer for cluster cleanup
	WazuhCluster = Domain + "/wazuhcluster"

	// WazuhManager finalizer for manager cleanup
	WazuhManager = Domain + "/wazuhmanager"

	// WazuhWorker finalizer for worker cleanup
	WazuhWorker = Domain + "/wazuhworker"

	// WazuhCertificate finalizer for certificate cleanup
	WazuhCertificate = Domain + "/wazuhcertificate"

	// WazuhRule finalizer for rule file cleanup
	WazuhRule = Domain + "/wazuhrule"

	// WazuhDecoder finalizer for decoder file cleanup
	WazuhDecoder = Domain + "/wazuhdecoder"

	// WazuhFilebeat finalizer for filebeat cleanup
	WazuhFilebeat = Domain + "/wazuhfilebeat"

	// WazuhBackup finalizer for backup cleanup
	WazuhBackup = Domain + "/wazuhbackup"

	// WazuhRestore finalizer for restore cleanup
	WazuhRestore = Domain + "/wazuhrestore"
)

// OpenSearch Security CRDs
const (
	// OpenSearchUser finalizer - removes user from OpenSearch
	OpenSearchUser = Domain + "/opensearchuser"

	// OpenSearchRole finalizer - removes role from OpenSearch
	OpenSearchRole = Domain + "/opensearchrole"

	// OpenSearchRoleMapping finalizer - removes role mapping from OpenSearch
	OpenSearchRoleMapping = Domain + "/opensearchrolemapping"

	// OpenSearchActionGroup finalizer - removes action group from OpenSearch
	OpenSearchActionGroup = Domain + "/opensearchactiongroup"

	// OpenSearchTenant finalizer - removes tenant from OpenSearch
	OpenSearchTenant = Domain + "/opensearchtenant"
)

// OpenSearch Index Management CRDs
const (
	// OpenSearchIndex finalizer - optionally removes index from OpenSearch
	OpenSearchIndex = Domain + "/opensearchindex"

	// OpenSearchIndexTemplate finalizer - removes index template from OpenSearch
	OpenSearchIndexTemplate = Domain + "/opensearchindextemplate"

	// OpenSearchComponentTemplate finalizer - removes component template from OpenSearch
	OpenSearchComponentTemplate = Domain + "/opensearchcomponenttemplate"

	// OpenSearchISMPolicy finalizer - removes ISM policy from OpenSearch
	OpenSearchISMPolicy = Domain + "/opensearchismpolicy"
)

// OpenSearch Infrastructure CRDs
const (
	// OpenSearchIndexer finalizer for indexer cleanup
	OpenSearchIndexer = Domain + "/opensearchindexer"

	// OpenSearchDashboard finalizer for dashboard cleanup
	OpenSearchDashboard = Domain + "/opensearchdashboard"
)

// OpenSearch Backup/Restore CRDs
const (
	// OpenSearchSnapshotPolicy finalizer - removes snapshot policy from OpenSearch
	OpenSearchSnapshotPolicy = Domain + "/opensearchsnapshotpolicy"

	// OpenSearchSnapshotRepository finalizer - removes repository from OpenSearch
	OpenSearchSnapshotRepository = Domain + "/opensearchsnapshotrepository"

	// OpenSearchSnapshot finalizer for manual snapshot cleanup
	OpenSearchSnapshot = Domain + "/opensearchsnapshot"

	// OpenSearchRestore finalizer for restore cleanup
	OpenSearchRestore = Domain + "/opensearchrestore"
)

// FinalizerInfo provides metadata about a finalizer
type FinalizerInfo struct {
	// Name is the finalizer string
	Name string

	// RequiresExternalCleanup indicates if cleanup involves external API calls
	RequiresExternalCleanup bool

	// Description explains what the finalizer protects
	Description string
}

// Registry maps CRD kinds to their finalizer info
var Registry = map[string]FinalizerInfo{
	// Wazuh Core
	"WazuhCluster": {
		Name:                    WazuhCluster,
		RequiresExternalCleanup: false,
		Description:             "Ensures all cluster resources are cleaned up",
	},
	"WazuhManager": {
		Name:                    WazuhManager,
		RequiresExternalCleanup: false,
		Description:             "Cleans up manager StatefulSet and services",
	},
	"WazuhWorker": {
		Name:                    WazuhWorker,
		RequiresExternalCleanup: false,
		Description:             "Cleans up worker StatefulSet and services",
	},
	"WazuhRule": {
		Name:                    WazuhRule,
		RequiresExternalCleanup: true,
		Description:             "Removes rule file from manager filesystem",
	},
	"WazuhDecoder": {
		Name:                    WazuhDecoder,
		RequiresExternalCleanup: true,
		Description:             "Removes decoder file from manager filesystem",
	},

	// OpenSearch Security
	"OpenSearchUser": {
		Name:                    OpenSearchUser,
		RequiresExternalCleanup: true,
		Description:             "Removes user from OpenSearch security plugin",
	},
	"OpenSearchRole": {
		Name:                    OpenSearchRole,
		RequiresExternalCleanup: true,
		Description:             "Removes role from OpenSearch security plugin",
	},
	"OpenSearchRoleMapping": {
		Name:                    OpenSearchRoleMapping,
		RequiresExternalCleanup: true,
		Description:             "Removes role mapping from OpenSearch security plugin",
	},
	"OpenSearchActionGroup": {
		Name:                    OpenSearchActionGroup,
		RequiresExternalCleanup: true,
		Description:             "Removes action group from OpenSearch security plugin",
	},
	"OpenSearchTenant": {
		Name:                    OpenSearchTenant,
		RequiresExternalCleanup: true,
		Description:             "Removes tenant from OpenSearch security plugin",
	},

	// OpenSearch Index Management
	"OpenSearchIndex": {
		Name:                    OpenSearchIndex,
		RequiresExternalCleanup: true,
		Description:             "Optionally removes index from OpenSearch (configurable)",
	},
	"OpenSearchIndexTemplate": {
		Name:                    OpenSearchIndexTemplate,
		RequiresExternalCleanup: true,
		Description:             "Removes index template from OpenSearch",
	},
	"OpenSearchComponentTemplate": {
		Name:                    OpenSearchComponentTemplate,
		RequiresExternalCleanup: true,
		Description:             "Removes component template from OpenSearch",
	},
	"OpenSearchISMPolicy": {
		Name:                    OpenSearchISMPolicy,
		RequiresExternalCleanup: true,
		Description:             "Removes ISM policy from OpenSearch",
	},

	// OpenSearch Backup
	"OpenSearchSnapshotPolicy": {
		Name:                    OpenSearchSnapshotPolicy,
		RequiresExternalCleanup: true,
		Description:             "Removes snapshot policy from OpenSearch",
	},
	"OpenSearchSnapshotRepository": {
		Name:                    OpenSearchSnapshotRepository,
		RequiresExternalCleanup: true,
		Description:             "Removes snapshot repository from OpenSearch",
	},
}

// GetFinalizer returns the finalizer name for a given CRD kind
func GetFinalizer(kind string) string {
	if info, ok := Registry[kind]; ok {
		return info.Name
	}
	// Fallback to generic pattern
	return Domain + "/" + kind
}

// RequiresExternalCleanup returns true if the CRD requires external API cleanup
func RequiresExternalCleanup(kind string) bool {
	if info, ok := Registry[kind]; ok {
		return info.RequiresExternalCleanup
	}
	return false
}
