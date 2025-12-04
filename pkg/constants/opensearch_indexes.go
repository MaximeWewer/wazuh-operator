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

package constants

// OpenSearch index names and patterns
const (
	// IndexWazuhAlerts is the base index name for Wazuh alerts
	IndexWazuhAlerts = "wazuh-alerts-4.x-"

	// IndexWazuhArchives is the base index name for Wazuh archives
	IndexWazuhArchives = "wazuh-archives-4.x-"

	// IndexOpenSearchDashboards is the OpenSearch Dashboards system index
	IndexOpenSearchDashboards = ".opensearch_dashboards"

	// IndexOpenSearchDashboardsWildcard is the wildcard pattern for dashboards indices
	IndexOpenSearchDashboardsWildcard = ".opensearch_dashboards-*"

	// IndexOpenDistroSecurity is the OpenDistro security configuration index
	IndexOpenDistroSecurity = ".opendistro_security"
)

// Wazuh index patterns for roles and permissions
const (
	// IndexPatternWazuhAlerts is the wildcard pattern for Wazuh alerts
	IndexPatternWazuhAlerts = "wazuh-alerts-*"

	// IndexPatternWazuhArchives is the wildcard pattern for Wazuh archives
	IndexPatternWazuhArchives = "wazuh-archives-*"

	// IndexPatternWazuhMonitoring is the wildcard pattern for Wazuh monitoring
	IndexPatternWazuhMonitoring = "wazuh-monitoring-*"

	// IndexPatternWazuhStatistics is the wildcard pattern for Wazuh statistics
	IndexPatternWazuhStatistics = "wazuh-statistics-*"
)
