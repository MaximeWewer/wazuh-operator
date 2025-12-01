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

// Wazuh Manager ports
const (
	// PortManagerAPI is the Wazuh Manager REST API port
	PortManagerAPI int32 = 55000

	// PortManagerAgentEvents is the port for agent events (syslog)
	PortManagerAgentEvents int32 = 1514

	// PortManagerAgentAuth is the port for agent authentication/registration
	PortManagerAgentAuth int32 = 1515

	// PortManagerCluster is the port for cluster communication between nodes
	PortManagerCluster int32 = 1516

	// PortManagerRegistration is the port for agent registration
	PortManagerRegistration int32 = 1515

	// PortManagerAgents is the port for agent connections
	PortManagerAgents int32 = 1514
)

// Wazuh Manager port names
const (
	// PortNameManagerAPI is the name for the API port
	PortNameManagerAPI = "api"

	// PortNameManagerAgentEvents is the name for the agent events port
	PortNameManagerAgentEvents = "agent-events"

	// PortNameManagerAgentAuth is the name for the agent auth port
	PortNameManagerAgentAuth = "agent-auth"

	// PortNameManagerCluster is the name for the cluster port
	PortNameManagerCluster = "cluster"
)

// OpenSearch Indexer ports
const (
	// PortIndexerREST is the OpenSearch REST API port
	PortIndexerREST int32 = 9200

	// PortIndexerHTTP is an alias for PortIndexerREST
	PortIndexerHTTP int32 = 9200

	// PortIndexerTransport is the OpenSearch transport port for node communication
	PortIndexerTransport int32 = 9300

	// PortIndexerMetrics is the OpenSearch metrics port
	PortIndexerMetrics int32 = 9600
)

// OpenSearch Indexer port names
const (
	// PortNameIndexerREST is the name for the REST API port
	PortNameIndexerREST = "rest"

	// PortNameIndexerTransport is the name for the transport port
	PortNameIndexerTransport = "transport"

	// PortNameIndexerMetrics is the name for the metrics port
	PortNameIndexerMetrics = "metrics"
)

// OpenSearch Dashboard ports
const (
	// PortDashboardHTTP is the Dashboard HTTP/HTTPS port
	PortDashboardHTTP int32 = 5601
)

// OpenSearch Dashboard port names
const (
	// PortNameDashboardHTTP is the name for the Dashboard HTTP port
	PortNameDashboardHTTP = "http"
)

// Filebeat ports
const (
	// PortFilebeatHTTP is the Filebeat HTTP port (for healthcheck)
	PortFilebeatHTTP int32 = 5066
)

// Operator ports
const (
	// PortOperatorMetrics is the operator metrics port
	PortOperatorMetrics int32 = 8080

	// PortOperatorHealth is the operator health probe port
	PortOperatorHealth int32 = 8081

	// PortOperatorWebhook is the operator webhook port
	PortOperatorWebhook int32 = 9443
)
