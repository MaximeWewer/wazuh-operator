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

// ISM Policy defaults for Wazuh alerts lifecycle management
const (
	// ISMPolicyName is the default ISM policy name for Wazuh alerts
	ISMPolicyName = "wazuh-alerts-policy"

	// ISMPolicyDescription is the default description for the ISM policy
	ISMPolicyDescription = "Wazuh alerts index lifecycle policy"

	// ISMDefaultState is the default initial state for new indices
	ISMDefaultState = "hot"

	// ISMHotStateMinIndexAge is the minimum index age to trigger rollover in hot state
	ISMHotStateMinIndexAge = "1d"

	// ISMHotStateMinDocCount is the minimum document count to trigger rollover in hot state
	ISMHotStateMinDocCount int64 = 100000000

	// ISMWarmStateMinIndexAge is the minimum index age to transition from hot to warm
	ISMWarmStateMinIndexAge = "7d"

	// ISMWarmStateReplicas is the number of replicas in warm state (0 to save space)
	ISMWarmStateReplicas = 0

	// ISMDeleteStateMinIndexAge is the minimum index age to delete the index
	ISMDeleteStateMinIndexAge = "30d"

	// ISMTemplateIndexPattern is the default index pattern for ISM template
	ISMTemplateIndexPattern = "wazuh-alerts-*"

	// ISMTemplatePriority is the default priority for ISM template
	ISMTemplatePriority = 100
)

// ISM State names
const (
	// ISMStateHot is the hot state name
	ISMStateHot = "hot"

	// ISMStateWarm is the warm state name
	ISMStateWarm = "warm"

	// ISMStateDelete is the delete state name
	ISMStateDelete = "delete"
)
