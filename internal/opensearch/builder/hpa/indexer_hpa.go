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

package hpa

import (
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// IndexerHPABuilder builds HPA for OpenSearch Indexer
// Note: HPA for StatefulSet requires careful consideration as OpenSearch
// needs shard rebalancing after scaling
type IndexerHPABuilder struct {
	clusterName string
	namespace   string
	spec        *wazuhv1.HPASpec
	labels      map[string]string
	annotations map[string]string
}

// NewIndexerHPABuilder creates a new IndexerHPABuilder
func NewIndexerHPABuilder(clusterName, namespace string) *IndexerHPABuilder {
	return &IndexerHPABuilder{
		clusterName: clusterName,
		namespace:   namespace,
		labels:      make(map[string]string),
		annotations: make(map[string]string),
	}
}

// WithSpec sets the HPA spec from the CRD
func (b *IndexerHPABuilder) WithSpec(spec *wazuhv1.HPASpec) *IndexerHPABuilder {
	b.spec = spec
	return b
}

// WithLabels sets additional labels
func (b *IndexerHPABuilder) WithLabels(labels map[string]string) *IndexerHPABuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations sets additional annotations
func (b *IndexerHPABuilder) WithAnnotations(annotations map[string]string) *IndexerHPABuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// Build creates the HPA resource for Indexer StatefulSet
func (b *IndexerHPABuilder) Build() *autoscalingv2.HorizontalPodAutoscaler {
	if b.spec == nil || !b.spec.Enabled {
		return nil
	}

	name := b.clusterName + "-indexer"

	// Default values
	minReplicas := int32(1)
	if b.spec.MinReplicas != nil {
		minReplicas = *b.spec.MinReplicas
	}

	maxReplicas := int32(10)
	if b.spec.MaxReplicas > 0 {
		maxReplicas = b.spec.MaxReplicas
	}

	// Build labels
	labels := map[string]string{
		constants.LabelManagedBy: constants.OperatorName,
		constants.LabelComponent: "indexer",
		constants.LabelInstance:  b.clusterName,
	}
	for k, v := range b.labels {
		labels[k] = v
	}

	// Build annotations with StatefulSet warning
	annotations := map[string]string{
		"wazuh.com/hpa-note": "HPA for StatefulSet; OpenSearch may require manual shard rebalancing after scale-up",
	}
	for k, v := range b.annotations {
		annotations[k] = v
	}

	// Build metrics
	var metrics []autoscalingv2.MetricSpec

	// CPU metric
	if b.spec.TargetCPUUtilizationPercentage != nil && *b.spec.TargetCPUUtilizationPercentage > 0 {
		metrics = append(metrics, autoscalingv2.MetricSpec{
			Type: autoscalingv2.ResourceMetricSourceType,
			Resource: &autoscalingv2.ResourceMetricSource{
				Name: "cpu",
				Target: autoscalingv2.MetricTarget{
					Type:               autoscalingv2.UtilizationMetricType,
					AverageUtilization: b.spec.TargetCPUUtilizationPercentage,
				},
			},
		})
	}

	// Memory metric
	if b.spec.TargetMemoryUtilizationPercentage != nil && *b.spec.TargetMemoryUtilizationPercentage > 0 {
		metrics = append(metrics, autoscalingv2.MetricSpec{
			Type: autoscalingv2.ResourceMetricSourceType,
			Resource: &autoscalingv2.ResourceMetricSource{
				Name: "memory",
				Target: autoscalingv2.MetricTarget{
					Type:               autoscalingv2.UtilizationMetricType,
					AverageUtilization: b.spec.TargetMemoryUtilizationPercentage,
				},
			},
		})
	}

	// Default to CPU 80% if no metrics specified
	if len(metrics) == 0 {
		defaultCPU := int32(80)
		metrics = append(metrics, autoscalingv2.MetricSpec{
			Type: autoscalingv2.ResourceMetricSourceType,
			Resource: &autoscalingv2.ResourceMetricSource{
				Name: "cpu",
				Target: autoscalingv2.MetricTarget{
					Type:               autoscalingv2.UtilizationMetricType,
					AverageUtilization: &defaultCPU,
				},
			},
		})
	}

	hpa := &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   b.namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{
				APIVersion: "apps/v1",
				Kind:       "StatefulSet",
				Name:       name,
			},
			MinReplicas: &minReplicas,
			MaxReplicas: maxReplicas,
			Metrics:     metrics,
		},
	}

	// Add behavior if specified - use conservative defaults for StatefulSet
	if b.spec.Behavior != nil {
		hpa.Spec.Behavior = b.buildBehavior()
	} else {
		// Default conservative behavior for StatefulSet (slow scale down)
		hpa.Spec.Behavior = b.defaultStatefulSetBehavior()
	}

	return hpa
}

// buildBehavior builds the HPA behavior configuration from spec
func (b *IndexerHPABuilder) buildBehavior() *autoscalingv2.HorizontalPodAutoscalerBehavior {
	if b.spec.Behavior == nil {
		return nil
	}

	behavior := &autoscalingv2.HorizontalPodAutoscalerBehavior{}

	if b.spec.Behavior.ScaleDown != nil {
		behavior.ScaleDown = b.buildScalingRules(b.spec.Behavior.ScaleDown)
	}

	if b.spec.Behavior.ScaleUp != nil {
		behavior.ScaleUp = b.buildScalingRules(b.spec.Behavior.ScaleUp)
	}

	return behavior
}

// buildScalingRules builds scaling rules from spec
func (b *IndexerHPABuilder) buildScalingRules(rules *wazuhv1.HPAScalingRules) *autoscalingv2.HPAScalingRules {
	if rules == nil {
		return nil
	}

	scalingRules := &autoscalingv2.HPAScalingRules{}

	if rules.StabilizationWindowSeconds != nil {
		scalingRules.StabilizationWindowSeconds = rules.StabilizationWindowSeconds
	}

	if rules.SelectPolicy != nil {
		policy := autoscalingv2.ScalingPolicySelect(*rules.SelectPolicy)
		scalingRules.SelectPolicy = &policy
	}

	return scalingRules
}

// defaultStatefulSetBehavior returns conservative scaling behavior for StatefulSet
// OpenSearch needs time to redistribute shards after scaling
func (b *IndexerHPABuilder) defaultStatefulSetBehavior() *autoscalingv2.HorizontalPodAutoscalerBehavior {
	// 5 minute stabilization window for scale down (allow shard redistribution)
	scaleDownWindow := int32(300)
	// 2 minute stabilization window for scale up
	scaleUpWindow := int32(120)

	minPolicy := autoscalingv2.MinChangePolicySelect

	return &autoscalingv2.HorizontalPodAutoscalerBehavior{
		ScaleDown: &autoscalingv2.HPAScalingRules{
			StabilizationWindowSeconds: &scaleDownWindow,
			SelectPolicy:               &minPolicy,
			Policies: []autoscalingv2.HPAScalingPolicy{
				{
					Type:          autoscalingv2.PodsScalingPolicy,
					Value:         1, // Scale down 1 pod at a time
					PeriodSeconds: 300,
				},
			},
		},
		ScaleUp: &autoscalingv2.HPAScalingRules{
			StabilizationWindowSeconds: &scaleUpWindow,
			Policies: []autoscalingv2.HPAScalingPolicy{
				{
					Type:          autoscalingv2.PodsScalingPolicy,
					Value:         2, // Scale up 2 pods at a time
					PeriodSeconds: 60,
				},
			},
		},
	}
}

// GetName returns the HPA name
func (b *IndexerHPABuilder) GetName() string {
	return b.clusterName + "-indexer"
}
