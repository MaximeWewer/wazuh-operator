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

package monitoring

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	osservices "github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/services"
	wazuhservices "github.com/MaximeWewer/wazuh-operator/internal/wazuh/builder/services"
)

// TestServiceMonitorsSkipHeadlessServices asserts each ServiceMonitor selects the regular
// Service and not the headless one: both select the same pods, so selecting both scrapes
// every manager master and indexer twice.
func TestServiceMonitorsSkipHeadlessServices(t *testing.T) {
	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: "ns"},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.14.8",
			Monitoring: &wazuhv1.MonitoringConfig{
				Enabled:         true,
				WazuhExporter:   &wazuhv1.WazuhExporterConfig{Enabled: true},
				IndexerExporter: &wazuhv1.IndexerExporterConfig{Enabled: true},
				ServiceMonitor:  &wazuhv1.ServiceMonitorConfig{Enabled: true},
			},
		},
	}
	managers := wazuhservices.NewManagerServiceBuilder("c", "ns", "master")
	indexers := osservices.NewIndexerServiceBuilder("c", "ns")
	nodePool := osservices.NewNodePoolServiceBuilder("c", "ns", "hot").Build()

	for name, tc := range map[string]struct {
		selector metav1.LabelSelector
		regular  *corev1.Service
		headless []*corev1.Service
	}{
		"manager": {NewManagerServiceMonitor(cluster).Spec.Selector, managers.Build(), []*corev1.Service{managers.BuildHeadless()}},
		"indexer": {NewIndexerServiceMonitor(cluster).Spec.Selector, indexers.Build(), []*corev1.Service{indexers.BuildHeadless(), nodePool}},
	} {
		sel, err := metav1.LabelSelectorAsSelector(&tc.selector)
		if err != nil {
			t.Fatal(err)
		}
		if !sel.Matches(labels.Set(tc.regular.Labels)) {
			t.Errorf("%s: ServiceMonitor does not select the regular Service %s", name, tc.regular.Name)
		}
		for _, h := range tc.headless {
			if sel.Matches(labels.Set(h.Labels)) {
				t.Errorf("%s: ServiceMonitor selects the headless Service %s", name, h.Name)
			}
		}
	}
}
