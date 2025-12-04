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

// Package monitoring provides monitoring resources for Wazuh components
package monitoring

import (
	"fmt"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// NewManagerServiceMonitor creates a ServiceMonitor for Wazuh Manager metrics
// Returns nil if monitoring is not enabled
func NewManagerServiceMonitor(cluster *wazuhv1alpha1.WazuhCluster) *monitoringv1.ServiceMonitor {
	// Check if monitoring is enabled
	if !isWazuhExporterEnabled(cluster) {
		return nil
	}

	// Check if ServiceMonitor is enabled
	if cluster.Spec.Monitoring.ServiceMonitor == nil || !cluster.Spec.Monitoring.ServiceMonitor.Enabled {
		return nil
	}

	labels := constants.CommonLabels(cluster.Name, "manager-metrics", cluster.Spec.Version)

	// Add custom labels from config
	if cluster.Spec.Monitoring.ServiceMonitor.Labels != nil {
		for k, v := range cluster.Spec.Monitoring.ServiceMonitor.Labels {
			labels[k] = v
		}
	}

	// Get configuration values
	interval := constants.ServiceMonitorIntervalDefault
	if cluster.Spec.Monitoring.ServiceMonitor.Interval != "" {
		interval = cluster.Spec.Monitoring.ServiceMonitor.Interval
	}

	scrapeTimeout := constants.ServiceMonitorScrapeTimeoutDefault
	if cluster.Spec.Monitoring.ServiceMonitor.ScrapeTimeout != "" {
		scrapeTimeout = cluster.Spec.Monitoring.ServiceMonitor.ScrapeTimeout
	}

	return &monitoringv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-manager-metrics", cluster.Name),
			Namespace: cluster.Namespace,
			Labels:    labels,
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					constants.LabelWazuhCluster:    cluster.Name,
					constants.LabelManagerNodeType: "master",
				},
			},
			Endpoints: []monitoringv1.Endpoint{
				{
					Port:          "metrics",
					Interval:      monitoringv1.Duration(interval),
					ScrapeTimeout: monitoringv1.Duration(scrapeTimeout),
					Path:          "/metrics",
					Scheme:        schemePtr(monitoringv1.SchemeHTTP),
				},
			},
		},
	}
}

// NewIndexerServiceMonitor creates a ServiceMonitor for OpenSearch Indexer metrics
// Returns nil if monitoring is not enabled
func NewIndexerServiceMonitor(cluster *wazuhv1alpha1.WazuhCluster) *monitoringv1.ServiceMonitor {
	// Check if monitoring is enabled
	if !isIndexerExporterEnabled(cluster) {
		return nil
	}

	// Check if ServiceMonitor is enabled
	if cluster.Spec.Monitoring.ServiceMonitor == nil || !cluster.Spec.Monitoring.ServiceMonitor.Enabled {
		return nil
	}

	labels := constants.CommonLabels(cluster.Name, "indexer-metrics", cluster.Spec.Version)

	// Add custom labels from config
	if cluster.Spec.Monitoring.ServiceMonitor.Labels != nil {
		for k, v := range cluster.Spec.Monitoring.ServiceMonitor.Labels {
			labels[k] = v
		}
	}

	// Get configuration values
	interval := constants.ServiceMonitorIntervalDefault
	if cluster.Spec.Monitoring.ServiceMonitor.Interval != "" {
		interval = cluster.Spec.Monitoring.ServiceMonitor.Interval
	}

	scrapeTimeout := constants.ServiceMonitorScrapeTimeoutDefault
	if cluster.Spec.Monitoring.ServiceMonitor.ScrapeTimeout != "" {
		scrapeTimeout = cluster.Spec.Monitoring.ServiceMonitor.ScrapeTimeout
	}

	// Get the credentials secret name
	credentialsSecretName := constants.IndexerCredentialsName(cluster.Name)

	return &monitoringv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.IndexerMetricsName(cluster.Name),
			Namespace: cluster.Namespace,
			Labels:    labels,
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Selector: metav1.LabelSelector{
				MatchLabels: constants.SelectorLabels(cluster.Name, constants.ComponentIndexer),
			},
			Endpoints: []monitoringv1.Endpoint{
				{
					Port:          constants.PortNameIndexerREST,
					Interval:      monitoringv1.Duration(interval),
					ScrapeTimeout: monitoringv1.Duration(scrapeTimeout),
					Path:          "/_prometheus/metrics",
					Scheme:        schemePtr(monitoringv1.SchemeHTTPS),
					TLSConfig: &monitoringv1.TLSConfig{
						SafeTLSConfig: monitoringv1.SafeTLSConfig{
							InsecureSkipVerify: boolPtr(true), // OpenSearch uses self-signed certs
						},
					},
					BasicAuth: &monitoringv1.BasicAuth{
						Username: corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: credentialsSecretName,
							},
							Key: constants.SecretKeyAdminUsername,
						},
						Password: corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: credentialsSecretName,
							},
							Key: constants.SecretKeyAdminPassword,
						},
					},
				},
			},
		},
	}
}

// isWazuhExporterEnabled checks if Wazuh Prometheus exporter is enabled
func isWazuhExporterEnabled(cluster *wazuhv1alpha1.WazuhCluster) bool {
	if cluster.Spec.Monitoring == nil || !cluster.Spec.Monitoring.Enabled {
		return false
	}
	if cluster.Spec.Monitoring.WazuhExporter == nil || !cluster.Spec.Monitoring.WazuhExporter.Enabled {
		return false
	}
	return true
}

// isIndexerExporterEnabled checks if OpenSearch Indexer Prometheus exporter is enabled
func isIndexerExporterEnabled(cluster *wazuhv1alpha1.WazuhCluster) bool {
	if cluster.Spec.Monitoring == nil || !cluster.Spec.Monitoring.Enabled {
		return false
	}
	if cluster.Spec.Monitoring.IndexerExporter == nil || !cluster.Spec.Monitoring.IndexerExporter.Enabled {
		return false
	}
	return true
}

// boolPtr returns a pointer to a bool
func boolPtr(b bool) *bool {
	return &b
}

// schemePtr returns a pointer to a Scheme
func schemePtr(s monitoringv1.Scheme) *monitoringv1.Scheme {
	return &s
}
