{{/*
Expand the name of the chart.
*/}}
{{- define "wazuh-cluster.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "wazuh-cluster.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "wazuh-cluster.labels" -}}
helm.sh/chart: {{ include "wazuh-cluster.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Merge spec with a default clusterRefs list pointing to the cluster.
User-provided clusterRefs in .spec takes precedence.
Used for multi-cluster CRDs (Rule, Decoder, AgentGroup, Filebeat, all
OpenSearch resources).
Usage: include "wazuh-cluster.specWithClusterRef" (dict "spec" .spec "clusterName" $.Values.cluster.name "clusterNamespace" $.Values.namespace)
*/}}
{{- define "wazuh-cluster.specWithClusterRef" -}}
{{- $defaults := dict "clusterRefs" (list (dict "name" .clusterName "namespace" .clusterNamespace)) -}}
{{- $spec := mustMergeOverwrite $defaults (default dict .spec) -}}
{{- toYaml $spec -}}
{{- end -}}

{{/*
Merge spec with a default singular clusterRef (name + namespace, both mandatory).
Used for one-shot CRDs (WazuhBackup, WazuhRestore, WazuhCertificate).
Usage: include "wazuh-cluster.specWithSingleClusterRef" (dict "spec" .spec "clusterName" $.Values.cluster.name "clusterNamespace" $.Values.namespace)
*/}}
{{- define "wazuh-cluster.specWithSingleClusterRef" -}}
{{- $defaults := dict "clusterRef" (dict "name" .clusterName "namespace" .clusterNamespace) -}}
{{- $spec := mustMergeOverwrite $defaults (default dict .spec) -}}
{{- toYaml $spec -}}
{{- end -}}
