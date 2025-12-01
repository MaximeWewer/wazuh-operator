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
