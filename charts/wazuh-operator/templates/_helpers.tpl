{{/*
Expand the name of the chart.
*/}}
{{- define "wazuh-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "wazuh-operator.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "wazuh-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "wazuh-operator.labels" -}}
helm.sh/chart: {{ include "wazuh-operator.chart" . }}
{{ include "wazuh-operator.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "wazuh-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "wazuh-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "wazuh-operator.serviceAccountName" -}}
{{- if .Values.operator.serviceAccount.create }}
{{- default (include "wazuh-operator.fullname" .) .Values.operator.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.operator.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the role to use
*/}}
{{- define "wazuh-operator.roleName" -}}
{{- if .Values.rbac.roleName }}
{{- .Values.rbac.roleName }}
{{- else }}
{{- printf "%s-manager-role" (include "wazuh-operator.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Create the name of the role binding to use
*/}}
{{- define "wazuh-operator.roleBindingName" -}}
{{- printf "%s-manager-rolebinding" (include "wazuh-operator.fullname" .) }}
{{- end }}

{{/*
Operator name
*/}}
{{- define "wazuh-operator.operatorName" -}}
{{- .Values.operator.name }}
{{- end }}

{{/*
Image pull policy
*/}}
{{- define "wazuh-operator.imagePullPolicy" -}}
{{- .Values.operator.image.pullPolicy | default "IfNotPresent" }}
{{- end }}

{{/*
Operator image
*/}}
{{- define "wazuh-operator.image" -}}
{{- $tag := .Values.operator.image.tag | default .Chart.AppVersion }}
{{- printf "%s:%s" .Values.operator.image.repository $tag }}
{{- end }}

{{/*
Namespace name
*/}}
{{- define "wazuh-operator.namespace" -}}
{{- if .Values.namespace.name }}
{{- .Values.namespace.name }}
{{- else }}
{{- .Release.Namespace }}
{{- end }}
{{- end }}

{{/*
Return true if CRDs should be installed
*/}}
{{- define "wazuh-operator.installCRDs" -}}
{{- if or (eq .Values.deploymentMode "crds") (eq .Values.deploymentMode "all") }}
{{- if .Values.crds.install }}
true
{{- end }}
{{- end }}
{{- end }}

{{/*
Return true if Operator should be installed
*/}}
{{- define "wazuh-operator.installOperator" -}}
{{- if or (eq .Values.deploymentMode "operator") (eq .Values.deploymentMode "all") }}
{{- if .Values.operator.enabled }}
true
{{- end }}
{{- end }}
{{- end }}

{{/*
Return true if ServiceMonitor should be created
*/}}
{{- define "wazuh-operator.createServiceMonitor" -}}
{{- if and (include "wazuh-operator.installOperator" .) .Values.operator.serviceMonitor.enabled .Values.operator.metrics.enabled }}
true
{{- end }}
{{- end }}

{{/*
Common annotations
*/}}
{{- define "wazuh-operator.annotations" -}}
{{- with .Values.commonAnnotations }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Validate deployment mode
*/}}
{{- define "wazuh-operator.validateDeploymentMode" -}}
{{- $validModes := list "operator" "crds" "all" }}
{{- if not (has .Values.deploymentMode $validModes) }}
{{- fail (printf "Invalid deploymentMode: %s. Must be one of: operator, crds, all" .Values.deploymentMode) }}
{{- end }}
{{- end }}
