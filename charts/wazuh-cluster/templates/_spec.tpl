{{/*
Build the complete WazuhCluster spec
Combines sizing profiles with credentials and other configurations
*/}}
{{- define "wazuh-cluster.spec" -}}
{{- $spec := deepCopy .Values.cluster.spec -}}

{{- /* Apply sizing profile if configured */ -}}
{{- if .Values.sizing.profile -}}
  {{- $spec = include "wazuh-cluster.applySizing" . | fromYaml -}}
{{- end -}}

{{- /* Apply TLS config if set in values */ -}}
{{- if .Values.cluster.spec.tls -}}
  {{- $_ := set $spec "tls" .Values.cluster.spec.tls -}}
{{- end -}}

{{- /* Apply monitoring config if set in values */ -}}
{{- if .Values.cluster.spec.monitoring -}}
  {{- $_ := set $spec "monitoring" .Values.cluster.spec.monitoring -}}
{{- end -}}

{{- /* Apply indexer credentials reference if secrets.indexerAdmin is configured */ -}}
{{- if and .Values.secrets.indexerAdmin .Values.secrets.indexerAdmin.password -}}
  {{- $indexer := default dict $spec.indexer -}}
  {{- $credentials := dict "secretName" "indexer-admin-credentials" "usernameKey" "admin-username" "passwordKey" "admin-password" -}}
  {{- $_ := set $indexer "credentials" $credentials -}}
  {{- $_ := set $spec "indexer" $indexer -}}
{{- end -}}

{{- /* Apply manager API credentials reference if secrets.wazuhApi is configured */ -}}
{{- if and .Values.secrets.wazuhApi .Values.secrets.wazuhApi.password -}}
  {{- $manager := default dict $spec.manager -}}
  {{- $apiCredentials := dict "secretName" "wazuh-api-credentials" "usernameKey" "username" "passwordKey" "password" -}}
  {{- $_ := set $manager "apiCredentials" $apiCredentials -}}
  {{- $_ := set $spec "manager" $manager -}}
{{- end -}}

{{- /* Apply logRotation config if set in values (independent of sizing profile) */ -}}
{{- if (default dict .Values.cluster.spec.manager).logRotation -}}
  {{- $manager := default dict $spec.manager -}}
  {{- $_ := set $manager "logRotation" .Values.cluster.spec.manager.logRotation -}}
  {{- $_ := set $spec "manager" $manager -}}
{{- end -}}

{{- toYaml $spec -}}
{{- end -}}
