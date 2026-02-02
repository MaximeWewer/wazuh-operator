{{/*
Build the complete WazuhCluster spec
Combines sizing profiles with credentials and other configurations
*/}}
{{- define "wazuh-cluster.spec" -}}
{{- $spec := deepCopy .Values.cluster.spec -}}
{{- $clusterName := .Values.cluster.name -}}

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

{{- /* ============================================ */ -}}
{{- /* Credentials Configuration */ -}}
{{- /* ============================================ */ -}}

{{- /* Apply indexer credentials - either from External Secrets or inline secrets */ -}}
{{- $indexer := default dict $spec.indexer -}}
{{- if and .Values.externalSecrets .Values.externalSecrets.enabled .Values.externalSecrets.indexerAdmin -}}
  {{- /* Use External Secrets Operator */ -}}
  {{- $eso := .Values.externalSecrets.indexerAdmin -}}
  {{- $externalSecretRef := dict "name" $eso.name -}}
  {{- if $eso.secretStoreRef -}}
    {{- $_ := set $externalSecretRef "secretStoreRef" $eso.secretStoreRef -}}
  {{- end -}}
  {{- if $eso.remoteRef -}}
    {{- $_ := set $externalSecretRef "remoteRef" $eso.remoteRef -}}
  {{- end -}}
  {{- if $eso.refreshInterval -}}
    {{- $_ := set $externalSecretRef "refreshInterval" $eso.refreshInterval -}}
  {{- end -}}
  {{- $credentials := dict "externalSecretRef" $externalSecretRef -}}
  {{- $credentials = merge $credentials (dict "usernameKey" (default "username" $eso.usernameKey) "passwordKey" (default "password" $eso.passwordKey)) -}}
  {{- $_ := set $indexer "credentials" $credentials -}}
{{- else if and .Values.secrets.indexerAdmin .Values.secrets.indexerAdmin.password -}}
  {{- /* Use inline secrets */ -}}
  {{- $secretName := printf "%s-indexer-credentials" $clusterName -}}
  {{- $credentials := dict "secretName" $secretName "usernameKey" "admin-username" "passwordKey" "admin-password" -}}
  {{- $_ := set $indexer "credentials" $credentials -}}
{{- end -}}

{{- /* Apply indexer antiAffinity if configured */ -}}
{{- if (default dict .Values.cluster.spec.indexer).antiAffinity -}}
  {{- $_ := set $indexer "antiAffinity" .Values.cluster.spec.indexer.antiAffinity -}}
{{- end -}}

{{- /* Apply indexer HPA if configured */ -}}
{{- if (default dict .Values.cluster.spec.indexer).hpa -}}
  {{- $_ := set $indexer "hpa" .Values.cluster.spec.indexer.hpa -}}
{{- end -}}

{{- /* Apply indexer gatewayAPI if configured */ -}}
{{- if (default dict .Values.cluster.spec.indexer).gatewayAPI -}}
  {{- $_ := set $indexer "gatewayAPI" .Values.cluster.spec.indexer.gatewayAPI -}}
{{- end -}}

{{- $_ := set $spec "indexer" $indexer -}}

{{- /* Apply manager API credentials - either from External Secrets or inline secrets */ -}}
{{- $manager := default dict $spec.manager -}}
{{- if and .Values.externalSecrets .Values.externalSecrets.enabled .Values.externalSecrets.wazuhApi -}}
  {{- /* Use External Secrets Operator */ -}}
  {{- $eso := .Values.externalSecrets.wazuhApi -}}
  {{- $externalSecretRef := dict "name" $eso.name -}}
  {{- if $eso.secretStoreRef -}}
    {{- $_ := set $externalSecretRef "secretStoreRef" $eso.secretStoreRef -}}
  {{- end -}}
  {{- if $eso.remoteRef -}}
    {{- $_ := set $externalSecretRef "remoteRef" $eso.remoteRef -}}
  {{- end -}}
  {{- if $eso.refreshInterval -}}
    {{- $_ := set $externalSecretRef "refreshInterval" $eso.refreshInterval -}}
  {{- end -}}
  {{- $apiCredentials := dict "externalSecretRef" $externalSecretRef -}}
  {{- $apiCredentials = merge $apiCredentials (dict "usernameKey" (default "username" $eso.usernameKey) "passwordKey" (default "password" $eso.passwordKey)) -}}
  {{- $_ := set $manager "apiCredentials" $apiCredentials -}}
{{- else if and .Values.secrets.wazuhApi .Values.secrets.wazuhApi.password -}}
  {{- /* Use inline secrets */ -}}
  {{- $secretName := printf "%s-api-credentials" $clusterName -}}
  {{- $apiCredentials := dict "secretName" $secretName "usernameKey" "api-username" "passwordKey" "api-password" -}}
  {{- $_ := set $manager "apiCredentials" $apiCredentials -}}
{{- end -}}

{{- /* Apply logRotation config if set in values (independent of sizing profile) */ -}}
{{- if (default dict .Values.cluster.spec.manager).logRotation -}}
  {{- $_ := set $manager "logRotation" .Values.cluster.spec.manager.logRotation -}}
{{- end -}}

{{- /* Apply workers HPA if configured */ -}}
{{- $workers := default dict $manager.workers -}}
{{- if (default dict (default dict .Values.cluster.spec.manager).workers).hpa -}}
  {{- $_ := set $workers "hpa" .Values.cluster.spec.manager.workers.hpa -}}
  {{- $_ := set $manager "workers" $workers -}}
{{- end -}}

{{- /* Apply workers gatewayAPI if configured */ -}}
{{- if (default dict (default dict .Values.cluster.spec.manager).workers).gatewayAPI -}}
  {{- $_ := set $workers "gatewayAPI" .Values.cluster.spec.manager.workers.gatewayAPI -}}
  {{- $_ := set $manager "workers" $workers -}}
{{- end -}}

{{- /* Apply master gatewayAPI if configured */ -}}
{{- $master := default dict $manager.master -}}
{{- if (default dict (default dict .Values.cluster.spec.manager).master).gatewayAPI -}}
  {{- $_ := set $master "gatewayAPI" .Values.cluster.spec.manager.master.gatewayAPI -}}
  {{- $_ := set $manager "master" $master -}}
{{- end -}}

{{- $_ := set $spec "manager" $manager -}}

{{- /* ============================================ */ -}}
{{- /* Dashboard Configuration */ -}}
{{- /* ============================================ */ -}}

{{- $dashboard := default dict $spec.dashboard -}}

{{- /* Apply dashboard HPA if configured */ -}}
{{- if (default dict .Values.cluster.spec.dashboard).hpa -}}
  {{- $_ := set $dashboard "hpa" .Values.cluster.spec.dashboard.hpa -}}
{{- end -}}

{{- /* Apply dashboard gatewayAPI if configured */ -}}
{{- if (default dict .Values.cluster.spec.dashboard).gatewayAPI -}}
  {{- $_ := set $dashboard "gatewayAPI" .Values.cluster.spec.dashboard.gatewayAPI -}}
{{- end -}}

{{- $_ := set $spec "dashboard" $dashboard -}}

{{- /* Apply drain config if set in values */ -}}
{{- if .Values.cluster.spec.drain -}}
  {{- $_ := set $spec "drain" .Values.cluster.spec.drain -}}
{{- end -}}

{{- toYaml $spec -}}
{{- end -}}
