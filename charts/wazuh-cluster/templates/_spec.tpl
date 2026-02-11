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
  {{- $tls := deepCopy .Values.cluster.spec.tls -}}
  {{- /* Remove customCerts when not configured (empty secret names) */ -}}
  {{- if $tls.customCerts -}}
    {{- if not (and $tls.customCerts.caSecretRef $tls.customCerts.caSecretRef.name) -}}
      {{- $_ := unset $tls "customCerts" -}}
    {{- end -}}
  {{- end -}}
  {{- /* Remove the non-CRD 'enabled' field from customCerts if it still exists */ -}}
  {{- if $tls.customCerts -}}
    {{- $_ := unset $tls.customCerts "enabled" -}}
  {{- end -}}
  {{- $_ := set $spec "tls" $tls -}}
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

{{- /* Apply indexer ingress if configured */ -}}
{{- if (default dict .Values.cluster.spec.indexer).ingress -}}
  {{- $_ := set $indexer "ingress" .Values.cluster.spec.indexer.ingress -}}
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

{{- /* Apply workers ingress if configured */ -}}
{{- if (default dict (default dict .Values.cluster.spec.manager).workers).ingress -}}
  {{- $_ := set $workers "ingress" .Values.cluster.spec.manager.workers.ingress -}}
  {{- $_ := set $manager "workers" $workers -}}
{{- end -}}

{{- /* Apply master gatewayAPI if configured */ -}}
{{- $master := default dict $manager.master -}}
{{- if (default dict (default dict .Values.cluster.spec.manager).master).gatewayAPI -}}
  {{- $_ := set $master "gatewayAPI" .Values.cluster.spec.manager.master.gatewayAPI -}}
  {{- $_ := set $manager "master" $master -}}
{{- end -}}

{{- /* Apply master ingress if configured */ -}}
{{- if (default dict (default dict .Values.cluster.spec.manager).master).ingress -}}
  {{- $_ := set $master "ingress" .Values.cluster.spec.manager.master.ingress -}}
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

{{- /* Apply dashboard ingress if configured */ -}}
{{- if (default dict .Values.cluster.spec.dashboard).ingress -}}
  {{- $_ := set $dashboard "ingress" .Values.cluster.spec.dashboard.ingress -}}
{{- end -}}

{{- $_ := set $spec "dashboard" $dashboard -}}

{{- /* Apply drain config if set in values */ -}}
{{- if .Values.cluster.spec.drain -}}
  {{- $_ := set $spec "drain" .Values.cluster.spec.drain -}}
{{- end -}}

{{- /* ============================================ */ -}}
{{- /* Clean up empty enum/optional fields          */ -}}
{{- /* Strip empty strings that would fail CRD      */ -}}
{{- /* validation on enum or required fields         */ -}}
{{- /* ============================================ */ -}}

{{- /* --- Indexer cleanup --- */ -}}
{{- $idx := $spec.indexer -}}
{{- if $idx -}}
  {{- if $idx.image -}}
    {{- if not $idx.image.pullPolicy }}{{ $_ := unset $idx.image "pullPolicy" }}{{ end -}}
    {{- if not $idx.image.repository }}{{ $_ := unset $idx.image "repository" }}{{ end -}}
    {{- if not $idx.image.tag }}{{ $_ := unset $idx.image "tag" }}{{ end -}}
  {{- end -}}
  {{- if and $idx.service (not $idx.service.type) }}{{ $_ := unset $idx.service "type" }}{{ end -}}
  {{- if not $idx.updateStrategy }}{{ $_ := unset $idx "updateStrategy" }}{{ end -}}
  {{- if not $idx.clusterName }}{{ $_ := unset $idx "clusterName" }}{{ end -}}
  {{- if and $idx.serviceAccount (not $idx.serviceAccount.create) }}{{ $_ := unset $idx "serviceAccount" }}{{ end -}}
{{- end -}}

{{- /* --- Dashboard cleanup --- */ -}}
{{- $dash := $spec.dashboard -}}
{{- if $dash -}}
  {{- if $dash.image -}}
    {{- if not $dash.image.pullPolicy }}{{ $_ := unset $dash.image "pullPolicy" }}{{ end -}}
    {{- if not $dash.image.repository }}{{ $_ := unset $dash.image "repository" }}{{ end -}}
    {{- if not $dash.image.tag }}{{ $_ := unset $dash.image "tag" }}{{ end -}}
  {{- end -}}
  {{- if and $dash.service (not $dash.service.type) }}{{ $_ := unset $dash.service "type" }}{{ end -}}
  {{- if and $dash.serviceAccount (not $dash.serviceAccount.create) }}{{ $_ := unset $dash "serviceAccount" }}{{ end -}}
{{- end -}}

{{- /* --- Manager cleanup --- */ -}}
{{- $mgr := $spec.manager -}}
{{- if $mgr -}}
  {{- if $mgr.image -}}
    {{- if not $mgr.image.pullPolicy }}{{ $_ := unset $mgr.image "pullPolicy" }}{{ end -}}
    {{- if not $mgr.image.repository }}{{ $_ := unset $mgr.image "repository" }}{{ end -}}
    {{- if not $mgr.image.tag }}{{ $_ := unset $mgr.image "tag" }}{{ end -}}
  {{- end -}}
  {{- /* Manager config string cleanup */ -}}
  {{- if $mgr.config -}}
    {{- if not $mgr.config.masterConfig }}{{ $_ := unset $mgr.config "masterConfig" }}{{ end -}}
    {{- if not $mgr.config.workerConfig }}{{ $_ := unset $mgr.config "workerConfig" }}{{ end -}}
    {{- if not $mgr.config.localInternalOptions }}{{ $_ := unset $mgr.config "localInternalOptions" }}{{ end -}}
  {{- end -}}
  {{- /* Master cleanup */ -}}
  {{- if $mgr.master -}}
    {{- if and $mgr.master.service (not $mgr.master.service.type) }}{{ $_ := unset $mgr.master.service "type" }}{{ end -}}
    {{- if not $mgr.master.extraConfig }}{{ $_ := unset $mgr.master "extraConfig" }}{{ end -}}
    {{- if and $mgr.master.serviceAccount (not $mgr.master.serviceAccount.create) }}{{ $_ := unset $mgr.master "serviceAccount" }}{{ end -}}
  {{- end -}}
  {{- /* Workers cleanup */ -}}
  {{- if $mgr.workers -}}
    {{- if and $mgr.workers.service (not $mgr.workers.service.type) }}{{ $_ := unset $mgr.workers.service "type" }}{{ end -}}
    {{- if not $mgr.workers.extraConfig }}{{ $_ := unset $mgr.workers "extraConfig" }}{{ end -}}
    {{- if and $mgr.workers.serviceAccount (not $mgr.workers.serviceAccount.create) }}{{ $_ := unset $mgr.workers "serviceAccount" }}{{ end -}}
  {{- end -}}
{{- end -}}

{{- toYaml $spec -}}
{{- end -}}
