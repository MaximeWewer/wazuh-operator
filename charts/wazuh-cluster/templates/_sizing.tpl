{{/*
Sizing profiles for WazuhCluster
Returns the complete spec with sizing applied
Custom values take precedence over profile defaults
*/}}
{{- define "wazuh-cluster.applySizing" -}}
{{- $spec := .Values.cluster.spec -}}
{{- $profile := .Values.sizing.profile -}}
{{- $storageClass := .Values.sizing.storageClassName -}}

{{- /* Store custom overrides before applying profile */ -}}
{{- $customIndexer := default dict $spec.indexer -}}
{{- $customMaster := default dict (default dict $spec.manager).master -}}
{{- $customWorkers := default dict (default dict $spec.manager).workers -}}
{{- $customDashboard := default dict $spec.dashboard -}}

{{- if $profile -}}
  {{- /* Apply profile defaults first, then merge custom values on top */ -}}
  {{- if eq $profile "XS" -}}
    {{- /* XS: Minimal profile for testing - no workers, single replica each */ -}}
    {{- /* Note: OpenSearch requires minimum 1GB JVM heap to start. Memory limit should be ~2x heap for overhead */ -}}
    {{- $profileIndexer := dict "replicas" 1 "storageSize" "10Gi" "javaOpts" "-Xms1g -Xmx1g -Dlog4j2.formatMsgNoLookups=true" "resources" (dict "requests" (dict "cpu" "200m" "memory" "1536Mi") "limits" (dict "cpu" "1" "memory" "2Gi")) -}}
    {{- $profileMaster := dict "storageSize" "5Gi" "resources" (dict "requests" (dict "cpu" "100m" "memory" "256Mi") "limits" (dict "cpu" "500m" "memory" "512Mi")) -}}
    {{- $profileWorkers := dict "replicas" 0 "storageSize" "5Gi" "resources" (dict "requests" (dict "cpu" "100m" "memory" "256Mi") "limits" (dict "cpu" "500m" "memory" "512Mi")) -}}
    {{- $profileDashboard := dict "replicas" 1 "resources" (dict "requests" (dict "cpu" "100m" "memory" "256Mi") "limits" (dict "cpu" "500m" "memory" "512Mi")) -}}
    {{- $_ := set $spec "indexer" (mergeOverwrite $profileIndexer $customIndexer) -}}
    {{- $_ := set $spec "manager" (dict "master" (mergeOverwrite $profileMaster $customMaster) "workers" (mergeOverwrite $profileWorkers $customWorkers)) -}}
    {{- $_ := set $spec "dashboard" (mergeOverwrite $profileDashboard $customDashboard) -}}
  {{- else if eq $profile "S" -}}
    {{- $profileIndexer := dict "replicas" 1 "storageSize" "20Gi" "resources" (dict "requests" (dict "cpu" "500m" "memory" "1Gi") "limits" (dict "cpu" "1" "memory" "2Gi")) -}}
    {{- $profileMaster := dict "storageSize" "10Gi" "resources" (dict "requests" (dict "cpu" "500m" "memory" "1Gi") "limits" (dict "cpu" "1" "memory" "2Gi")) -}}
    {{- $profileWorkers := dict "replicas" 1 "storageSize" "10Gi" "resources" (dict "requests" (dict "cpu" "500m" "memory" "1Gi") "limits" (dict "cpu" "1" "memory" "2Gi")) -}}
    {{- $profileDashboard := dict "replicas" 1 "resources" (dict "requests" (dict "cpu" "250m" "memory" "512Mi") "limits" (dict "cpu" "500m" "memory" "1Gi")) -}}
    {{- $_ := set $spec "indexer" (mergeOverwrite $profileIndexer $customIndexer) -}}
    {{- $_ := set $spec "manager" (dict "master" (mergeOverwrite $profileMaster $customMaster) "workers" (mergeOverwrite $profileWorkers $customWorkers)) -}}
    {{- $_ := set $spec "dashboard" (mergeOverwrite $profileDashboard $customDashboard) -}}
  {{- else if eq $profile "M" -}}
    {{- $profileIndexer := dict "replicas" 3 "storageSize" "50Gi" "resources" (dict "requests" (dict "cpu" "2" "memory" "4Gi") "limits" (dict "cpu" "4" "memory" "8Gi")) -}}
    {{- $profileMaster := dict "storageSize" "20Gi" "resources" (dict "requests" (dict "cpu" "1" "memory" "2Gi") "limits" (dict "cpu" "2" "memory" "4Gi")) -}}
    {{- $profileWorkers := dict "replicas" 2 "storageSize" "20Gi" "resources" (dict "requests" (dict "cpu" "1" "memory" "2Gi") "limits" (dict "cpu" "2" "memory" "4Gi")) -}}
    {{- $profileDashboard := dict "replicas" 1 "resources" (dict "requests" (dict "cpu" "500m" "memory" "1Gi") "limits" (dict "cpu" "1" "memory" "2Gi")) -}}
    {{- $_ := set $spec "indexer" (mergeOverwrite $profileIndexer $customIndexer) -}}
    {{- $_ := set $spec "manager" (dict "master" (mergeOverwrite $profileMaster $customMaster) "workers" (mergeOverwrite $profileWorkers $customWorkers)) -}}
    {{- $_ := set $spec "dashboard" (mergeOverwrite $profileDashboard $customDashboard) -}}
  {{- else if eq $profile "L" -}}
    {{- $profileIndexer := dict "replicas" 3 "storageSize" "100Gi" "resources" (dict "requests" (dict "cpu" "4" "memory" "8Gi") "limits" (dict "cpu" "8" "memory" "16Gi")) -}}
    {{- $profileMaster := dict "storageSize" "50Gi" "resources" (dict "requests" (dict "cpu" "2" "memory" "4Gi") "limits" (dict "cpu" "4" "memory" "8Gi")) -}}
    {{- $profileWorkers := dict "replicas" 3 "storageSize" "50Gi" "resources" (dict "requests" (dict "cpu" "2" "memory" "4Gi") "limits" (dict "cpu" "4" "memory" "8Gi")) -}}
    {{- $profileDashboard := dict "replicas" 2 "resources" (dict "requests" (dict "cpu" "1" "memory" "2Gi") "limits" (dict "cpu" "2" "memory" "4Gi")) -}}
    {{- $_ := set $spec "indexer" (mergeOverwrite $profileIndexer $customIndexer) -}}
    {{- $_ := set $spec "manager" (dict "master" (mergeOverwrite $profileMaster $customMaster) "workers" (mergeOverwrite $profileWorkers $customWorkers)) -}}
    {{- $_ := set $spec "dashboard" (mergeOverwrite $profileDashboard $customDashboard) -}}
  {{- else if eq $profile "XL" -}}
    {{- $profileIndexer := dict "replicas" 5 "storageSize" "200Gi" "resources" (dict "requests" (dict "cpu" "8" "memory" "16Gi") "limits" (dict "cpu" "16" "memory" "32Gi")) -}}
    {{- $profileMaster := dict "storageSize" "100Gi" "resources" (dict "requests" (dict "cpu" "4" "memory" "8Gi") "limits" (dict "cpu" "8" "memory" "16Gi")) -}}
    {{- $profileWorkers := dict "replicas" 5 "storageSize" "100Gi" "resources" (dict "requests" (dict "cpu" "4" "memory" "8Gi") "limits" (dict "cpu" "8" "memory" "16Gi")) -}}
    {{- $profileDashboard := dict "replicas" 3 "resources" (dict "requests" (dict "cpu" "2" "memory" "4Gi") "limits" (dict "cpu" "4" "memory" "8Gi")) -}}
    {{- $_ := set $spec "indexer" (mergeOverwrite $profileIndexer $customIndexer) -}}
    {{- $_ := set $spec "manager" (dict "master" (mergeOverwrite $profileMaster $customMaster) "workers" (mergeOverwrite $profileWorkers $customWorkers)) -}}
    {{- $_ := set $spec "dashboard" (mergeOverwrite $profileDashboard $customDashboard) -}}
  {{- end -}}

  {{- /* Apply custom storageClassName if set */ -}}
  {{- if $storageClass -}}
    {{- $_ := set $spec "storageClassName" $storageClass -}}
  {{- end -}}
{{- end -}}

{{- /* Apply TLS config if set in values */ -}}
{{- if .Values.cluster.spec.tls -}}
  {{- $_ := set $spec "tls" .Values.cluster.spec.tls -}}
{{- end -}}

{{- toYaml $spec -}}
{{- end -}}
