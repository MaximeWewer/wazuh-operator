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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WazuhMasterSpec defines the master node configuration
type WazuhMasterSpec struct {
	// Resources for the master node
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// Storage size for master node
	// +kubebuilder:default="50Gi"
	StorageSize string `json:"storageSize,omitempty"`

	// Service configuration
	// +optional
	Service *ServiceSpec `json:"service,omitempty"`

	// Node selector
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Affinity
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// Additional volumes
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	ExtraVolumes []corev1.Volume `json:"extraVolumes,omitempty"`

	// Additional volume mounts
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	ExtraVolumeMounts []corev1.VolumeMount `json:"extraVolumeMounts,omitempty"`

	// Pod annotations
	// +optional
	PodAnnotations map[string]string `json:"podAnnotations,omitempty"`

	// Ingress configuration
	// +optional
	Ingress *IngressSpec `json:"ingress,omitempty"`

	// Extra configuration to inject into ossec.conf
	// +optional
	ExtraConfig string `json:"extraConfig,omitempty"`

	// Environment variables
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Env []corev1.EnvVar `json:"env,omitempty"`

	// Environment variables from ConfigMaps or Secrets
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	EnvFrom []corev1.EnvFromSource `json:"envFrom,omitempty"`

	// Security context for the pod
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	SecurityContext *corev1.PodSecurityContext `json:"securityContext,omitempty"`

	// Security context for the container
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	ContainerSecurityContext *corev1.SecurityContext `json:"containerSecurityContext,omitempty"`

	// Annotations for the StatefulSet
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// WazuhWorkerSpec defines the worker nodes configuration
type WazuhWorkerSpec struct {
	// Number of worker replicas
	// Use pointer to distinguish between 0 (no workers) and unset (apply default)
	// +optional
	// +kubebuilder:validation:Minimum=0
	Replicas *int32 `json:"replicas,omitempty"`

	// Resources for worker nodes
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// Storage size for worker nodes
	// +kubebuilder:default="50Gi"
	StorageSize string `json:"storageSize,omitempty"`

	// Service configuration
	// +optional
	Service *ServiceSpec `json:"service,omitempty"`

	// Node selector
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Affinity
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// Pod Disruption Budget
	// +optional
	PodDisruptionBudget *PodDisruptionBudgetSpec `json:"podDisruptionBudget,omitempty"`

	// Additional volumes
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	ExtraVolumes []corev1.Volume `json:"extraVolumes,omitempty"`

	// Additional volume mounts
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	ExtraVolumeMounts []corev1.VolumeMount `json:"extraVolumeMounts,omitempty"`

	// Pod annotations
	// +optional
	PodAnnotations map[string]string `json:"podAnnotations,omitempty"`

	// Ingress configuration
	// +optional
	Ingress *IngressSpec `json:"ingress,omitempty"`

	// Extra configuration to inject into ossec.conf
	// +optional
	ExtraConfig string `json:"extraConfig,omitempty"`

	// Environment variables
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Env []corev1.EnvVar `json:"env,omitempty"`

	// Environment variables from ConfigMaps or Secrets
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	EnvFrom []corev1.EnvFromSource `json:"envFrom,omitempty"`

	// Security context for the pod
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	SecurityContext *corev1.PodSecurityContext `json:"securityContext,omitempty"`

	// Security context for the container
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	ContainerSecurityContext *corev1.SecurityContext `json:"containerSecurityContext,omitempty"`

	// Annotations for the StatefulSet
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Per-pod configuration overrides for specific worker indices
	// This allows specializing individual worker pods (e.g., worker-0 for cloud log collection)
	// +optional
	Overrides []WorkerOverride `json:"overrides,omitempty"`
}

// GetReplicas returns the number of worker replicas, defaulting to DefaultManagerWorkerReplicas if not set
func (w *WazuhWorkerSpec) GetReplicas() int32 {
	if w.Replicas != nil {
		return *w.Replicas
	}
	// Default: 2 workers (from constants.DefaultManagerWorkerReplicas)
	return 2
}

// WorkerOverride defines per-pod configuration for a specific worker
// Use this to specialize individual worker pods (e.g., cloud log collection on worker-0)
type WorkerOverride struct {
	// Index of the worker pod (0-based, corresponds to pod name suffix like worker-0, worker-1)
	// +kubebuilder:validation:Minimum=0
	Index int32 `json:"index"`

	// Extra configuration to inject into ossec.conf for this specific worker
	// This is merged with the base workers.extraConfig
	// +optional
	ExtraConfig string `json:"extraConfig,omitempty"`

	// Description of this worker's specialization (for documentation)
	// +optional
	Description string `json:"description,omitempty"`
}

// ImageSpec defines container image configuration
type ImageSpec struct {
	// Repository for the image
	// +optional
	Repository string `json:"repository,omitempty"`

	// Tag for the image
	// +optional
	Tag string `json:"tag,omitempty"`

	// Pull policy
	// +optional
	// +kubebuilder:validation:Enum=Always;Never;IfNotPresent
	PullPolicy corev1.PullPolicy `json:"pullPolicy,omitempty"`
}

// ServiceSpec defines service configuration
type ServiceSpec struct {
	// Service type
	// +optional
	// +kubebuilder:validation:Enum=ClusterIP;NodePort;LoadBalancer
	Type corev1.ServiceType `json:"type,omitempty"`

	// Annotations for the service
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// LoadBalancer IP for LoadBalancer services
	// +optional
	LoadBalancerIP string `json:"loadBalancerIP,omitempty"`

	// Custom service ports configuration
	// +optional
	Ports []ServicePortSpec `json:"ports,omitempty"`

	// NodePort for NodePort services
	// +optional
	NodePort int32 `json:"nodePort,omitempty"`
}

// ServicePortSpec defines a single service port configuration
type ServicePortSpec struct {
	// Name of the port
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Port number
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// TargetPort
	// +optional
	TargetPort int32 `json:"targetPort,omitempty"`

	// NodePort
	// +optional
	// +kubebuilder:validation:Minimum=30000
	// +kubebuilder:validation:Maximum=32767
	NodePort int32 `json:"nodePort,omitempty"`

	// Protocol
	// +optional
	// +kubebuilder:default="TCP"
	// +kubebuilder:validation:Enum=TCP;UDP
	Protocol corev1.Protocol `json:"protocol,omitempty"`
}

// IngressSpec defines ingress configuration
type IngressSpec struct {
	// Enable ingress
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Ingress class name
	// +optional
	IngressClassName string `json:"ingressClassName,omitempty"`

	// Annotations for the ingress
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Hosts configuration
	// +optional
	Hosts []IngressHost `json:"hosts,omitempty"`

	// TLS configuration
	// +optional
	TLS []IngressTLS `json:"tls,omitempty"`
}

// IngressHost defines ingress host configuration
type IngressHost struct {
	// Host name
	Host string `json:"host"`

	// Paths
	Paths []IngressPath `json:"paths,omitempty"`
}

// IngressPath defines ingress path configuration
type IngressPath struct {
	// Path
	Path string `json:"path"`

	// Path type
	// +optional
	PathType string `json:"pathType,omitempty"`
}

// IngressTLS defines ingress TLS configuration
type IngressTLS struct {
	// Secret name
	SecretName string `json:"secretName,omitempty"`

	// Hosts
	Hosts []string `json:"hosts,omitempty"`
}

// PodDisruptionBudgetSpec defines pod disruption budget
type PodDisruptionBudgetSpec struct {
	// Enable PDB
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Max unavailable pods
	// +optional
	MaxUnavailable *int32 `json:"maxUnavailable,omitempty"`

	// Min available pods
	// +optional
	MinAvailable *int32 `json:"minAvailable,omitempty"`
}

// NetworkPolicySpec defines network policy configuration
type NetworkPolicySpec struct {
	// Enable network policy
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Ingress rules
	// +optional
	Ingress []NetworkPolicyIngressRule `json:"ingress,omitempty"`

	// Egress rules
	// +optional
	Egress []NetworkPolicyEgressRule `json:"egress,omitempty"`
}

// NetworkPolicyIngressRule defines ingress network policy rule
type NetworkPolicyIngressRule struct {
	// From selectors
	// +optional
	From []NetworkPolicyPeer `json:"from,omitempty"`

	// Ports
	// +optional
	Ports []NetworkPolicyPort `json:"ports,omitempty"`
}

// NetworkPolicyEgressRule defines egress network policy rule
type NetworkPolicyEgressRule struct {
	// To selectors
	// +optional
	To []NetworkPolicyPeer `json:"to,omitempty"`

	// Ports
	// +optional
	Ports []NetworkPolicyPort `json:"ports,omitempty"`
}

// NetworkPolicyPeer defines network policy peer
type NetworkPolicyPeer struct {
	// Pod selector
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`

	// Namespace selector
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

// NetworkPolicyPort defines network policy port
type NetworkPolicyPort struct {
	// Protocol
	// +optional
	Protocol *corev1.Protocol `json:"protocol,omitempty"`

	// Port number
	// +optional
	Port *int32 `json:"port,omitempty"`
}

// CredentialsSecretRef references a secret containing credentials
type CredentialsSecretRef struct {
	// Secret name
	// +optional
	SecretName string `json:"secretName,omitempty"`

	// Username key in secret
	// +optional
	// +kubebuilder:default="username"
	UsernameKey string `json:"usernameKey,omitempty"`

	// Password key in secret
	// +optional
	// +kubebuilder:default="password"
	PasswordKey string `json:"passwordKey,omitempty"`
}

// WazuhConfigSpec defines custom Wazuh configuration
type WazuhConfigSpec struct {
	// Master configuration overlay (raw XML to append)
	// +optional
	MasterConfig string `json:"masterConfig,omitempty"`

	// Worker configuration overlay (raw XML to append)
	// +optional
	WorkerConfig string `json:"workerConfig,omitempty"`

	// Local internal options
	// +optional
	LocalInternalOptions string `json:"localInternalOptions,omitempty"`

	// Global section configuration for ossec.conf
	// +optional
	Global *OSSECGlobalSpec `json:"global,omitempty"`

	// Alerts section configuration for ossec.conf
	// +optional
	Alerts *OSSECAlertsSpec `json:"alerts,omitempty"`

	// Logging section configuration for ossec.conf
	// +optional
	Logging *OSSECLoggingSpec `json:"logging,omitempty"`

	// Remote section configuration for ossec.conf
	// +optional
	Remote *OSSECRemoteSpec `json:"remote,omitempty"`

	// Auth section configuration for wazuh-authd
	// +optional
	Auth *OSSECAuthSpec `json:"auth,omitempty"`
}

// OSSECGlobalSpec defines the <global> section configuration
type OSSECGlobalSpec struct {
	// JSONOutOutput enables JSON output for alerts
	// +optional
	// +kubebuilder:default=true
	JSONOutOutput *bool `json:"jsonoutOutput,omitempty"`

	// AlertsLog enables alerts.log file
	// +optional
	// +kubebuilder:default=true
	AlertsLog *bool `json:"alertsLog,omitempty"`

	// LogAll enables logging all events
	// +optional
	// +kubebuilder:default=false
	LogAll *bool `json:"logAll,omitempty"`

	// LogAllJSON enables logging all events in JSON
	// +optional
	// +kubebuilder:default=false
	LogAllJSON *bool `json:"logAllJson,omitempty"`

	// EmailNotification enables email notifications
	// +optional
	// +kubebuilder:default=false
	EmailNotification *bool `json:"emailNotification,omitempty"`

	// SMTPServer is the SMTP server address
	// +optional
	// +kubebuilder:default="smtp.example.wazuh.com"
	SMTPServer string `json:"smtpServer,omitempty"`

	// EmailFrom is the sender email address
	// +optional
	// +kubebuilder:default="wazuh@example.wazuh.com"
	EmailFrom string `json:"emailFrom,omitempty"`

	// EmailTo is the recipient email address
	// +optional
	// +kubebuilder:default="recipient@example.wazuh.com"
	EmailTo string `json:"emailTo,omitempty"`

	// EmailMaxPerHour limits emails per hour
	// +optional
	// +kubebuilder:default=12
	EmailMaxPerHour *int `json:"emailMaxPerHour,omitempty"`

	// EmailLogSource is the log source for emails
	// +optional
	// +kubebuilder:default="alerts.log"
	EmailLogSource string `json:"emailLogSource,omitempty"`

	// AgentsDisconnectionTime is the time before agents are marked disconnected
	// +optional
	// +kubebuilder:default="10m"
	AgentsDisconnectionTime string `json:"agentsDisconnectionTime,omitempty"`

	// AgentsDisconnectionAlertTime is the time before disconnection alert (0 = disabled)
	// +optional
	// +kubebuilder:default="0"
	AgentsDisconnectionAlertTime string `json:"agentsDisconnectionAlertTime,omitempty"`
}

// OSSECAlertsSpec defines the <alerts> section configuration
type OSSECAlertsSpec struct {
	// LogAlertLevel is the minimum level for logging alerts (0-16)
	// +optional
	// +kubebuilder:default=3
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=16
	LogAlertLevel *int `json:"logAlertLevel,omitempty"`

	// EmailAlertLevel is the minimum level for email alerts (0-16)
	// +optional
	// +kubebuilder:default=12
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=16
	EmailAlertLevel *int `json:"emailAlertLevel,omitempty"`
}

// OSSECLoggingSpec defines the <logging> section configuration
type OSSECLoggingSpec struct {
	// LogFormat is the log format (plain, json, plain,json)
	// +optional
	// +kubebuilder:default="plain"
	// +kubebuilder:validation:Enum=plain;json;"plain,json"
	LogFormat string `json:"logFormat,omitempty"`
}

// OSSECRemoteSpec defines the <remote> section configuration
type OSSECRemoteSpec struct {
	// Connection type (secure, syslog)
	// +optional
	// +kubebuilder:default="secure"
	// +kubebuilder:validation:Enum=secure;syslog
	Connection string `json:"connection,omitempty"`

	// Port for agent connections
	// +optional
	// +kubebuilder:default=1514
	Port *int `json:"port,omitempty"`

	// Protocol for agent connections (tcp, udp)
	// +optional
	// +kubebuilder:default="tcp"
	// +kubebuilder:validation:Enum=tcp;udp
	Protocol string `json:"protocol,omitempty"`

	// QueueSize for the queue
	// +optional
	// +kubebuilder:default=131072
	QueueSize *int `json:"queueSize,omitempty"`
}

// OSSECAuthSpec defines the <auth> section configuration for wazuh-authd
type OSSECAuthSpec struct {
	// Disabled disables wazuh-authd
	// +optional
	// +kubebuilder:default=false
	Disabled *bool `json:"disabled,omitempty"`

	// Port for authd
	// +optional
	// +kubebuilder:default=1515
	Port *int `json:"port,omitempty"`

	// UseSourceIP uses agent's source IP for identification
	// +optional
	// +kubebuilder:default=false
	UseSourceIP *bool `json:"useSourceIP,omitempty"`

	// Purge removes old agent keys when re-enrolling
	// +optional
	// +kubebuilder:default=true
	Purge *bool `json:"purge,omitempty"`

	// UsePassword enables password authentication for agent enrollment
	// +optional
	// +kubebuilder:default=false
	UsePassword *bool `json:"usePassword,omitempty"`

	// PasswordSecretRef references a secret containing the authd password
	// If UsePassword is true, this secret will be read for the password
	// +optional
	PasswordSecretRef *SecretKeyRef `json:"passwordSecretRef,omitempty"`

	// Ciphers for SSL connections
	// +optional
	// +kubebuilder:default="HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH"
	Ciphers string `json:"ciphers,omitempty"`

	// SSLVerifyHost verifies the host SSL certificate
	// +optional
	// +kubebuilder:default=false
	SSLVerifyHost *bool `json:"sslVerifyHost,omitempty"`

	// SSLManagerCert is the path to the manager certificate
	// +optional
	// +kubebuilder:default="etc/sslmanager.cert"
	SSLManagerCert string `json:"sslManagerCert,omitempty"`

	// SSLManagerKey is the path to the manager key
	// +optional
	// +kubebuilder:default="etc/sslmanager.key"
	SSLManagerKey string `json:"sslManagerKey,omitempty"`

	// SSLAutoNegotiate enables SSL auto-negotiation
	// +optional
	// +kubebuilder:default=false
	SSLAutoNegotiate *bool `json:"sslAutoNegotiate,omitempty"`

	// EnabledOnMasterOnly when true, enables authd only on master node
	// When false, authd is enabled on all nodes (master and workers)
	// +optional
	// +kubebuilder:default=true
	EnabledOnMasterOnly *bool `json:"enabledOnMasterOnly,omitempty"`
}
