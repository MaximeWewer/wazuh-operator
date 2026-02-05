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

package reconciler

import (
	"time"

	corev1 "k8s.io/api/core/v1"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// Certificate event reasons (generic, for backward compatibility)
const (
	// EventReasonCertificateRenewing is emitted when a certificate renewal starts
	EventReasonCertificateRenewing = "CertificateRenewing"
	// EventReasonCertificateRenewed is emitted when a certificate is successfully renewed
	EventReasonCertificateRenewed = "CertificateRenewed"
	// EventReasonCertificateRenewalFailed is emitted when a certificate renewal fails
	EventReasonCertificateRenewalFailed = "CertificateRenewalFailed"
	// EventReasonCertificateCreated is emitted when a new certificate is created
	EventReasonCertificateCreated = "CertificateCreated"
	// EventReasonCertificateDomainMismatch is emitted when a certificate has SANs with wrong cluster domain
	EventReasonCertificateDomainMismatch = "CertificateDomainMismatch"
)

// CertEventType represents the type of certificate for event emission
type CertEventType string

const (
	// CertEventTypeCA represents CA certificate events
	CertEventTypeCA CertEventType = "ca"
	// CertEventTypeNode represents Node/Indexer certificate events
	CertEventTypeNode CertEventType = "node"
	// CertEventTypeAdmin represents Admin certificate events
	CertEventTypeAdmin CertEventType = "admin"
	// CertEventTypeFilebeat represents Filebeat certificate events
	CertEventTypeFilebeat CertEventType = "filebeat"
	// CertEventTypeDashboard represents Dashboard certificate events
	CertEventTypeDashboard CertEventType = "dashboard"
)

// getEventReasonForCertType returns the appropriate event reason for a certificate type and action
func getEventReasonForCertType(certType CertEventType, action string) string {
	switch certType {
	case CertEventTypeCA:
		switch action {
		case "renewing":
			return constants.EventReasonCARenewing
		case "renewed":
			return constants.EventReasonCARenewed
		case "failed":
			return constants.EventReasonCARenewalFailed
		case "expiring":
			return constants.EventReasonCAExpiring
		}
	case CertEventTypeNode:
		switch action {
		case "renewing":
			return constants.EventReasonNodeCertRenewing
		case "renewed":
			return constants.EventReasonNodeCertRenewed
		case "failed":
			return constants.EventReasonNodeCertRenewalFailed
		case "expiring":
			return constants.EventReasonNodeCertExpiring
		}
	case CertEventTypeAdmin:
		switch action {
		case "renewing":
			return constants.EventReasonAdminCertRenewing
		case "renewed":
			return constants.EventReasonAdminCertRenewed
		case "failed":
			return constants.EventReasonAdminCertRenewalFailed
		case "expiring":
			return constants.EventReasonAdminCertExpiring
		}
	case CertEventTypeFilebeat:
		switch action {
		case "renewing":
			return constants.EventReasonFilebeatCertRenewing
		case "renewed":
			return constants.EventReasonFilebeatCertRenewed
		case "failed":
			return constants.EventReasonFilebeatCertRenewalFailed
		case "expiring":
			return constants.EventReasonFilebeatCertExpiring
		}
	case CertEventTypeDashboard:
		switch action {
		case "renewing":
			return constants.EventReasonDashboardCertRenewing
		case "renewed":
			return constants.EventReasonDashboardCertRenewed
		case "failed":
			return constants.EventReasonDashboardCertRenewalFailed
		case "expiring":
			return constants.EventReasonDashboardCertExpiring
		}
	}
	// Fallback to generic events
	switch action {
	case "renewing":
		return EventReasonCertificateRenewing
	case "renewed":
		return EventReasonCertificateRenewed
	case "failed":
		return EventReasonCertificateRenewalFailed
	default:
		return EventReasonCertificateRenewing
	}
}

// emitCertificateRenewingEvent emits an event when certificate renewal starts (generic)
//
//nolint:unused // Utility function for certificate event system - will be used by certificate renewal logic
func (r *CertificateReconciler) emitCertificateRenewingEvent(cluster *wazuhv1.WazuhCluster, certName string) {
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(cluster, corev1.EventTypeNormal, EventReasonCertificateRenewing,
			"Starting renewal of certificate: %s", certName)
	}
}

// emitCertificateRenewedEvent emits an event when certificate renewal succeeds (generic)
//
//nolint:unused // Utility function for certificate event system - will be used by certificate renewal logic
func (r *CertificateReconciler) emitCertificateRenewedEvent(cluster *wazuhv1.WazuhCluster, certName string) {
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(cluster, corev1.EventTypeNormal, EventReasonCertificateRenewed,
			"Successfully renewed certificate: %s", certName)
	}
}

// emitCertificateRenewalFailedEvent emits an event when certificate renewal fails (generic)
//
//nolint:unused // Utility function for certificate event system - will be used by certificate renewal logic
func (r *CertificateReconciler) emitCertificateRenewalFailedEvent(cluster *wazuhv1.WazuhCluster, certName string, err error) {
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(cluster, corev1.EventTypeWarning, EventReasonCertificateRenewalFailed,
			"Failed to renew certificate %s: %v", certName, err)
	}
}

// emitCertificateCreatedEvent emits an event when a new certificate is created (generic)
//
//nolint:unused // Utility function for certificate event system - will be used by certificate renewal logic
func (r *CertificateReconciler) emitCertificateCreatedEvent(cluster *wazuhv1.WazuhCluster, certName string) {
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(cluster, corev1.EventTypeNormal, EventReasonCertificateCreated,
			"Created new certificate: %s", certName)
	}
}

// emitCertificateDomainMismatchEvent emits a warning event when a certificate has SANs with wrong cluster domain
func (r *CertificateReconciler) emitCertificateDomainMismatchEvent(cluster *wazuhv1.WazuhCluster, certName, expectedDomain string) {
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(cluster, corev1.EventTypeWarning, EventReasonCertificateDomainMismatch,
			"Certificate %s has SANs with wrong cluster domain (expected: %s), triggering regeneration", certName, expectedDomain)
	}
}

// emitTypedCertRenewingEvent emits a type-specific event when certificate renewal starts
func (r *CertificateReconciler) emitTypedCertRenewingEvent(cluster *wazuhv1.WazuhCluster, certType CertEventType, certName string) {
	if r.EventRecorder != nil {
		reason := getEventReasonForCertType(certType, "renewing")
		r.EventRecorder.Eventf(cluster, corev1.EventTypeNormal, reason,
			"Starting renewal of %s certificate: %s", certType, certName)
	}
}

// emitTypedCertRenewedEvent emits a type-specific event when certificate renewal succeeds
func (r *CertificateReconciler) emitTypedCertRenewedEvent(cluster *wazuhv1.WazuhCluster, certType CertEventType, certName string) {
	if r.EventRecorder != nil {
		reason := getEventReasonForCertType(certType, "renewed")
		r.EventRecorder.Eventf(cluster, corev1.EventTypeNormal, reason,
			"Successfully renewed %s certificate: %s", certType, certName)
	}
}

// emitTypedCertRenewalFailedEvent emits a type-specific event when certificate renewal fails
func (r *CertificateReconciler) emitTypedCertRenewalFailedEvent(cluster *wazuhv1.WazuhCluster, certType CertEventType, certName string, err error) {
	if r.EventRecorder != nil {
		reason := getEventReasonForCertType(certType, "failed")
		r.EventRecorder.Eventf(cluster, corev1.EventTypeWarning, reason,
			"Failed to renew %s certificate %s: %v", certType, certName, err)
	}
}

// emitTypedCertCreatedEvent emits a type-specific event when a new certificate is created
func (r *CertificateReconciler) emitTypedCertCreatedEvent(cluster *wazuhv1.WazuhCluster, certType CertEventType, certName string) {
	if r.EventRecorder != nil {
		// Use the renewed event for creation as well (no separate "created" event per type)
		reason := getEventReasonForCertType(certType, "renewed")
		r.EventRecorder.Eventf(cluster, corev1.EventTypeNormal, reason,
			"Created new %s certificate: %s", certType, certName)
	}
}

// emitTypedCertExpiringEvent emits a type-specific event when a certificate is approaching expiry
//
//nolint:unused // Utility function for certificate event system - will be used by certificate expiry checks
func (r *CertificateReconciler) emitTypedCertExpiringEvent(cluster *wazuhv1.WazuhCluster, certType CertEventType, certName string, daysUntilExpiry int) {
	if r.EventRecorder != nil {
		reason := getEventReasonForCertType(certType, "expiring")
		r.EventRecorder.Eventf(cluster, corev1.EventTypeWarning, reason,
			"%s certificate %s is expiring in %d days", certType, certName, daysUntilExpiry)
	}
}

// emitCAMaintenanceScheduledEvent emits an event when CA renewal is waiting for maintenance window
func (r *CertificateReconciler) emitCAMaintenanceScheduledEvent(cluster *wazuhv1.WazuhCluster, nextWindow time.Time) {
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(cluster, corev1.EventTypeNormal, constants.EventReasonCertMaintenanceScheduled,
			"CA certificate renewal scheduled for next maintenance window at %s", nextWindow.Format(time.RFC3339))
	}
}
