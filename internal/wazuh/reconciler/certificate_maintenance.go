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
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/certificates"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// CAMaintenanceCheckResult contains the result of checking CA maintenance windows
type CAMaintenanceCheckResult struct {
	// AllowRenewal indicates if CA renewal/restart is allowed now
	AllowRenewal bool
	// Reason explains why renewal is or isn't allowed
	Reason string
	// NextWindowStart is when the next maintenance window starts (if not currently allowed)
	NextWindowStart time.Time
	// ForceRenewal indicates if renewal should be forced due to max wait exceeded
	ForceRenewal bool
}

// checkCAMaintenanceWindow checks if CA renewal restart is allowed based on maintenance windows
func (r *CertificateReconciler) checkCAMaintenanceWindow(cluster *wazuhv1.WazuhCluster, caExpiry time.Time) *CAMaintenanceCheckResult {
	result := &CAMaintenanceCheckResult{AllowRenewal: true, Reason: "No maintenance windows configured"}

	// Get CA maintenance config from TLS config
	if cluster.Spec.TLS == nil || cluster.Spec.TLS.CAMaintenance == nil {
		return result
	}
	caConfig := cluster.Spec.TLS.CAMaintenance

	// If AutoRestart is disabled, don't allow automatic renewal
	if !caConfig.AutoRestart {
		result.AllowRenewal = false
		result.Reason = "AutoRestart is disabled, waiting for manual intervention"
		return result
	}

	// If no maintenance windows configured, allow immediate renewal
	if len(caConfig.MaintenanceWindows) == 0 {
		return result
	}

	// Check each maintenance window
	now := time.Now()
	var nextWindow time.Time
	for _, window := range caConfig.MaintenanceWindows {
		// Parse duration
		duration := 4 * time.Hour // default
		if window.Duration != "" {
			if d, err := certificates.ParseCertDuration(window.Duration); err == nil {
				duration = d
			}
		}

		checker, err := utils.NewMaintenanceWindowChecker(window.Schedule, duration, window.Timezone)
		if err != nil {
			continue // Skip invalid windows
		}

		// Check if we're within this window
		inWindow, err := checker.IsWithinWindow(now)
		if err != nil {
			continue
		}
		if inWindow {
			result.AllowRenewal = true
			result.Reason = "Currently within maintenance window"
			return result
		}

		// Track next window start
		if next, err := checker.NextWindowStart(now); err == nil {
			if nextWindow.IsZero() || next.Before(nextWindow) {
				nextWindow = next
			}
		}
	}

	// Not within any window - check if we should force renewal
	maxWait := 7 * 24 * time.Hour // default 7 days
	if caConfig.MaxWaitDuration != "" {
		if d, err := certificates.ParseCertDuration(caConfig.MaxWaitDuration); err == nil {
			maxWait = d
		}
	}

	// If CA expires before we can wait for a window, force renewal
	timeUntilExpiry := caExpiry.Sub(now)
	if timeUntilExpiry < maxWait && !nextWindow.IsZero() && nextWindow.After(caExpiry) {
		result.AllowRenewal = true
		result.ForceRenewal = true
		result.Reason = fmt.Sprintf("Forcing renewal: CA expires in %v, before next maintenance window", timeUntilExpiry.Round(time.Hour))
		return result
	}

	// Otherwise, wait for maintenance window
	result.AllowRenewal = false
	result.NextWindowStart = nextWindow
	result.Reason = fmt.Sprintf("Waiting for maintenance window starting at %s", nextWindow.Format(time.RFC3339))
	return result
}

// CAReconcileResult contains the result of CA reconciliation
type CAReconcileResult struct {
	// CAResult contains the CA certificate details
	CAResult *certificates.CAResult
	// Renewed indicates if the CA was renewed in this reconciliation
	Renewed bool
	// RenewalPending indicates CA needs renewal but is waiting for maintenance window
	RenewalPending bool
	// NextMaintenanceWindow is when the next maintenance window starts (if RenewalPending)
	NextMaintenanceWindow time.Time
}

// reconcileCA reconciles the CA certificate
// Returns the CA reconcile result and any error
func (r *CertificateReconciler) reconcileCA(ctx context.Context, cluster *wazuhv1.WazuhCluster, certOpts *certificates.CertificateOptions) (*CAReconcileResult, error) {
	log := logf.FromContext(ctx)
	secretName := cluster.Name + "-ca"
	result := &CAReconcileResult{}

	// Check if CA secret exists
	found := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, found)
	if err == nil {
		// Parse existing CA
		caResult, parseErr := certificates.ParseCA(found.Data[constants.SecretKeyCACert], found.Data[constants.SecretKeyCAKey])
		if parseErr != nil {
			log.Error(parseErr, "Failed to parse existing CA, regenerating")
		} else {
			// Check if CA needs renewal using options from CRD
			needsRenewal := certOpts.ShouldRenewCA(caResult)
			if needsRenewal {
				log.Info("CA certificate needs renewal", "name", secretName, "daysUntilExpiry", caResult.DaysUntilExpiry(), "renewalThreshold", certificates.FormatCertDuration(certOpts.GetCARenewalThreshold()))

				// Check maintenance window before proceeding with renewal
				maintenanceCheck := r.checkCAMaintenanceWindow(cluster, caResult.Certificate.NotAfter)
				if !maintenanceCheck.AllowRenewal {
					log.Info("CA renewal postponed - waiting for maintenance window",
						"reason", maintenanceCheck.Reason,
						"nextWindow", maintenanceCheck.NextWindowStart)
					r.emitCAMaintenanceScheduledEvent(cluster, maintenanceCheck.NextWindowStart)
					result.CAResult = caResult
					result.RenewalPending = true
					result.NextMaintenanceWindow = maintenanceCheck.NextWindowStart
					return result, nil
				}

				// Maintenance window allows renewal or was forced
				if maintenanceCheck.ForceRenewal {
					log.Info("CA renewal forced due to imminent expiry", "reason", maintenanceCheck.Reason)
				}

				// If CA needs renewal, regenerate it
				// This will trigger regeneration of all dependent certificates
				r.emitTypedCertRenewingEvent(cluster, CertEventTypeCA, secretName)
				log.Info("Regenerating CA certificate", "name", secretName)
				result.Renewed = true
				// Fall through to regenerate CA
			} else {
				// CA is valid and doesn't need renewal
				result.CAResult = caResult
				return result, nil
			}
		}
	}

	if err != nil && !errors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to get CA secret: %w", err)
	}

	// Generate new CA using options from CRD
	log.Info("Generating new CA certificate", "name", secretName, "validity", certificates.FormatCertDuration(certOpts.GetCAValidity()),
		"country", certOpts.Country, "state", certOpts.State, "locality", certOpts.Locality,
		"organization", certOpts.Organization, "organizationalUnit", certOpts.OrganizationalUnit)
	caConfig := certificates.DefaultCAConfig(cluster.Name + "-ca")
	// Apply subject fields from CRD configuration
	caConfig.Country = certOpts.Country
	caConfig.State = certOpts.State
	caConfig.Locality = certOpts.Locality
	caConfig.Organization = certOpts.Organization
	caConfig.OrganizationalUnit = certOpts.OrganizationalUnit
	caConfig.Validity = certOpts.GetCAValidity()
	caConfig.KeyAlgorithm = certOpts.KeyAlgorithm
	caConfig.ECDSACurve = certOpts.ECDSACurve

	caResult, err := certificates.GenerateCA(caConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA: %w", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cluster.Namespace,
			Labels: map[string]string{
				constants.LabelName:         "wazuh-ca",
				constants.LabelInstance:     cluster.Name,
				constants.LabelComponent:    "certificates",
				constants.LabelPartOf:       constants.AppName,
				constants.LabelManagedBy:    constants.OperatorName,
				constants.LabelWazuhCluster: cluster.Name,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			constants.SecretKeyCACert:  caResult.CertificatePEM,
			constants.SecretKeyCAKey:   caResult.PrivateKeyPEM,
			constants.SecretKeyTLSCert: caResult.CertificatePEM,
			constants.SecretKeyTLSKey:  caResult.PrivateKeyPEM,
		},
	}

	if err := controllerutil.SetControllerReference(cluster, secret, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Use CreateOrUpdate to handle both creation and renewal
	isRenewal := found.Name != ""
	if isRenewal {
		// Update existing secret
		found.Data = secret.Data
		found.Labels = secret.Labels
		if err := r.Update(ctx, found); err != nil {
			r.emitTypedCertRenewalFailedEvent(cluster, CertEventTypeCA, secretName, err)
			return nil, fmt.Errorf("failed to update CA secret: %w", err)
		}
		r.emitTypedCertRenewedEvent(cluster, CertEventTypeCA, secretName)
		log.Info("CA certificate renewed successfully", "name", secretName)
		result.Renewed = true
	} else {
		// Create new secret
		if err := r.Create(ctx, secret); err != nil {
			r.emitTypedCertRenewalFailedEvent(cluster, CertEventTypeCA, secretName, err)
			return nil, fmt.Errorf("failed to create CA secret: %w", err)
		}
		r.emitTypedCertCreatedEvent(cluster, CertEventTypeCA, secretName)
	}

	result.CAResult = caResult
	return result, nil
}
