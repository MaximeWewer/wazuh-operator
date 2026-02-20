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

package v1

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/resource"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var opensearchindexerlog = logf.Log.WithName("opensearchindexer-webhook")

// SetupOpenSearchIndexerWebhookWithManager registers the webhook for OpenSearchIndexer in the manager.
func SetupOpenSearchIndexerWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &OpenSearchIndexer{}).
		WithValidator(&OpenSearchIndexerCustomValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-resources-wazuh-com-v1-opensearchindexer,mutating=false,failurePolicy=fail,sideEffects=None,groups=resources.wazuh.com,resources=opensearchindexers,verbs=create;update,versions=v1,name=vopensearchindexer.kb.io,admissionReviewVersions=v1

// OpenSearchIndexerCustomValidator handles validation for OpenSearchIndexer
type OpenSearchIndexerCustomValidator struct{}

var _ admission.Validator[*OpenSearchIndexer] = &OpenSearchIndexerCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *OpenSearchIndexerCustomValidator) ValidateCreate(_ context.Context, indexer *OpenSearchIndexer) (admission.Warnings, error) {
	opensearchindexerlog.Info("validate create", "name", indexer.Name, "namespace", indexer.Namespace)
	return v.validateOpenSearchIndexer(indexer)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *OpenSearchIndexerCustomValidator) ValidateUpdate(_ context.Context, oldIndexer, newIndexer *OpenSearchIndexer) (admission.Warnings, error) {
	opensearchindexerlog.Info("validate update", "name", newIndexer.Name, "namespace", newIndexer.Namespace)

	// Validate the new spec
	warnings, err := v.validateOpenSearchIndexer(newIndexer)
	if err != nil {
		return warnings, err
	}

	// Warn if scale-down
	if oldIndexer.Spec.Replicas > newIndexer.Spec.Replicas {
		warnings = append(warnings, "scaling down indexer replicas will trigger shard relocation")
	}

	return warnings, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *OpenSearchIndexerCustomValidator) ValidateDelete(_ context.Context, indexer *OpenSearchIndexer) (admission.Warnings, error) {
	opensearchindexerlog.Info("validate delete", "name", indexer.Name, "namespace", indexer.Namespace)
	return nil, nil
}

// validateOpenSearchIndexer validates the OpenSearchIndexer spec
func (v *OpenSearchIndexerCustomValidator) validateOpenSearchIndexer(indexer *OpenSearchIndexer) (admission.Warnings, error) {
	var allErrors []string
	var warnings admission.Warnings

	spec := &indexer.Spec

	// Validate version format
	if err := validateVersion(spec.Version); err != nil {
		allErrors = append(allErrors, fmt.Sprintf("spec.version: %s", err.Error()))
	}

	// Validate replicas minimum
	if spec.Replicas < 1 {
		allErrors = append(allErrors, "spec.replicas: must be at least 1")
	} else if spec.Replicas < 3 {
		warnings = append(warnings, "indexer has fewer than 3 replicas; consider 3+ for high availability")
	}

	// Validate storageSize is a valid Kubernetes quantity
	if spec.StorageSize != "" {
		if _, err := resource.ParseQuantity(spec.StorageSize); err != nil {
			allErrors = append(allErrors, fmt.Sprintf("spec.storageSize: invalid quantity %q: %s", spec.StorageSize, err.Error()))
		}
	}

	// Validate GatewayAPI/Ingress mutual exclusion
	gatewayErrors := validateGatewayAPIConfig(spec.GatewayAPI, spec.Ingress, "spec")
	allErrors = append(allErrors, gatewayErrors...)

	// Validate TLS configuration
	if spec.TLS != nil {
		tlsErrors := validateTLSConfig(spec.TLS)
		allErrors = append(allErrors, tlsErrors...)
	}

	if len(allErrors) > 0 {
		return warnings, fmt.Errorf("validation failed: %v", allErrors)
	}

	return warnings, nil
}
