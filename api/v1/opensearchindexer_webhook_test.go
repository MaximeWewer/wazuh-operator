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
	"testing"
)

func TestOpenSearchIndexerValidator_ValidMinimalSpec(t *testing.T) {
	v := &OpenSearchIndexerCustomValidator{}

	indexer := &OpenSearchIndexer{
		Spec: OpenSearchIndexerSpec{
			Version:     "4.9.0",
			Replicas:    3,
			StorageSize: "50Gi",
		},
	}

	warnings, err := v.ValidateCreate(context.Background(), indexer)
	if err != nil {
		t.Errorf("expected no error with valid minimal spec, got: %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("expected no warnings with 3 replicas, got: %v", warnings)
	}
}

func TestOpenSearchIndexerValidator_EmptyVersion(t *testing.T) {
	v := &OpenSearchIndexerCustomValidator{}

	indexer := &OpenSearchIndexer{
		Spec: OpenSearchIndexerSpec{
			Version:     "",
			Replicas:    3,
			StorageSize: "50Gi",
		},
	}

	_, err := v.ValidateCreate(context.Background(), indexer)
	if err == nil {
		t.Error("expected error when version is empty, got nil")
	}
}

func TestOpenSearchIndexerValidator_InvalidVersionFormat(t *testing.T) {
	v := &OpenSearchIndexerCustomValidator{}

	indexer := &OpenSearchIndexer{
		Spec: OpenSearchIndexerSpec{
			Version:     "v4.9.0",
			Replicas:    3,
			StorageSize: "50Gi",
		},
	}

	_, err := v.ValidateCreate(context.Background(), indexer)
	if err == nil {
		t.Error("expected error when version has invalid format, got nil")
	}
}

func TestOpenSearchIndexerValidator_ReplicasLessThanOne(t *testing.T) {
	v := &OpenSearchIndexerCustomValidator{}

	indexer := &OpenSearchIndexer{
		Spec: OpenSearchIndexerSpec{
			Version:     "4.9.0",
			Replicas:    0,
			StorageSize: "50Gi",
		},
	}

	_, err := v.ValidateCreate(context.Background(), indexer)
	if err == nil {
		t.Error("expected error when replicas < 1, got nil")
	}
}

func TestOpenSearchIndexerValidator_ReplicasLessThanThreeWarning(t *testing.T) {
	v := &OpenSearchIndexerCustomValidator{}

	indexer := &OpenSearchIndexer{
		Spec: OpenSearchIndexerSpec{
			Version:     "4.9.0",
			Replicas:    2,
			StorageSize: "50Gi",
		},
	}

	warnings, err := v.ValidateCreate(context.Background(), indexer)
	if err != nil {
		t.Errorf("expected no error with 2 replicas, got: %v", err)
	}
	if len(warnings) == 0 {
		t.Error("expected warning when replicas < 3, got none")
	}
}

func TestOpenSearchIndexerValidator_InvalidStorageSize(t *testing.T) {
	v := &OpenSearchIndexerCustomValidator{}

	indexer := &OpenSearchIndexer{
		Spec: OpenSearchIndexerSpec{
			Version:     "4.9.0",
			Replicas:    3,
			StorageSize: "not-a-quantity",
		},
	}

	_, err := v.ValidateCreate(context.Background(), indexer)
	if err == nil {
		t.Error("expected error when storageSize is invalid, got nil")
	}
}

func TestOpenSearchIndexerValidator_GatewayAndIngressBothEnabled(t *testing.T) {
	v := &OpenSearchIndexerCustomValidator{}

	indexer := &OpenSearchIndexer{
		Spec: OpenSearchIndexerSpec{
			Version:     "4.9.0",
			Replicas:    3,
			StorageSize: "50Gi",
			GatewayAPI: &GatewayAPISpec{
				Enabled: true,
				GatewayRef: &GatewayReference{
					Name: "my-gateway",
				},
			},
			Ingress: &IngressSpec{
				Enabled: true,
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), indexer)
	if err == nil {
		t.Error("expected error when both gatewayAPI and ingress are enabled, got nil")
	}
}

func TestOpenSearchIndexerValidator_ValidUpdate(t *testing.T) {
	v := &OpenSearchIndexerCustomValidator{}

	old := &OpenSearchIndexer{
		Spec: OpenSearchIndexerSpec{
			Version:     "4.9.0",
			Replicas:    3,
			StorageSize: "50Gi",
		},
	}
	new := &OpenSearchIndexer{
		Spec: OpenSearchIndexerSpec{
			Version:     "4.9.1",
			Replicas:    5,
			StorageSize: "50Gi",
		},
	}

	warnings, err := v.ValidateUpdate(context.Background(), old, new)
	if err != nil {
		t.Errorf("expected no error on valid update, got: %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("expected no warnings on scale-up, got: %v", warnings)
	}
}

func TestOpenSearchIndexerValidator_ScaleDownWarning(t *testing.T) {
	v := &OpenSearchIndexerCustomValidator{}

	old := &OpenSearchIndexer{
		Spec: OpenSearchIndexerSpec{
			Version:     "4.9.0",
			Replicas:    5,
			StorageSize: "50Gi",
		},
	}
	new := &OpenSearchIndexer{
		Spec: OpenSearchIndexerSpec{
			Version:     "4.9.0",
			Replicas:    3,
			StorageSize: "50Gi",
		},
	}

	warnings, err := v.ValidateUpdate(context.Background(), old, new)
	if err != nil {
		t.Errorf("expected no error on scale-down, got: %v", err)
	}
	if len(warnings) == 0 {
		t.Error("expected warning on scale-down, got none")
	}
}

func TestOpenSearchIndexerValidator_Delete(t *testing.T) {
	v := &OpenSearchIndexerCustomValidator{}

	indexer := &OpenSearchIndexer{
		Spec: OpenSearchIndexerSpec{
			Version:     "4.9.0",
			Replicas:    3,
			StorageSize: "50Gi",
		},
	}

	_, err := v.ValidateDelete(context.Background(), indexer)
	if err != nil {
		t.Errorf("expected no error on delete, got: %v", err)
	}
}
