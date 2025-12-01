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

package client

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
)

// K8sClient provides a public interface for Kubernetes operations
type K8sClient struct {
	adapter *adapters.K8sAdapter
}

// NewK8sClient creates a new K8sClient
func NewK8sClient(c client.Client, scheme *runtime.Scheme) *K8sClient {
	return &K8sClient{
		adapter: adapters.NewK8sAdapter(c, scheme),
	}
}

// GetSecret retrieves a secret value by key
func (c *K8sClient) GetSecret(ctx context.Context, namespace, name string) (map[string][]byte, error) {
	secret, err := c.adapter.GetSecret(ctx, namespace, name)
	if err != nil {
		return nil, err
	}
	return secret.Data, nil
}

// GetConfigMap retrieves a ConfigMap data
func (c *K8sClient) GetConfigMap(ctx context.Context, namespace, name string) (map[string]string, error) {
	cm, err := c.adapter.GetConfigMap(ctx, namespace, name)
	if err != nil {
		return nil, err
	}
	return cm.Data, nil
}

// IsDeploymentReady checks if a deployment is ready
func (c *K8sClient) IsDeploymentReady(ctx context.Context, namespace, name string) (bool, error) {
	deployment, err := c.adapter.GetDeployment(ctx, namespace, name)
	if err != nil {
		return false, err
	}
	return c.adapter.IsDeploymentReady(deployment), nil
}

// IsStatefulSetReady checks if a StatefulSet is ready
func (c *K8sClient) IsStatefulSetReady(ctx context.Context, namespace, name string) (bool, error) {
	sts, err := c.adapter.GetStatefulSet(ctx, namespace, name)
	if err != nil {
		return false, err
	}
	return c.adapter.IsStatefulSetReady(sts), nil
}

// Client returns the underlying controller-runtime client
func (c *K8sClient) Client() client.Client {
	return c.adapter.Client()
}

// Scheme returns the runtime scheme
func (c *K8sClient) Scheme() *runtime.Scheme {
	return c.adapter.Scheme()
}
