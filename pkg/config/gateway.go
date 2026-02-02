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

package config

import (
	"context"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// EnvGatewayAPIEnabled is the environment variable to enable/disable Gateway API support.
	// When set to "true", the operator will watch Gateway API resources (HTTPRoute, TCPRoute, UDPRoute).
	// Default: "false"
	EnvGatewayAPIEnabled = "GATEWAY_API_ENABLED"
)

// GatewayAPIStatus represents the status of Gateway API support in the cluster.
type GatewayAPIStatus struct {
	// Enabled indicates if Gateway API is enabled in the operator configuration.
	Enabled bool

	// HTTPRouteAvailable indicates if the HTTPRoute CRD is installed.
	HTTPRouteAvailable bool

	// TCPRouteAvailable indicates if the TCPRoute CRD is installed.
	TCPRouteAvailable bool

	// UDPRouteAvailable indicates if the UDPRoute CRD is installed.
	UDPRouteAvailable bool

	// Message provides additional information about the status.
	Message string
}

// IsGatewayAPIEnabled returns true if Gateway API support is enabled via environment variable.
func IsGatewayAPIEnabled() bool {
	val := os.Getenv(EnvGatewayAPIEnabled)
	return strings.ToLower(val) == "true"
}

// CheckGatewayAPICRDs checks if Gateway API CRDs are installed in the cluster.
// Returns a GatewayAPIStatus with the availability of each CRD type.
func CheckGatewayAPICRDs(ctx context.Context, c client.Client) GatewayAPIStatus {
	status := GatewayAPIStatus{
		Enabled: IsGatewayAPIEnabled(),
	}

	if !status.Enabled {
		status.Message = "Gateway API support is disabled. Set GATEWAY_API_ENABLED=true to enable."
		return status
	}

	// Check HTTPRoute CRD (standard install)
	httpRouteGVK := schema.GroupVersionKind{
		Group:   "gateway.networking.k8s.io",
		Version: "v1",
		Kind:    "HTTPRoute",
	}
	status.HTTPRouteAvailable = isCRDAvailable(ctx, c, httpRouteGVK)

	// Check TCPRoute CRD (experimental install)
	tcpRouteGVK := schema.GroupVersionKind{
		Group:   "gateway.networking.k8s.io",
		Version: "v1alpha2",
		Kind:    "TCPRoute",
	}
	status.TCPRouteAvailable = isCRDAvailable(ctx, c, tcpRouteGVK)

	// Check UDPRoute CRD (experimental install)
	udpRouteGVK := schema.GroupVersionKind{
		Group:   "gateway.networking.k8s.io",
		Version: "v1alpha2",
		Kind:    "UDPRoute",
	}
	status.UDPRouteAvailable = isCRDAvailable(ctx, c, udpRouteGVK)

	// Build status message
	if status.HTTPRouteAvailable && status.TCPRouteAvailable && status.UDPRouteAvailable {
		status.Message = "Gateway API fully available (HTTPRoute, TCPRoute, UDPRoute)"
	} else if status.HTTPRouteAvailable {
		missing := []string{}
		if !status.TCPRouteAvailable {
			missing = append(missing, "TCPRoute")
		}
		if !status.UDPRouteAvailable {
			missing = append(missing, "UDPRoute")
		}
		status.Message = "Gateway API partially available. Missing experimental CRDs: " + strings.Join(missing, ", ") +
			". Install with: kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/experimental-install.yaml"
	} else {
		status.Message = "Gateway API CRDs not installed. Install standard CRDs with: " +
			"kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml"
	}

	return status
}

// CanUseGatewayAPI returns true if Gateway API is both enabled and at least HTTPRoute CRD is available.
func CanUseGatewayAPI(ctx context.Context, c client.Client) bool {
	status := CheckGatewayAPICRDs(ctx, c)
	return status.Enabled && status.HTTPRouteAvailable
}

// isCRDAvailable checks if a specific CRD is available by attempting to get its REST mapping.
func isCRDAvailable(_ context.Context, c client.Client, gvk schema.GroupVersionKind) bool {
	// Use the REST mapper to check if the resource type exists
	mapping, err := c.RESTMapper().RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		// If we can't get a mapping, the CRD is not installed
		if errors.IsNotFound(err) || strings.Contains(err.Error(), "no matches for kind") {
			return false
		}
		// For other errors, assume not available
		return false
	}

	// If we got a mapping, the CRD is installed
	return mapping != nil
}
