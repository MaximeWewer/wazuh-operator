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

package telemetry

import (
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// WrapTransport wraps an http.RoundTripper with OpenTelemetry instrumentation
// If the transport is nil, http.DefaultTransport is used as the base
// The operationName parameter is used to identify the HTTP client in traces
func WrapTransport(transport http.RoundTripper, operationName string) http.RoundTripper {
	if transport == nil {
		transport = http.DefaultTransport
	}

	return otelhttp.NewTransport(
		transport,
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return operationName + " " + r.Method + " " + r.URL.Path
		}),
	)
}

// NewInstrumentedClient creates an http.Client with OpenTelemetry instrumentation
func NewInstrumentedClient(baseClient *http.Client, operationName string) *http.Client {
	if baseClient == nil {
		baseClient = &http.Client{}
	}

	return &http.Client{
		Transport:     WrapTransport(baseClient.Transport, operationName),
		CheckRedirect: baseClient.CheckRedirect,
		Jar:           baseClient.Jar,
		Timeout:       baseClient.Timeout,
	}
}
