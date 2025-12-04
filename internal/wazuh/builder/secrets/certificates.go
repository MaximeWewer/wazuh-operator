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

package secrets

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// CertificateSecretBuilder builds Secrets for TLS certificates
type CertificateSecretBuilder struct {
	clusterName   string
	namespace     string
	componentName string
	caCert        []byte
	tlsCert       []byte
	tlsKey        []byte
}

// NewCertificateSecretBuilder creates a new CertificateSecretBuilder
func NewCertificateSecretBuilder(clusterName, namespace, componentName string) *CertificateSecretBuilder {
	return &CertificateSecretBuilder{
		clusterName:   clusterName,
		namespace:     namespace,
		componentName: componentName,
	}
}

// WithCACert sets the CA certificate
func (b *CertificateSecretBuilder) WithCACert(caCert []byte) *CertificateSecretBuilder {
	b.caCert = caCert
	return b
}

// WithTLSCert sets the TLS certificate
func (b *CertificateSecretBuilder) WithTLSCert(tlsCert []byte) *CertificateSecretBuilder {
	b.tlsCert = tlsCert
	return b
}

// WithTLSKey sets the TLS private key
func (b *CertificateSecretBuilder) WithTLSKey(tlsKey []byte) *CertificateSecretBuilder {
	b.tlsKey = tlsKey
	return b
}

// Build creates the Secret for certificates
func (b *CertificateSecretBuilder) Build() *corev1.Secret {
	name := b.clusterName + "-" + b.componentName + "-certs"

	labels := map[string]string{
		constants.LabelName:      b.componentName,
		constants.LabelInstance:  b.clusterName,
		constants.LabelComponent: b.componentName,
		constants.LabelPartOf:    constants.AppName,
		constants.LabelManagedBy: constants.OperatorName,
	}

	data := map[string][]byte{}
	if b.caCert != nil {
		data[constants.SecretKeyCACert] = b.caCert
	}
	if b.tlsCert != nil {
		data[constants.SecretKeyTLSCert] = b.tlsCert
	}
	if b.tlsKey != nil {
		data[constants.SecretKeyTLSKey] = b.tlsKey
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: b.namespace,
			Labels:    labels,
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}
}

// FilebeatCertSecretBuilder builds Secrets for Filebeat TLS certificates
type FilebeatCertSecretBuilder struct {
	clusterName string
	namespace   string
	caCert      []byte
	tlsCert     []byte
	tlsKey      []byte
}

// NewFilebeatCertSecretBuilder creates a new FilebeatCertSecretBuilder
func NewFilebeatCertSecretBuilder(clusterName, namespace string) *FilebeatCertSecretBuilder {
	return &FilebeatCertSecretBuilder{
		clusterName: clusterName,
		namespace:   namespace,
	}
}

// WithCACert sets the CA certificate
func (b *FilebeatCertSecretBuilder) WithCACert(caCert []byte) *FilebeatCertSecretBuilder {
	b.caCert = caCert
	return b
}

// WithTLSCert sets the TLS certificate
func (b *FilebeatCertSecretBuilder) WithTLSCert(tlsCert []byte) *FilebeatCertSecretBuilder {
	b.tlsCert = tlsCert
	return b
}

// WithTLSKey sets the TLS private key
func (b *FilebeatCertSecretBuilder) WithTLSKey(tlsKey []byte) *FilebeatCertSecretBuilder {
	b.tlsKey = tlsKey
	return b
}

// Build creates the Secret for Filebeat certificates
func (b *FilebeatCertSecretBuilder) Build() *corev1.Secret {
	name := b.clusterName + "-filebeat-certs"

	labels := map[string]string{
		constants.LabelName:      "filebeat",
		constants.LabelInstance:  b.clusterName,
		constants.LabelComponent: "filebeat",
		constants.LabelPartOf:    constants.AppName,
		constants.LabelManagedBy: constants.OperatorName,
	}

	data := map[string][]byte{}
	if b.caCert != nil {
		data[constants.SecretKeyCACert] = b.caCert
	}
	if b.tlsCert != nil {
		data[constants.SecretKeyTLSCert] = b.tlsCert
	}
	if b.tlsKey != nil {
		data[constants.SecretKeyTLSKey] = b.tlsKey
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: b.namespace,
			Labels:    labels,
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}
}
