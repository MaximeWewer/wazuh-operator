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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// cdbFetchConfigKey returns the key of a list's curl config in the CDBFetchSecretName
// Secret: a hash of the list path, which may contain characters a Secret key cannot.
func cdbFetchConfigKey(listName string) string {
	sum := sha256.Sum256([]byte(listName))
	return "list-" + hex.EncodeToString(sum[:8]) + ".curlrc"
}

// httpHeaderName matches an HTTP header field name (RFC 9110 token).
var httpHeaderName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

// curlConfigString quotes a value for a curl config file. A line break would end the
// option early and let a value inject further options, so it is rejected.
func curlConfigString(v string) (string, error) {
	if strings.ContainsAny(v, "\r\n") {
		return "", fmt.Errorf("value contains a line break")
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`, nil
}

// cdbFetchCurlConfig renders the curl config the cdb-download init container fetches an
// init-fetch list with: the resolved URL and headers, TLS verification unless the source
// opts out, failure on an HTTP error status and bounded retries and timeouts.
func cdbFetchCurlConfig(url string, headers map[string]string, insecure bool) (string, error) {
	q, err := curlConfigString(url)
	if err != nil {
		return "", fmt.Errorf("url: %w", err)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "url = %s\n", q)
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !httpHeaderName.MatchString(name) {
			return "", fmt.Errorf("invalid header name %q", name)
		}
		h, err := curlConfigString(name + ": " + headers[name])
		if err != nil {
			return "", fmt.Errorf("header %s: %w", name, err)
		}
		fmt.Fprintf(&sb, "header = %s\n", h)
	}
	if insecure {
		sb.WriteString("insecure\n")
	}
	sb.WriteString("fail\nsilent\nshow-error\nlocation\nretry = 2\nconnect-timeout = 30\nmax-time = 600\n")
	return sb.String(), nil
}

// CDBFetchConfigs returns the curl config of every init-fetch list in infos, keyed by
// FetchConfigKey. A list whose Secrets cannot be resolved is left out and logged: the
// cdb-download init container then keeps its existing file.
func (r *CDBListReconciler) CDBFetchConfigs(ctx context.Context, infos []CDBListConfigMapInfo) map[string][]byte {
	log := logf.FromContext(ctx)
	configs := map[string][]byte{}
	for _, info := range infos {
		if info.Mode != cdbDeliveryInitFetch {
			continue
		}
		list := &wazuhv1.WazuhCDBList{}
		if err := r.Get(ctx, types.NamespacedName{Name: info.ListCRName, Namespace: info.ListCRNamespace}, list); err != nil {
			log.Error(err, "Failed to get the CDB list for its fetch config", "list", info.ListCRName)
			continue
		}
		if list.Spec.Source == nil {
			continue
		}
		config, err := r.fetchCurlConfig(ctx, list)
		if err != nil {
			log.Error(err, "Failed to build the CDB list fetch config", "list", info.ListCRName)
			continue
		}
		configs[info.FetchConfigKey] = []byte(config)
	}
	return configs
}

func (r *CDBListReconciler) fetchCurlConfig(ctx context.Context, list *wazuhv1.WazuhCDBList) (string, error) {
	url, err := r.resolveURL(ctx, list)
	if err != nil {
		return "", err
	}
	var headers map[string]string
	if list.Spec.Source.HeadersSecretRef != nil {
		if headers, err = r.resolveHeaders(ctx, list.Namespace, list.Spec.Source.HeadersSecretRef); err != nil {
			return "", err
		}
	}
	return cdbFetchCurlConfig(url, headers, list.Spec.Source.InsecureSkipVerify)
}

// reconcileCDBFetchSecret writes the curl configs of the cluster's init-fetch lists to the
// CDBFetchSecretName Secret the cdb-download init container mounts, and deletes the
// Secret when there is no such list.
func (r *ClusterReconciler) reconcileCDBFetchSecret(ctx context.Context, cluster *wazuhv1.WazuhCluster, infos []CDBListConfigMapInfo) error {
	name := constants.CDBFetchSecretName(cluster.Name)
	configs := r.CDBListReconciler.CDBFetchConfigs(ctx, infos)
	hasInitFetch := false
	for _, info := range infos {
		if info.Mode == cdbDeliveryInitFetch {
			hasInitFetch = true
			break
		}
	}
	if !hasInitFetch {
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: cluster.Namespace}}
		if err := r.Delete(ctx, secret); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete CDB fetch secret %s: %w", name, err)
		}
		return nil
	}

	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: cluster.Namespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		secret.Type = corev1.SecretTypeOpaque
		secret.Data = configs
		return controllerutil.SetControllerReference(cluster, secret, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("failed to reconcile CDB fetch secret %s: %w", name, err)
	}
	return nil
}
