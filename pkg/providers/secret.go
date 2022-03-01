/*
Copyright AppsCode Inc. and Contributors

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

package providers

import (
	"crypto/x509"
	"fmt"
	"time"

	"kubeops.dev/csi-driver-cacerts/pkg/providers/lib"

	"gomodules.xyz/cert"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type SecretProvider struct{}

var _ lib.CAProvider = &SecretProvider{}

func (c *SecretProvider) GetCAs(obj client.Object, key string) ([]*x509.Certificate, error) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return nil, fmt.Errorf("%v %s/%s is not a Secret", obj.GetObjectKind().GroupVersionKind(), obj.GetNamespace(), obj.GetName())
	}
	if key == "" {
		if secret.Type == corev1.SecretTypeServiceAccountToken {
			key = corev1.ServiceAccountRootCAKey
		} else {
			key = corev1.TLSCertKey
		}
	}
	data, ok := secret.Data[key]
	if !ok {
		return nil, fmt.Errorf("missing key %s in secret %s/%s", key, obj.GetNamespace(), obj.GetName())
	}
	caCerts, _, err := cert.ParseRootCAs(data)
	if err != nil {
		return nil, err
	}
	if len(caCerts) == 0 {
		return nil, fmt.Errorf("%v %s/%s signing certificate is not a CA", secret.GetObjectKind().GroupVersionKind(), secret.GetNamespace(), secret.GetName())
	}

	now := time.Now()
	for _, caCert := range caCerts {
		if now.Before(caCert.NotBefore) {
			return nil, fmt.Errorf("%v %s/%s points a CA cert not valid before %v, now: %s", secret.GetObjectKind().GroupVersionKind(), secret.GetNamespace(), secret.GetName(), caCert.NotBefore, now)
		}
		if now.After(caCert.NotAfter) {
			return nil, fmt.Errorf("%v %s/%s points a CA cert expired at %v, now: %s", secret.GetObjectKind().GroupVersionKind(), secret.GetNamespace(), secret.GetName(), caCert.NotAfter, now)
		}
	}

	return caCerts, err
}
