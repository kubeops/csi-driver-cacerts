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

	"kubeops.dev/csi-driver-cacerts/pkg/providers/lib"

	"github.com/pkg/errors"
	"gomodules.xyz/cert"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const LEStagingServerURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

var (
	// see: https://letsencrypt.org/docs/staging-environment/

	// curl -L https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.pem
	LEStagingRootX1 string

	// curl -L https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x2.pem
	LEStagingRootX2 string
)

type AcmeStagingProvider struct {
	certs []*x509.Certificate
}

var _ lib.CAProvider = AcmeStagingProvider{}

func (a AcmeStagingProvider) GetCAs(_ client.Object, _ string) ([]*x509.Certificate, error) {
	return a.certs, nil
}

var DefaultAcmeStagingProvider = func() lib.CAProvider {
	var certs []*x509.Certificate
	if LEStagingRootX1 != "" {
		caCerts, _, err := cert.ParseRootCAs([]byte(LEStagingRootX1))
		if err != nil {
			panic(errors.Wrap(err, "failed to parse LEStagingRootX1"))
		}
		certs = append(certs, caCerts...)
	}
	if LEStagingRootX2 != "" {
		caCerts, _, err := cert.ParseRootCAs([]byte(LEStagingRootX2))
		if err != nil {
			panic(errors.Wrap(err, "failed to parse LEStagingRootX2"))
		}
		certs = append(certs, caCerts...)
	}
	return AcmeStagingProvider{certs: certs}
}()
