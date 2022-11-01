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
	"fmt"

	api "kubeops.dev/csi-driver-cacerts/apis/cacerts/v1alpha1"
	"kubeops.dev/csi-driver-cacerts/pkg/providers/lib"

	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewCAProvider(c client.Client, ref api.ObjectRef, obj client.Object) (lib.CAProvider, error) {
	switch ref.GroupKind() {
	case schema.GroupKind{Kind: "Secret"}:
		return new(SecretProvider), nil
	case schema.GroupKind{Group: certmanager.GroupName, Kind: "Issuer"},
		schema.GroupKind{Group: certmanager.GroupName, Kind: "ClusterIssuer"}:
		issuer, ok := obj.(cmapi.GenericIssuer)
		if !ok {
			return nil, fmt.Errorf("unknow obj ref %+v", ref)
		}
		spec := issuer.GetSpec()
		if spec.CA != nil {
			return &IssuerProvider{Reader: c}, nil
		} else if spec.ACME != nil && spec.ACME.Server == LEStagingServerURL {
			return DefaultAcmeStagingProvider, nil
		}
	}
	return nil, fmt.Errorf("unknow obj ref %+v", ref)
}
