/*
Copyright 2020 The cert-manager Authors.

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

	vaultinternal "kubeops.dev/csi-driver-cacerts/pkg/internal/vault"
	"kubeops.dev/csi-driver-cacerts/pkg/providers/lib"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"gomodules.xyz/cert"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	messageVaultClientInitFailed         = "Failed to initialize VaultProvider client: "
	messageVaultStatusVerificationFailed = "VaultProvider is not initialized or is sealed"
	messageVaultConfigRequired           = "VaultProvider config cannot be empty"
	messageServerAndPathRequired         = "VaultProvider server and path are required fields"
	messageAuthFieldsRequired            = "VaultProvider tokenSecretRef, appRole, or kubernetes is required"
	messageMultipleAuthFieldsSet         = "Multiple auth methods cannot be set on the same VaultProvider issuer"

	messageKubeAuthFieldsRequired    = "VaultProvider Kubernetes auth requires both role and secretRef.name"
	messageTokenAuthNameRequired     = "VaultProvider Token auth requires tokenSecretRef.name"
	messageAppRoleAuthFieldsRequired = "VaultProvider AppRole auth requires both roleId and tokenSecretRef.name"
)

type VaultProvider struct {
	reader client.Reader
	opts   IssuerOptions

	// Namespace in which to read resources related to this Issuer from.
	// For Issuers, this will be the namespace of the Issuer.
	// For ClusterIssuers, this will be the cluster resource namespace.
	resourceNamespace string
}

func NewVault(c client.Reader, opts IssuerOptions) (lib.CAProvider, error) {
	return &VaultProvider{
		reader: c,
		opts:   opts,
	}, nil
}

//// Register this Issuer with the issuer factory
//func init() {
//	issuer.RegisterIssuer(apiutil.IssuerVault, NewVault)
//}

type IssuerOptions struct {
	// ClusterResourceNamespace is the namespace to store resources created by
	// non-namespaced resources (e.g. ClusterIssuer) in.
	ClusterResourceNamespace string

	// ClusterIssuerAmbientCredentials controls whether a cluster issuer should
	// pick up ambient credentials, such as those from metadata services, to
	// construct clients.
	ClusterIssuerAmbientCredentials bool

	// IssuerAmbientCredentials controls whether an issuer should pick up ambient
	// credentials, such as those from metadata services, to construct clients.
	IssuerAmbientCredentials bool
}

func (o IssuerOptions) ResourceNamespace(iss cmapi.GenericIssuer) string {
	ns := iss.GetObjectMeta().Namespace
	if ns == "" {
		ns = o.ClusterResourceNamespace
	}
	return ns
}

func (v *VaultProvider) GetCAs(obj client.Object, _ string) ([]*x509.Certificate, error) {
	issuer, ok := obj.(cmapi.GenericIssuer)
	if !ok {
		return nil, fmt.Errorf("%v %s/%s is not a GenericIssuer", obj.GetObjectKind().GroupVersionKind(), obj.GetNamespace(), obj.GetName())
	}

	if issuer.GetSpec().Vault == nil {
		return nil, fmt.Errorf("%s: %s", issuer.GetObjectMeta().Name, messageVaultConfigRequired)
	}

	// check if VaultProvider server info is specified.
	if issuer.GetSpec().Vault.Server == "" ||
		issuer.GetSpec().Vault.Path == "" {
		return nil, fmt.Errorf("%s: %s", issuer.GetObjectMeta().Name, messageServerAndPathRequired)
	}

	tokenAuth := issuer.GetSpec().Vault.Auth.TokenSecretRef
	appRoleAuth := issuer.GetSpec().Vault.Auth.AppRole
	kubeAuth := issuer.GetSpec().Vault.Auth.Kubernetes

	// check if at least one auth method is specified.
	if tokenAuth == nil && appRoleAuth == nil && kubeAuth == nil {
		return nil, fmt.Errorf("%s: %s", issuer.GetObjectMeta().Name, messageAuthFieldsRequired)
	}

	// check only one auth method set
	if (tokenAuth != nil && appRoleAuth != nil) ||
		(tokenAuth != nil && kubeAuth != nil) ||
		(appRoleAuth != nil && kubeAuth != nil) {
		return nil, fmt.Errorf("%s: %s", issuer.GetObjectMeta().Name, messageMultipleAuthFieldsSet)
	}

	// check if all mandatory VaultProvider Token fields are set.
	if tokenAuth != nil && len(tokenAuth.Name) == 0 {
		return nil, fmt.Errorf("%s: %s", issuer.GetObjectMeta().Name, messageTokenAuthNameRequired)
	}

	// check if all mandatory VaultProvider appRole fields are set.
	if appRoleAuth != nil && (len(appRoleAuth.RoleId) == 0 || len(appRoleAuth.SecretRef.Name) == 0) {
		return nil, fmt.Errorf("%s: %s", issuer.GetObjectMeta().Name, messageAppRoleAuthFieldsRequired)
	}

	// check if all mandatory VaultProvider Kubernetes fields are set.
	if kubeAuth != nil && (len(kubeAuth.SecretRef.Name) == 0 || len(kubeAuth.Role) == 0) {
		return nil, fmt.Errorf("%s: %s", issuer.GetObjectMeta().Name, messageKubeAuthFieldsRequired)
	}

	vc, err := vaultinternal.New(v.resourceNamespace, v.reader, issuer)
	if err != nil {
		s := messageVaultClientInitFailed + err.Error()
		return nil, fmt.Errorf("%s: %s", issuer.GetObjectMeta().Name, s)
	}

	if err := vc.IsVaultInitializedAndUnsealed(); err != nil {
		return nil, fmt.Errorf("%s: %s: error: %s", issuer.GetObjectMeta().Name, messageVaultStatusVerificationFailed, err.Error())
	}

	caPEM, err := vc.CA()
	if err != nil {
		return nil, err
	}
	caCerts, _, err := cert.ParseRootCAs(caPEM)
	if err != nil {
		return nil, err
	}
	if len(caCerts) == 0 {
		return nil, fmt.Errorf("%v %s/%s signing certificate is not a CA", issuer.GetObjectKind().GroupVersionKind(), issuer.GetNamespace(), issuer.GetName())
	}

	now := time.Now()
	for _, caCert := range caCerts {
		if now.Before(caCert.NotBefore) {
			return nil, fmt.Errorf("%v %s/%s points a CA cert not valid before %v, now: %s", issuer.GetObjectKind().GroupVersionKind(), issuer.GetNamespace(), issuer.GetName(), caCert.NotBefore, now)
		}
		if now.After(caCert.NotAfter) {
			return nil, fmt.Errorf("%v %s/%s points a CA cert expired at %v, now: %s", issuer.GetObjectKind().GroupVersionKind(), issuer.GetNamespace(), issuer.GetName(), caCert.NotAfter, now)
		}
	}

	return caCerts, err
}
