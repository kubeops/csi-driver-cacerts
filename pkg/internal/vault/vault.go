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

package vault

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	corev1 "k8s.io/api/core/v1"
	"kmodules.xyz/client-go/tools/configreader"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ Interface = &Vault{}

// ClientBuilder is a function type that returns a new Interface.
// Can be used in tests to create a mock signer of Vault certificate requests.
type ClientBuilder func(namespace string, secretsLister configreader.ConfigReader,
	issuer cmapi.GenericIssuer) (Interface, error)

// Interface implements various high level functionality related to connecting
// with a Vault server, verifying its status and signing certificate request for
// Vault's certificate.
// TODO: Sys() is duplicated here and in Client interface
type Interface interface {
	CA() (caPEM []byte, err error)
	Sign(csrPEM []byte, duration time.Duration) (certPEM []byte, caPEM []byte, err error)
	Sys() *vault.Sys
	IsVaultInitializedAndUnsealed() error
}

// Client implements functionality to talk to a Vault server.
type Client interface {
	NewRequest(method, requestPath string) *vault.Request
	RawRequest(r *vault.Request) (*vault.Response, error)
	SetToken(v string)
	Token() string
	Sys() *vault.Sys
}

// Vault implements Interface and holds a Vault issuer, secrets lister and a
// Vault client.
type Vault struct {
	reader    client.Reader
	issuer    cmapi.GenericIssuer
	namespace string

	client Client
}

// New returns a new Vault instance with the given namespace, issuer and
// secrets lister.
// Returned errors may be network failures and should be considered for
// retrying.
func New(namespace string, secretsLister client.Reader, issuer cmapi.GenericIssuer) (Interface, error) {
	v := &Vault{
		reader:    secretsLister,
		namespace: namespace,
		issuer:    issuer,
	}

	cfg, err := v.newConfig()
	if err != nil {
		return nil, err
	}

	vc, err := vault.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("error initializing Vault vc: %s", err.Error())
	}

	if err := v.setToken(vc); err != nil {
		return nil, err
	}

	v.client = vc

	return v, nil
}

func (v *Vault) CA() (ca []byte, err error) {
	vaultIssuer := v.issuer.GetSpec().Vault

	var p string
	// https://www.vaultproject.io/api/secret/pki#sign-certificate
	if idx := strings.LastIndex(vaultIssuer.Path, "/sign/"); idx != -1 {
		p = vaultIssuer.Path[:idx] + "/ca/pem"
	} else if idx := strings.LastIndex(vaultIssuer.Path, "/sign-verbatim"); idx != -1 {
		p = vaultIssuer.Path[:idx] + "/ca/pem"
	}
	if p == "" {
		return nil, fmt.Errorf("failed to detect PKI path from %s", vaultIssuer.Path)
	}
	url := path.Join("/cmapi", p)

	request := v.client.NewRequest("GET", url)

	v.addVaultNamespaceToRequest(request)

	resp, err := v.client.RawRequest(request)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate by vault: %s", err)
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// Sign will connect to a Vault instance to sign a certificate signing request.
func (v *Vault) Sign(csrPEM []byte, duration time.Duration) (cert []byte, ca []byte, err error) {
	csr, err := pki.DecodeX509CertificateRequestBytes(csrPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode CSR for signing: %s", err)
	}

	parameters := map[string]string{
		"common_name": csr.Subject.CommonName,
		"alt_names":   strings.Join(csr.DNSNames, ","),
		"ip_sans":     strings.Join(pki.IPAddressesToString(csr.IPAddresses), ","),
		"uri_sans":    strings.Join(pki.URLsToString(csr.URIs), ","),
		"ttl":         duration.String(),
		"csr":         string(csrPEM),

		"exclude_cn_from_sans": "true",
	}

	vaultIssuer := v.issuer.GetSpec().Vault
	url := path.Join("/cmapi", vaultIssuer.Path)

	request := v.client.NewRequest("POST", url)

	v.addVaultNamespaceToRequest(request)

	if err := request.SetJSONBody(parameters); err != nil {
		return nil, nil, fmt.Errorf("failed to build vault request: %s", err)
	}

	resp, err := v.client.RawRequest(request)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign certificate by vault: %s", err)
	}

	defer resp.Body.Close()

	vaultResult := certutil.Secret{}
	err = resp.DecodeJSON(&vaultResult)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode response returned by vault: %s", err)
	}

	return extractCertificatesFromVaultCertificateSecret(&vaultResult)
}

func (v *Vault) setToken(vc Client) error {
	tokenRef := v.issuer.GetSpec().Vault.Auth.TokenSecretRef
	if tokenRef != nil {
		token, err := v.tokenRef(tokenRef.Name, v.namespace, tokenRef.Key)
		if err != nil {
			return err
		}
		vc.SetToken(token)

		return nil
	}

	appRole := v.issuer.GetSpec().Vault.Auth.AppRole
	if appRole != nil {
		token, err := v.requestTokenWithAppRoleRef(vc, appRole)
		if err != nil {
			return err
		}
		vc.SetToken(token)

		return nil
	}

	kubernetesAuth := v.issuer.GetSpec().Vault.Auth.Kubernetes
	if kubernetesAuth != nil {
		token, err := v.requestTokenWithKubernetesAuth(vc, kubernetesAuth)
		if err != nil {
			return fmt.Errorf("error reading Kubernetes service account token from %s: %s", kubernetesAuth.SecretRef.Name, err.Error())
		}
		vc.SetToken(token)
		return nil
	}

	return fmt.Errorf("error initializing Vault vc: tokenSecretRef, appRoleSecretRef, or Kubernetes auth role not set")
}

func (v *Vault) newConfig() (*vault.Config, error) {
	cfg := vault.DefaultConfig()
	cfg.Address = v.issuer.GetSpec().Vault.Server

	certs := v.issuer.GetSpec().Vault.CABundle
	if len(certs) == 0 {
		return cfg, nil
	}

	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(certs)
	if !ok {
		return nil, fmt.Errorf("error loading Vault CA bundle")
	}

	cfg.HttpClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = caCertPool

	return cfg, nil
}

func (v *Vault) tokenRef(name, namespace, key string) (string, error) {
	var secret corev1.Secret
	err := v.reader.Get(context.TODO(), client.ObjectKey{Namespace: namespace, Name: name}, &secret)
	if err != nil {
		return "", err
	}

	if key == "" {
		key = cmapi.DefaultVaultTokenAuthSecretKey
	}

	keyBytes, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("no data for %q in secret '%s/%s'", key, name, namespace)
	}

	token := string(keyBytes)
	token = strings.TrimSpace(token)

	return token, nil
}

func (v *Vault) appRoleRef(appRole *cmapi.VaultAppRole) (roleId, secretId string, err error) {
	roleId = strings.TrimSpace(appRole.RoleId)

	var secret corev1.Secret
	err = v.reader.Get(context.TODO(), client.ObjectKey{Namespace: v.namespace, Name: appRole.SecretRef.Name}, &secret)
	if err != nil {
		return "", "", err
	}

	key := appRole.SecretRef.Key

	keyBytes, ok := secret.Data[key]
	if !ok {
		return "", "", fmt.Errorf("no data for %q in secret '%s/%s'", key, v.namespace, appRole.SecretRef.Name)
	}

	secretId = string(keyBytes)
	secretId = strings.TrimSpace(secretId)

	return roleId, secretId, nil
}

func (v *Vault) requestTokenWithAppRoleRef(vc Client, appRole *cmapi.VaultAppRole) (string, error) {
	roleId, secretId, err := v.appRoleRef(appRole)
	if err != nil {
		return "", err
	}

	parameters := map[string]string{
		"role_id":   roleId,
		"secret_id": secretId,
	}

	authPath := appRole.Path
	if authPath == "" {
		authPath = "approle"
	}

	url := path.Join("/cmapi", "auth", authPath, "login")

	request := vc.NewRequest("POST", url)

	err = request.SetJSONBody(parameters)
	if err != nil {
		return "", fmt.Errorf("error encoding Vault parameters: %s", err.Error())
	}

	v.addVaultNamespaceToRequest(request)

	resp, err := vc.RawRequest(request)
	if err != nil {
		return "", fmt.Errorf("error logging in to Vault server: %s", err.Error())
	}

	defer resp.Body.Close()

	vaultResult := vault.Secret{}
	if err := resp.DecodeJSON(&vaultResult); err != nil {
		return "", fmt.Errorf("unable to decode JSON payload: %s", err.Error())
	}

	token, err := vaultResult.TokenID()
	if err != nil {
		return "", fmt.Errorf("unable to read token: %s", err.Error())
	}

	if token == "" {
		return "", errors.New("no token returned")
	}

	return token, nil
}

func (v *Vault) requestTokenWithKubernetesAuth(vc Client, kubernetesAuth *cmapi.VaultKubernetesAuth) (string, error) {
	var secret corev1.Secret
	err := v.reader.Get(context.TODO(), client.ObjectKey{Namespace: v.namespace, Name: kubernetesAuth.SecretRef.Name}, &secret)
	if err != nil {
		return "", err
	}

	key := kubernetesAuth.SecretRef.Key
	if key == "" {
		key = cmapi.DefaultVaultTokenAuthSecretKey
	}

	keyBytes, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("no data for %q in secret '%s/%s'", key, v.namespace, kubernetesAuth.SecretRef.Name)
	}

	jwt := string(keyBytes)

	parameters := map[string]string{
		"role": kubernetesAuth.Role,
		"jwt":  jwt,
	}

	mountPath := kubernetesAuth.Path
	if mountPath == "" {
		mountPath = cmapi.DefaultVaultKubernetesAuthMountPath
	}

	url := filepath.Join(mountPath, "login")
	request := vc.NewRequest("POST", url)
	err = request.SetJSONBody(parameters)
	if err != nil {
		return "", fmt.Errorf("error encoding Vault parameters: %s", err.Error())
	}

	v.addVaultNamespaceToRequest(request)

	resp, err := vc.RawRequest(request)
	if err != nil {
		return "", fmt.Errorf("error calling Vault server: %s", err.Error())
	}

	defer resp.Body.Close()
	vaultResult := vault.Secret{}
	err = resp.DecodeJSON(&vaultResult)
	if err != nil {
		return "", fmt.Errorf("unable to decode JSON payload: %s", err.Error())
	}

	token, err := vaultResult.TokenID()
	if err != nil {
		return "", fmt.Errorf("unable to read token: %s", err.Error())
	}

	return token, nil
}

func (v *Vault) Sys() *vault.Sys {
	return v.client.Sys()
}

func extractCertificatesFromVaultCertificateSecret(secret *certutil.Secret) ([]byte, []byte, error) {
	parsedBundle, err := certutil.ParsePKIMap(secret.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode response returned by vault: %s", err)
	}

	vbundle, err := parsedBundle.ToCertBundle()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to convert certificate bundle to PEM bundle: %s", err.Error())
	}

	bundle, err := pki.ParseSingleCertificateChainPEM([]byte(
		strings.Join(append(
			vbundle.CAChain,
			vbundle.IssuingCA,
			vbundle.Certificate,
		), "\n")))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate chain from vault: %w", err)
	}

	return bundle.ChainPEM, bundle.CAPEM, nil
}

func (v *Vault) IsVaultInitializedAndUnsealed() error {
	healthURL := path.Join("/cmapi", "sys", "health")
	healthRequest := v.client.NewRequest("GET", healthURL)
	healthResp, err := v.client.RawRequest(healthRequest)

	if healthResp != nil {
		defer healthResp.Body.Close()
	}

	// 429 = if unsealed and standby
	// 472 = if disaster recovery mode replication secondary and active
	// 473 = if performance standby
	if err != nil {
		switch {
		case healthResp == nil:
			return err
		case healthResp.StatusCode == 429, healthResp.StatusCode == 472, healthResp.StatusCode == 473:
			return nil
		default:
			return fmt.Errorf("error calling Vault %s: %w", healthURL, err)
		}
	}

	return nil
}

func (v *Vault) addVaultNamespaceToRequest(request *vault.Request) {
	vaultIssuer := v.issuer.GetSpec().Vault
	if vaultIssuer != nil && vaultIssuer.Namespace != "" {
		if request.Headers != nil {
			request.Headers.Add("X-VAULT-NAMESPACE", vaultIssuer.Namespace)
		} else {
			vaultReqHeaders := http.Header{}
			vaultReqHeaders.Add("X-VAULT-NAMESPACE", vaultIssuer.Namespace)
			request.Headers = vaultReqHeaders
		}
	}
}
