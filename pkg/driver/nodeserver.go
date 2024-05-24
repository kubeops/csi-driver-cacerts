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

package driver

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	api "kubeops.dev/csi-driver-cacerts/apis/cacerts/v1alpha1"
	csicommon "kubeops.dev/csi-driver-cacerts/pkg/csi-common"
	"kubeops.dev/csi-driver-cacerts/pkg/providers"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/pkg/errors"
	"github.com/zeebo/xxh3"
	"golang.org/x/net/context"
	atomic_writer "gomodules.xyz/atomic-writer"
	"gomodules.xyz/cert"
	ksets "gomodules.xyz/sets/kubernetes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	mount "k8s.io/mount-utils"
	clientx "kmodules.xyz/client-go/client"
	ctrl "sigs.k8s.io/controller-runtime"
)

// https://manuals.gfi.com/en/kerio/connect/content/server-configuration/ssl-certificates/adding-trusted-root-certificates-to-the-server-1605.html

/*

- https://serverfault.com/a/722646/167143
- https://golang.org/src/crypto/x509/root_linux.go
- https://golang.org/src/crypto/x509/root_unix.go
- https://www.unix.com/man-page/centos/8/update-ca-trust/

This is where Go looks for public root certificates:

"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
"/etc/pki/tls/cacert.pem",                           // OpenELEC
"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
"/etc/ssl/cert.pem",                                 // Alpine Linux
Also:

"/etc/ssl/certs",               // SLES10/SLES11, https://golang.org/issue/12139
"/system/etc/security/cacerts", // Android
"/usr/local/share/certs",       // FreeBSD
"/etc/pki/tls/certs",           // Fedora/RHEL
"/etc/openssl/certs",           // NetBSD
"/var/ssl/certs",               // AIX

*/

type OsFamily string

const (
	OsFamilyDebian       OsFamily = "debian"
	OsFamilyUbuntu       OsFamily = "ubuntu"
	OsFamilyAlpine       OsFamily = "alpine"
	OsFamilyOpensuse     OsFamily = "opensuse"
	OsFamilyFedora       OsFamily = "fedora"
	OsFamilyCentos       OsFamily = "centos"
	OsFamilyCentos6      OsFamily = "centos-6"
	OsFamilyOracleLinux  OsFamily = "oraclelinux"
	OsFamilyOracleLinux6 OsFamily = "oraclelinux-6"
	OsFamilyRockyLinux   OsFamily = "rockylinux"
)

const (
	cacertsGeneric = "ca-certificates.crt"
	cacertsJava    = "java/cacerts"
	deviceID       = "deviceID"
)

var (
	osFamilies = sets.NewString(
		string(OsFamilyDebian),
		string(OsFamilyUbuntu),
		string(OsFamilyAlpine),
		string(OsFamilyOpensuse),
		string(OsFamilyFedora),
		string(OsFamilyCentos),
		string(OsFamilyCentos6),
		string(OsFamilyOracleLinux),
		string(OsFamilyOracleLinux6),
		string(OsFamilyRockyLinux),
	)
	javaCertStorePassword = []byte("changeit")
)

type nodeServer struct {
	*csicommon.DefaultNodeServer
	Timeout time.Duration

	mgr  ctrl.Manager
	opts providers.IssuerOptions
}

func (ns *nodeServer) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	// Check arguments
	if req.GetVolumeCapability() == nil {
		return nil, status.Error(codes.InvalidArgument, "Volume capability missing in request")
	}
	if len(req.GetVolumeId()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Volume ID missing in request")
	}
	if len(req.GetTargetPath()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Target path missing in request")
	}
	if req.GetVolumeContext()["csi.storage.k8s.io/ephemeral"] != "true" {
		return nil, fmt.Errorf("only ephemeral volume types are supported")
	}
	if !req.GetReadonly() {
		return nil, status.Error(codes.InvalidArgument, "pod.spec.volumes[].csi.readOnly must be set to 'true'")
	}

	// fsGroup
	/*
		csi.storage.k8s.io/pod.name: {pod.Name}
		csi.storage.k8s.io/pod.namespace: {pod.Namespace}
		csi.storage.k8s.io/pod.uid: {pod.UID}
		csi.storage.k8s.io/serviceAccount.name: {pod.Spec.ServiceAccountName}
	*/
	podName := req.GetVolumeContext()["csi.storage.k8s.io/pod.name"]
	podNamespace := req.GetVolumeContext()["csi.storage.k8s.io/pod.namespace"]

	caProviderClasses := req.GetVolumeContext()["caProviderClasses"]
	fmt.Println(caProviderClasses) // secret and ca cert names

	osFamily := strings.ToLower(strings.TrimSpace(req.GetVolumeContext()["os"]))
	fmt.Println(osFamily)
	if osFamily == "" {
		return nil, status.Errorf(codes.InvalidArgument, "pod.spec.volumes[].csi.volumeAttributes.os must be set to one of [%s]", strings.Join(osFamilies.List(), ", "))
	}
	if !osFamilies.Has(osFamily) {
		return nil, status.Errorf(codes.InvalidArgument, "pod.spec.volumes[].csi.volumeAttributes.os must be set to one of [%s]", strings.Join(osFamilies.List(), ", "))
	}

	providerKeys := strings.FieldsFunc(caProviderClasses, func(r rune) bool {
		return r == ',' || r == ';' || unicode.IsSpace(r)
	})
	providerNames := ksets.NewNamespacedName()
	for _, key := range providerKeys {
		if ns, name, err := cache.SplitMetaNamespaceKey(key); err != nil {
			klog.ErrorS(err, "invalid provider class", "podName", podName, "podNamespace", podNamespace, "volume", req.GetVolumeId(), "key", key)
		} else {
			if ns == "" {
				ns = podNamespace
			}
			providerNames.Insert(types.NamespacedName{
				Namespace: ns,
				Name:      name,
			})
		}
	}
	klog.InfoS("NodePublishVolume", "podName", podName, "podNamespace", podNamespace, "volume", req.GetVolumeId(), "key", providerNames.UnsortedList(), "stagingTargetPath", req.GetStagingTargetPath(), "targetPath", req.GetTargetPath())

	targetPath := req.GetTargetPath()
	notMnt, err := mount.New("").IsLikelyNotMountPoint(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			if err = os.MkdirAll(targetPath, 0o555); err != nil {
				return nil, status.Error(codes.Internal, err.Error())
			}
			notMnt = true
		} else {
			return nil, status.Error(codes.Internal, err.Error())
		}
	}

	if !notMnt {
		return &csi.NodePublishVolumeResponse{}, nil
	}

	fsType := req.GetVolumeCapability().GetMount().GetFsType()

	deviceId := ""
	if req.GetPublishContext() != nil {
		deviceId = req.GetPublishContext()[deviceID]
	}

	readOnly := req.GetReadonly()
	volumeId := req.GetVolumeId()
	attrib := req.GetVolumeContext()
	mountFlags := req.GetVolumeCapability().GetMount().GetMountFlags()

	klog.V(4).Infof("target %v\nfstype %v\ndevice %v\nreadonly %v\nvolumeId %v\nattributes %v\n mountflags %v\n",
		targetPath, fsType, deviceId, readOnly, volumeId, attrib, mountFlags)

	/*
		/etc/ssl/certs/java/cacerts
		/etc/ssl/certs/ca-certificates.crt
		/etc/ssl/certs/ca-bundle.trust.crt
	*/

	caProviders := make([]api.CAProviderClass, 0, providerNames.Len())
	for _, key := range providerNames.UnsortedList() {
		var pc api.CAProviderClass
		err = ns.mgr.GetClient().Get(context.TODO(), key, &pc)
		if err != nil {
			return nil, err
		}
		caProviders = append(caProviders, pc)
	}

	certs, err := ns.fetchCAcerts(caProviders)
	if err != nil {
		return nil, err
	}

	err = updateCACerts(certs, OsFamily(osFamily), "/etc/ssl/certs", targetPath)
	return &csi.NodePublishVolumeResponse{}, err
}

func (ns *nodeServer) NodeUnpublishVolume(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	return &csi.NodeUnpublishVolumeResponse{}, nil
}

func (ns *nodeServer) NodeUnstageVolume(ctx context.Context, req *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
	return &csi.NodeUnstageVolumeResponse{}, nil
}

func (ns *nodeServer) NodeStageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
	return &csi.NodeStageVolumeResponse{}, nil
}

func hashCertificate(cert *x509.Certificate) string {
	hash := sha1.Sum(cert.RawSubject)
	return hex.EncodeToString(hash[:])[:8]
}

func (ns *nodeServer) fetchCAcerts(caProviders []api.CAProviderClass) (map[uint64]*x509.Certificate, error) {
	certs := map[uint64]*x509.Certificate{}
	for _, pc := range caProviders {
		for _, typedRef := range pc.Spec.Refs {
			ref := api.RefFrom(pc, typedRef)
			obj, err := clientx.GetForGVK(context.TODO(), ns.mgr.GetClient(), ref.GroupKind().WithVersion(""), ref.ObjKey())
			if err != nil {
				return nil, err
			}

			p, err := providers.NewCAProvider(ns.mgr.GetClient(), ns.opts, ref, obj)
			if err != nil {
				return nil, err
			}
			cas, err := p.GetCAs(obj, ref.Key)
			if err != nil {
				return nil, err
			}
			for _, ca := range cas {
				// https://stackoverflow.com/a/9104143
				certs[xxh3.Hash(ca.Raw)] = ca
			}
		}
	}
	return certs, nil
}

func updateCACerts(certs map[uint64]*x509.Certificate, osFamily OsFamily, srcDir, targetDir string) error {
	certIds := make([]uint64, 0, len(certs))
	for id := range certs {
		certIds = append(certIds, id)
	}
	sort.Slice(certIds, func(i, j int) bool {
		return certIds[i] < certIds[j]
	})

	filename := filepath.Join(srcDir, cacertsJava)
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	ks := keystore.New()

	if err := ks.Load(f, javaCertStorePassword); err != nil {
		return err
	}
	for _, alias := range ks.Aliases() {
		if crt, err := ks.GetTrustedCertificateEntry(alias); err != nil {
			return err
		} else {
			fmt.Printf("%s: %s %s\n", alias, crt.Certificate.Type, crt.CreationTime)
		}
	}
	for _, certId := range certIds {
		ca := certs[certId]
		err := ks.SetTrustedCertificateEntry(fmt.Sprintf("%d", certId), keystore.TrustedCertificateEntry{
			CreationTime: ca.NotBefore,
			Certificate: keystore.Certificate{
				Type:    "X.509",
				Content: ca.Raw,
			},
		})
		if err != nil {
			return err
		}
	}

	// /etc/ssl/certs/ca-bundle.trust.crt
	trsutData, err := os.ReadFile(filepath.Join(srcDir, "ca-bundle.trust.crt"))
	if err != nil {
		return err
	}

	var javaBuf bytes.Buffer
	if err := ks.Store(&javaBuf, javaCertStorePassword); err != nil {
		return err
	}

	payload := map[string]atomic_writer.FileProjection{}

	switch osFamily {
	case OsFamilyDebian, OsFamilyUbuntu, OsFamilyAlpine, OsFamilyOpensuse:
		entries, err := os.ReadDir(srcDir)
		if err != nil {
			return errors.Wrap(err, "error reading directory "+srcDir)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() ||
				name == "ca-certificates.crt" ||
				name == "ca-bundle.pem" {
				continue
			}

			data, err := os.ReadFile(filepath.Join(srcDir, name))
			if err != nil {
				return err
			}
			payload[name] = atomic_writer.FileProjection{Data: data, Mode: 0o444}
		}
	}

	var caBuf bytes.Buffer
	caData, err := os.ReadFile(filepath.Join(srcDir, cacertsGeneric))
	if err != nil {
		return err
	}
	caBuf.Write(caData)

	var pemBuf bytes.Buffer
	for _, certId := range certIds {
		ca := certs[certId]
		block := pem.Block{
			Type:  cert.CertificateBlockType,
			Bytes: ca.Raw,
		}

		pemBuf.Reset()
		err := pem.Encode(&pemBuf, &block)
		if err != nil {
			return err
		}

		switch osFamily {
		case OsFamilyDebian, OsFamilyUbuntu, OsFamilyAlpine, OsFamilyOpensuse:
			// https://www.openssl.org/docs/man3.0/man1/openssl-rehash.html
			// https://chatgpt.com/share/dc051bec-7cc5-4ddf-82bf-6a0235efee48
			payload[fmt.Sprintf("%s.0", hashCertificate(ca))] = atomic_writer.FileProjection{Data: pemBuf.Bytes(), Mode: 0o444}
		}

		caBuf.Write(pemBuf.Bytes())
	}

	err = os.MkdirAll(targetDir, 0o755)
	if err != nil {
		return err
	}
	certWriter, err := atomic_writer.NewAtomicWriter(targetDir, "cacerts-csi-driver")
	if err != nil {
		return err
	}

	var capayload map[string]atomic_writer.FileProjection
	switch osFamily {
	case OsFamilyDebian, OsFamilyUbuntu, OsFamilyAlpine:
		capayload = map[string]atomic_writer.FileProjection{
			"ca-certificates.crt": {Data: caBuf.Bytes(), Mode: 0o444},
			"java/cacerts":        {Data: javaBuf.Bytes(), Mode: 0o444},
		}
	case OsFamilyOpensuse:
		capayload = map[string]atomic_writer.FileProjection{
			"ca-bundle.pem": {Data: caBuf.Bytes(), Mode: 0o444},
			"java-cacerts":  {Data: javaBuf.Bytes(), Mode: 0o444},
		}
	case OsFamilyFedora, OsFamilyCentos, OsFamilyOracleLinux, OsFamilyRockyLinux:
		capayload = map[string]atomic_writer.FileProjection{
			"pem/tls-ca-bundle.pem":       {Data: caBuf.Bytes(), Mode: 0o444},
			"java/cacerts":                {Data: javaBuf.Bytes(), Mode: 0o444},
			"openssl/ca-bundle.trust.crt": {Data: trsutData, Mode: 0o444},
		}
	case OsFamilyCentos6, OsFamilyOracleLinux6:
		capayload = map[string]atomic_writer.FileProjection{
			"tls/cert.pem":                                   {Data: caBuf.Bytes(), Mode: 0o444},
			"tls/certs/ca-bundle.crt":                        {Data: caBuf.Bytes(), Mode: 0o444},
			"ca-trust/extracted/pem/tls-ca-bundle.pem":       {Data: caBuf.Bytes(), Mode: 0o444},
			"java/cacerts":                                   {Data: javaBuf.Bytes(), Mode: 0o444},
			"ca-trust/extracted/java/cacerts":                {Data: javaBuf.Bytes(), Mode: 0o444},
			"ca-trust/extracted/openssl/ca-bundle.trust.crt": {Data: trsutData, Mode: 0o444},
			"tls/certs/ca-bundle.trust.crt":                  {Data: trsutData, Mode: 0o444},
		}
	}
	for k, v := range capayload {
		payload[k] = v
	}

	_, err = certWriter.Write(payload)
	if err != nil {
		return err
	}
	return nil
}
