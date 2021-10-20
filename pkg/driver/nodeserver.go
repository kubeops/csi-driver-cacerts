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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	csicommon "kubeops.dev/csi-driver-cacerts/pkg/csi-common"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"golang.org/x/net/context"
	ksets "gomodules.xyz/sets/kubernetes"
	"gomodules.xyz/x/ioutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	mount "k8s.io/mount-utils"
)

const (
	deviceID = "deviceID"
)

var (
	TimeoutError = fmt.Errorf("Timeout")
)

type nodeServer struct {
	*csicommon.DefaultNodeServer
	Timeout  time.Duration
	execPath string
	args     []string
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

	providerKeys := strings.FieldsFunc(caProviderClasses, func(r rune) bool {
		return r == ',' || r == ';'
	})
	providers := ksets.NewNamespacedName()
	for _, key := range providerKeys {
		if ns, name, err := cache.SplitMetaNamespaceKey(key); err != nil {
			klog.ErrorS(err, "invalid provider class", "podName", podName, "podNamespace", podNamespace, "volume", req.GetVolumeId(), "key", key)
		} else {
			if ns == "" {
				ns = podNamespace
			}
			providers.Insert(types.NamespacedName{
				Namespace: ns,
				Name:      name,
			})
		}
	}
	klog.InfoS("NodePublishVolume", "podName", podName, "podNamespace", podNamespace, "volume", req.GetVolumeId(), "key", providers.UnsortedList(), "stagingTargetPath", req.GetStagingTargetPath(), "targetPath", req.GetTargetPath())

	//err := ns.setupVolume(req.GetVolumeId(), image)
	//if err != nil {
	//	return nil, err
	//}

	targetPath := req.GetTargetPath()
	notMnt, err := mount.New("").IsLikelyNotMountPoint(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			if err = os.MkdirAll(targetPath, 0750); err != nil {
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
	*/

	if err = os.MkdirAll(filepath.Join(targetPath, "java"), 0755); err != nil {
		return nil, err
	}
	if err = ioutil.CopyFile(filepath.Join(targetPath, "ca-certificates.crt"), "/etc/ssl/certs/ca-certificates.crt"); err != nil {
		return nil, err
	}
	if err = ioutil.CopyFile(filepath.Join(targetPath, "java/cacerts"), "/etc/ssl/certs/java/cacerts"); err != nil {
		return nil, err
	}

	//options := []string{"bind"}
	//if readOnly {
	//	options = append(options, "ro")
	//}
	//
	//args := []string{"mount", volumeId}
	//ns.execPath = "/bin/buildah" // FIXME
	//output, err := ns.runCmd(args)
	//// FIXME handle failure.
	//provisionRoot := strings.TrimSpace(string(output[:]))
	//klog.V(4).Infof("container mount point at %s\n", provisionRoot)
	//
	//mounter := mount.New("")
	//path := provisionRoot
	//if err := mounter.Mount(path, targetPath, "", options); err != nil {
	//	return nil, err
	//}

	return &csi.NodePublishVolumeResponse{}, nil
}

func (ns *nodeServer) NodeUnpublishVolume(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {

	// Check arguments
	if len(req.GetVolumeId()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Volume ID missing in request")
	}
	if len(req.GetTargetPath()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Target path missing in request")
	}
	targetPath := req.GetTargetPath()
	volumeId := req.GetVolumeId()

	err := os.RemoveAll(req.GetTargetPath())

	// Unmounting the image
	// err := mount.New("").Unmount(req.GetTargetPath())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	klog.V(4).Infof("image: volume %s/%s has been unmounted.", targetPath, volumeId)

	//err = ns.unsetupVolume(volumeId)
	//if err != nil {
	//	return nil, err
	//}
	return &csi.NodeUnpublishVolumeResponse{}, nil
}

func (ns *nodeServer) setupVolume(volumeId string, image string) error {

	args := []string{"from", "--name", volumeId, "--pull", image}
	ns.execPath = "/bin/buildah" // FIXME
	output, err := ns.runCmd(args)
	// FIXME handle failure.
	// FIXME handle already deleted.
	provisionRoot := strings.TrimSpace(string(output[:]))
	// FIXME remove
	klog.V(4).Infof("container mount point at %s\n", provisionRoot)
	return err
}

func (ns *nodeServer) unsetupVolume(volumeId string) error {

	args := []string{"delete", volumeId}
	ns.execPath = "/bin/buildah" // FIXME
	output, err := ns.runCmd(args)
	// FIXME handle failure.
	// FIXME handle already deleted.
	provisionRoot := strings.TrimSpace(string(output[:]))
	// FIXME remove
	klog.V(4).Infof("container mount point at %s\n", provisionRoot)
	return err
}

func (ns *nodeServer) runCmd(args []string) ([]byte, error) {
	execPath := ns.execPath

	cmd := exec.Command(execPath, args...)

	timeout := false
	if ns.Timeout > 0 {
		timer := time.AfterFunc(ns.Timeout, func() {
			timeout = true
			// TODO: cmd.Stop()
		})
		defer timer.Stop()
	}

	output, execErr := cmd.CombinedOutput()
	if execErr != nil {
		if timeout {
			return nil, TimeoutError
		}
	}
	return output, execErr
}

func (ns *nodeServer) NodeUnstageVolume(ctx context.Context, req *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
	return &csi.NodeUnstageVolumeResponse{}, nil
}

func (ns *nodeServer) NodeStageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
	return &csi.NodeStageVolumeResponse{}, nil
}
