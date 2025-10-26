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
	csicommon "kubeops.dev/csi-driver-cacerts/pkg/csi-common"
	"kubeops.dev/csi-driver-cacerts/pkg/providers"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"k8s.io/klog/v2"
	"kmodules.xyz/selinux"
	ctrl "sigs.k8s.io/controller-runtime"
)

type driver struct {
	csiDriver *csicommon.CSIDriver
	endpoint  string
}

var version = "0.0.1"

func NewDriver(driverName, nodeID, endpoint string) *driver {
	klog.Infof("Driver: %v version: %v", driverName, version)

	d := &driver{}

	d.endpoint = endpoint

	csiDriver := csicommon.NewCSIDriver(driverName, version, nodeID)
	// FIX(tamal): correct?
	csiDriver.AddVolumeCapabilityAccessModes([]csi.VolumeCapability_AccessMode_Mode{csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY})
	// image plugin does not support ControllerServiceCapability now.
	// If support is added, it should set to appropriate
	// ControllerServiceCapability RPC types.
	csiDriver.AddControllerServiceCapabilities([]csi.ControllerServiceCapability_RPC_Type{csi.ControllerServiceCapability_RPC_UNKNOWN})

	d.csiDriver = csiDriver

	return d
}

func NewNodeServer(d *csicommon.CSIDriver, mgr ctrl.Manager, opts providers.IssuerOptions) csi.NodeServer {
	return &nodeServer{
		DefaultNodeServer: csicommon.NewDefaultNodeServer(d),
		mgr:               mgr,
		opts:              opts,
		translator:        selinux.NewSELinuxLabelTranslator(),
	}
}

func (d *driver) Run(mgr ctrl.Manager, opts providers.IssuerOptions) {
	s := csicommon.NewNonBlockingGRPCServer()
	s.Start(d.endpoint,
		csicommon.NewDefaultIdentityServer(d.csiDriver),
		csicommon.NewDefaultControllerServer(d.csiDriver),
		NewNodeServer(d.csiDriver, mgr, opts))
	// FIX(tamal): Don't wait because we need to start the controller
	// s.Wait()
}
