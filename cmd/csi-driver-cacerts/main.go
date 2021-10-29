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

package main

import (
	"flag"
	"os"

	api "kubeops.dev/csi-driver-cacerts/apis/cacerts/v1alpha1"
	cacertscontrollers "kubeops.dev/csi-driver-cacerts/pkg/controllers/cacerts"
	"kubeops.dev/csi-driver-cacerts/pkg/driver"

	cmscheme "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/scheme"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/klogr"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	endpoint   = flag.String("endpoint", "unix://tmp/csi.sock", "CSI endpoint")
	driverName = flag.String("drivername", "cacerts.csi.cert-manager.io", "name of the driver")
	nodeID     = flag.String("nodeid", "", "node id")

	scheme      = runtime.NewScheme()
	setupLog    = ctrl.Log.WithName("setup")
	metricsAddr = flag.String("metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	qps         = flag.Float64("qps", 100, "The maximum QPS to the master from this client")
	burst       = flag.Int("burst", 100, "The maximum burst for throttle")
)

func init() {
	_ = flag.Set("logtostderr", "true")

	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(cmscheme.AddToScheme(scheme))
	utilruntime.Must(api.AddToScheme(scheme))
}

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	ctrl.SetLogger(klogr.New())

	cfg := ctrl.GetConfigOrDie()
	cfg.QPS = float32(*qps)
	cfg.Burst = *burst
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     *metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: "", // csi driver runs its own probe sidecar
		LeaderElection:         false,
		LeaderElectionID:       "4ab6f271.cacerts.csi.cert-manager.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = (&cacertscontrollers.CAProviderClassReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "CAProviderClass")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	setupLog.Info("starting driver")
	d := driver.NewDriver(*driverName, *nodeID, *endpoint)
	d.Run(mgr)

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
