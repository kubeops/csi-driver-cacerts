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

package cacerts

import (
	"context"

	api "kubeops.dev/csi-driver-cacerts/apis/cacerts/v1alpha1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// CAProviderClassReconciler reconciles a CAProviderClass object
type CAProviderClassReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the CAProviderClass object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *CAProviderClassReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CAProviderClassReconciler) SetupWithManager(mgr ctrl.Manager) error {
	mf := func(gk schema.GroupKind) handler.MapFunc {
		return func(ctx context.Context, a client.Object) []reconcile.Request {
			providers := &api.CAProviderClassList{}
			if err := r.List(ctx, providers); err != nil {
				return nil
			}
			var req []reconcile.Request

			var ns string
			for _, p := range providers.Items {
				for _, ref := range p.Spec.Refs {
					var group string
					if ref.APIGroup != nil {
						group = *ref.APIGroup
					}
					if group != gk.Group ||
						ref.Kind != gk.Kind ||
						a.GetName() != ref.Name {
						continue
					}

					ns = ref.Namespace
					if ns == "" {
						ns = p.Namespace
					}

					if a.GetNamespace() != "" && a.GetNamespace() != ns {
						continue
					}

					req = append(req, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&p)})
					break
				}
			}
			return req
		}
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&api.CAProviderClass{}).
		Watches(&core.Secret{}, handler.EnqueueRequestsFromMapFunc(mf(schema.GroupKind{Group: "", Kind: "Secret"}))).
		Watches(&cmapi.Issuer{}, handler.EnqueueRequestsFromMapFunc(mf(schema.GroupKind{Group: cmapi.SchemeGroupVersion.Group, Kind: "Issuer"}))).
		Watches(&cmapi.ClusterIssuer{}, handler.EnqueueRequestsFromMapFunc(mf(schema.GroupKind{Group: cmapi.SchemeGroupVersion.Group, Kind: "ClusterIssuer"}))).
		Complete(r)
}
