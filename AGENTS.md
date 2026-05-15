# AGENTS.md

This file provides guidance to coding agents (e.g. Claude Code, claude.ai/code) when working with code in this repository.

## Repository purpose

Go module `kubeops.dev/csi-driver-cacerts` — an ephemeral CSI driver that **augments the OS trust store** of a pod with custom CA certificates pulled from Kubernetes secrets, ACME (Let's Encrypt), cert-manager `Issuer`s, or HashiCorp Vault PKI. Pod authors reference a `CAProviderClass` in their `csi` volume; this driver materializes the CA certs into the OS-specific trust files (`/etc/ssl/certs/ca-certificates.crt`, `/etc/ssl/certs/java/cacerts`, etc.), so the app inside the pod doesn't need to learn about a custom CA via env vars or `-k` flags.

The produced binary is `csi-driver-cacerts`. Runs as a DaemonSet alongside the kubelet's CSI plugin contract.

## Architecture

- `cmd/csi-driver-cacerts/` — entry point.
- `apis/cacerts/v1alpha1/` — `CAProviderClass` Kubebuilder types (`doc.go`, `groupversion_info.go`, types, `zz_generated.deepcopy.go`). API group is `cacerts.csi.cert-manager.io`.
- `client/` — generated typed clientset.
- `crds/` — generated CRDs for `CAProviderClass`.
- `pkg/driver/`:
  - `driver.go` — the CSI driver plumbing.
  - `nodeserver.go`, `nodeserver_test.go` — `NodeServer` implementation (where mount/unmount happens). On mount it asks providers for CA certs, writes them into the per-pod scratch dir, and updates the trust store files.
- `pkg/csi-common/` — shared CSI server plumbing (identity, controller, node stubs).
- `pkg/providers/` — **pluggable CA source backends**:
  - `secret.go` — Kubernetes `Secret` source.
  - `ca.go` — generic CA file source.
  - `acme-staging.go` — Let's Encrypt staging root.
  - `issuers.go` — cert-manager `Issuer` source.
  - `vault.go` — HashiCorp Vault PKI source.
  - `lib/` — shared provider helpers.
- `pkg/controllers/cacerts/` — controller-runtime reconciler watching `CAProviderClass` changes.
- `pkg/internal/` — internal helpers.
- `example/` — runnable example pod specs per OS family (`curl-alpine.yaml`, `curl-centos*.yaml`, `curl-debian.yaml`, `curl-fedora.yaml`, `curl-opensuse.yaml`, plus the cert + provider class manifests) — useful for verifying trust-store layout per distro.
- `Dockerfile.in` (PROD, distroless), `Dockerfile.dbg` (debian), `Dockerfile.ubi` (Red Hat certified) — three image variants.
- `PROJECT` — Kubebuilder metadata.
- `hack/`, `Makefile` — AppsCode build harness.
- `vendor/` — checked-in deps.

The driver knows about multiple OS-specific trust-store layouts; the `example/` directory doubles as a regression checklist when changing trust-store materialization.

## Common commands

All Make targets run inside `ghcr.io/appscode/golang-dev` — Docker must be running.

- `make ci` — CI pipeline.
- `make build` / `make all-build` — build host or all-platform binaries.
- `make gen` — regenerate clientset + CRDs. Run after changes to `apis/cacerts/v1alpha1/*_types.go`.
- `make manifests` — regenerate CRDs only.
- `make clientset` — regenerate `client/` only.
- `make fmt`, `make lint`, `make unit-tests` / `make test` — standard.
- `make verify` — `verify-gen verify-modules`; `go mod tidy && go mod vendor` must leave the tree clean.
- `make container` — build PROD, DBG, and UBI images.
- `make push` — push all three; `make docker-manifest` writes multi-arch manifests; `make release` is the full publish flow.
- `make push-to-kind` / `make deploy-to-kind` — load into Kind and Helm-install.
- `make install` / `make uninstall` / `make purge` — Helm install lifecycle.
- `make add-license` / `make check-license` — manage license headers.

Run a single Go test (requires a local Go toolchain):

```
go test ./pkg/driver/... -run TestName -v
```

## Conventions

- Module path is `kubeops.dev/csi-driver-cacerts` (vanity URL). Imports must use that.
- CRD API group is `cacerts.csi.cert-manager.io` (deliberately under the cert-manager CSI-driver namespace so it composes with other cert-manager CSI drivers); do not rename casually.
- License: see `LICENSE`. Sign off commits (`git commit -s`); contributions follow the DCO.
- Vendor directory is checked in — `go mod tidy && go mod vendor` must leave the tree clean (enforced by `verify-modules`).
- Adding a new CA source: drop a `pkg/providers/<name>.go` implementing the provider interface defined in `pkg/providers/lib/`. Don't sprinkle source-specific logic across `pkg/driver/nodeserver.go`.
- Do not hand-edit `zz_generated.*.go`, anything under `client/`, or `crds/` — change `apis/cacerts/v1alpha1/*_types.go` and re-run `make gen`.
- OS trust-store layouts vary; when adding a new layout (or fixing one), exercise it against the matching fixture in `example/curl-<distro>.yaml` and add a new fixture if needed.
- Three Dockerfiles, one binary — keep `Dockerfile.in`, `Dockerfile.dbg`, and `Dockerfile.ubi` in sync.
