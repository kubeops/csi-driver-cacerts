# Copyright AppsCode Inc. and Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

SHELL=/bin/bash -o pipefail

PRODUCT_OWNER_NAME := appscode
PRODUCT_NAME       := csi-driver-cacerts
ENFORCE_LICENSE    ?=

GO_PKG   := kubeops.dev
REPO     := $(notdir $(shell pwd))
BIN      := csi-driver-cacerts
COMPRESS ?= no

# Produce CRDs that work back to Kubernetes 1.11 (no version conversion)
CRD_OPTIONS          ?= "crd:crdVersions={v1},allowDangerousTypes=true"
CODE_GENERATOR_IMAGE ?= ghcr.io/appscode/gengo:release-1.32
API_GROUPS           ?= cacerts:v1alpha1

# Where to push the docker image.
REGISTRY ?= ghcr.io/appscode
SRC_REG  ?=

# This version-strategy uses git tags to set the version string
git_branch       := $(shell git rev-parse --abbrev-ref HEAD)
git_tag          := $(shell git describe --exact-match --abbrev=0 2>/dev/null || echo "")
commit_hash      := $(shell git rev-parse --verify HEAD)
commit_timestamp := $(shell date --date="@$$(git show -s --format=%ct)" --utc +%FT%T)

VERSION          := $(shell git describe --tags --always --dirty)
version_strategy := commit_hash
ifdef git_tag
	VERSION := $(git_tag)
	version_strategy := tag
else
	ifeq (,$(findstring $(git_branch),master HEAD))
		ifneq (,$(patsubst release-%,,$(git_branch)))
			VERSION := $(git_branch)
			version_strategy := branch
		endif
	endif
endif

###
### These variables should not need tweaking.
###

SRC_PKGS := apis client cmd crds pkg # directories which hold app source excluding tests (not vendored)
SRC_DIRS := $(SRC_PKGS) # directories which hold app source (not vendored)

DOCKER_PLATFORMS := linux/amd64 linux/arm64
BIN_PLATFORMS    := $(DOCKER_PLATFORMS)

# Used internally.  Users should pass GOOS and/or GOARCH.
OS   := $(if $(GOOS),$(GOOS),$(shell go env GOOS))
ARCH := $(if $(GOARCH),$(GOARCH),$(shell go env GOARCH))

# BASEIMAGE_PROD ?= gcr.io/distroless/static-debian12
BASEIMAGE_PROD   ?= debian:12
BASEIMAGE_DBG    ?= debian:12

IMAGE            := $(REGISTRY)/$(BIN)
VERSION_PROD     := $(VERSION)
VERSION_DBG      := $(VERSION)-dbg
TAG              := $(VERSION)_$(OS)_$(ARCH)
TAG_PROD         := $(TAG)
TAG_DBG          := $(VERSION)-dbg_$(OS)_$(ARCH)

GO_VERSION       ?= 1.24
BUILD_IMAGE      ?= ghcr.io/appscode/golang-dev:$(GO_VERSION)
CHART_TEST_IMAGE ?= quay.io/helmpack/chart-testing:v3.11.0

OUTBIN = bin/$(OS)_$(ARCH)/$(BIN)
ifeq ($(OS),windows)
  OUTBIN = bin/$(OS)_$(ARCH)/$(BIN).exe
endif

# Directories that we need created to build/test.
BUILD_DIRS  := bin/$(OS)_$(ARCH)     \
               .go/bin/$(OS)_$(ARCH) \
               .go/cache             \
               hack/config           \
               $(HOME)/.credentials  \
               $(HOME)/.kube         \
               $(HOME)/.minikube

DOCKERFILE_PROD  = Dockerfile.in
DOCKERFILE_DBG   = Dockerfile.dbg

DOCKER_REPO_ROOT := /go/src/$(GO_PKG)/$(REPO)

# If you want to build all binaries, see the 'all-build' rule.
# If you want to build all containers, see the 'all-container' rule.
# If you want to build AND push all containers, see the 'all-push' rule.
all: fmt build

# For the following OS/ARCH expansions, we transform OS/ARCH into OS_ARCH
# because make pattern rules don't match with embedded '/' characters.

build-%:
	@$(MAKE) build                        \
	    --no-print-directory              \
	    GOOS=$(firstword $(subst _, ,$*)) \
	    GOARCH=$(lastword $(subst _, ,$*))

container-%:
	@$(MAKE) container                    \
	    --no-print-directory              \
	    GOOS=$(firstword $(subst _, ,$*)) \
	    GOARCH=$(lastword $(subst _, ,$*))

push-%:
	@$(MAKE) push                         \
	    --no-print-directory              \
	    GOOS=$(firstword $(subst _, ,$*)) \
	    GOARCH=$(lastword $(subst _, ,$*))

all-build: $(addprefix build-, $(subst /,_, $(BIN_PLATFORMS)))

all-container: $(addprefix container-, $(subst /,_, $(DOCKER_PLATFORMS)))

all-push: $(addprefix push-, $(subst /,_, $(DOCKER_PLATFORMS)))

version:
	@echo ::set-output name=version::$(VERSION)
	@echo ::set-output name=version_strategy::$(version_strategy)
	@echo ::set-output name=git_tag::$(git_tag)
	@echo ::set-output name=git_branch::$(git_branch)
	@echo ::set-output name=commit_hash::$(commit_hash)
	@echo ::set-output name=commit_timestamp::$(commit_timestamp)

# Generate code for Kubernetes types
.PHONY: clientset
clientset:
	@docker run --rm                                            \
		-u $$(id -u):$$(id -g)                                    \
		-v /tmp:/.cache                                           \
		-v $$(pwd):$(DOCKER_REPO_ROOT)                            \
		-w $(DOCKER_REPO_ROOT)                                    \
		--env HTTP_PROXY=$(HTTP_PROXY)                            \
		--env HTTPS_PROXY=$(HTTPS_PROXY)                          \
		$(CODE_GENERATOR_IMAGE)                                   \
		/go/src/k8s.io/code-generator/generate-groups.sh          \
			"deepcopy,defaulter"                                    \
			$(GO_PKG)/$(REPO)/client                                \
			$(GO_PKG)/$(REPO)/apis                                  \
			"$(API_GROUPS)"                                         \
			--go-header-file "./hack/license/go.txt"

# Generate openapi schema
.PHONY: openapi
openapi: $(addprefix openapi-, $(subst :,_, $(API_GROUPS)))
openapi-%:
	@echo "Generating openapi schema for $(subst _,/,$*)"
	@mkdir -p .config/api-rules
	@docker run --rm                                     \
		-u $$(id -u):$$(id -g)                           \
		-v /tmp:/.cache                                  \
		-v $$(pwd):$(DOCKER_REPO_ROOT)                   \
		-w $(DOCKER_REPO_ROOT)                           \
		--env HTTP_PROXY=$(HTTP_PROXY)                   \
		--env HTTPS_PROXY=$(HTTPS_PROXY)                 \
		$(CODE_GENERATOR_IMAGE)                          \
		openapi-gen                                      \
			--v 1 --logtostderr                          \
			--go-header-file "./hack/license/go.txt" \
			--input-dirs "$(GO_PKG)/$(REPO)/apis/$(subst _,/,$*),k8s.io/apimachinery/pkg/apis/meta/v1,k8s.io/apimachinery/pkg/api/resource,k8s.io/apimachinery/pkg/runtime,k8s.io/apimachinery/pkg/util/intstr,k8s.io/apimachinery/pkg/version,k8s.io/api/core/v1,k8s.io/api/apps/v1,k8s.io/api/rbac/v1,kmodules.xyz/client-go/api/v1" \
			--output-package "$(GO_PKG)/$(REPO)/apis/$(subst _,/,$*)" \
			--report-filename .config/api-rules/violation_exceptions.list

# Generate CRD manifests
.PHONY: gen-crds
gen-crds:
	@echo "Generating CRD manifests"
	@docker run --rm	                    \
		-u $$(id -u):$$(id -g)              \
		-v /tmp:/.cache                     \
		-v $$(pwd):$(DOCKER_REPO_ROOT)      \
		-w $(DOCKER_REPO_ROOT)              \
	    --env HTTP_PROXY=$(HTTP_PROXY)      \
	    --env HTTPS_PROXY=$(HTTPS_PROXY)    \
		$(CODE_GENERATOR_IMAGE)             \
		controller-gen                      \
			$(CRD_OPTIONS)                  \
			paths="./apis/..."              \
			output:crd:artifacts:config=crds

crds_to_patch := cacerts.csi.cert-manager.io_caproviderclasses.yaml

.PHONY: patch-crds
patch-crds: $(addprefix patch-crd-, $(crds_to_patch))
patch-crd-%: $(BUILD_DIRS)
	@echo "patching $*"
	@kubectl patch -f crds/$* -p "$$(cat hack/crd-patch.json)" --type=json --local=true -o yaml > bin/$*
	@mv bin/$* crds/$*

.PHONY: label-crds
label-crds: $(BUILD_DIRS)
	@for f in crds/*.yaml; do \
		echo "applying app.kubernetes.io/name=cert-manager label to $$f"; \
		kubectl label --overwrite -f $$f --local=true -o yaml app.kubernetes.io/name=cert-manager > bin/crd.yaml; \
		mv bin/crd.yaml $$f; \
	done

.PHONY: manifests
manifests: gen-crds patch-crds label-crds

.PHONY: gen
gen: clientset manifests openapi

fmt: $(BUILD_DIRS)
	@docker run                                                 \
	    -i                                                      \
	    --rm                                                    \
	    -u $$(id -u):$$(id -g)                                  \
	    -v $$(pwd):/src                                         \
	    -w /src                                                 \
	    -v $$(pwd)/.go/bin/$(OS)_$(ARCH):/go/bin                \
	    -v $$(pwd)/.go/bin/$(OS)_$(ARCH):/go/bin/$(OS)_$(ARCH)  \
	    -v $$(pwd)/.go/cache:/.cache                            \
	    --env HTTP_PROXY=$(HTTP_PROXY)                          \
	    --env HTTPS_PROXY=$(HTTPS_PROXY)                        \
	    $(BUILD_IMAGE)                                          \
	    /bin/bash -c "                                          \
	        REPO_PKG=$(GO_PKG)                                  \
	        ./hack/fmt.sh $(SRC_DIRS)                           \
	    "

build: $(OUTBIN)

# The following structure defeats Go's (intentional) behavior to always touch
# result files, even if they have not changed.  This will still run `go` but
# will not trigger further work if nothing has actually changed.

$(OUTBIN): .go/$(OUTBIN).stamp
	@true

# This will build the binary under ./.go and update the real binary iff needed.
.PHONY: .go/$(OUTBIN).stamp
.go/$(OUTBIN).stamp: $(BUILD_DIRS)
	@echo "making $(OUTBIN)"
	@docker run                                                 \
	    -i                                                      \
	    --rm                                                    \
	    -u $$(id -u):$$(id -g)                                  \
	    -v $$(pwd):/src                                         \
	    -w /src                                                 \
	    -v $$(pwd)/.go/bin/$(OS)_$(ARCH):/go/bin                \
	    -v $$(pwd)/.go/bin/$(OS)_$(ARCH):/go/bin/$(OS)_$(ARCH)  \
	    -v $$(pwd)/.go/cache:/.cache                            \
	    --env HTTP_PROXY=$(HTTP_PROXY)                          \
	    --env HTTPS_PROXY=$(HTTPS_PROXY)                        \
	    $(BUILD_IMAGE)                                          \
	    /bin/bash -c "                                          \
	        PRODUCT_OWNER_NAME=$(PRODUCT_OWNER_NAME)            \
	        PRODUCT_NAME=$(PRODUCT_NAME)                        \
	        ENFORCE_LICENSE=$(ENFORCE_LICENSE)                  \
	        ARCH=$(ARCH)                                        \
	        OS=$(OS)                                            \
	        VERSION=$(VERSION)                                  \
	        version_strategy=$(version_strategy)                \
	        git_branch=$(git_branch)                            \
	        git_tag=$(git_tag)                                  \
	        commit_hash=$(commit_hash)                          \
	        commit_timestamp=$(commit_timestamp)                \
	        ./hack/build.sh                                     \
	    "
	@if [ $(COMPRESS) = yes ] && [ $(OS) != darwin ]; then          \
		echo "compressing $(OUTBIN)";                               \
		@docker run                                                 \
		    -i                                                      \
		    --rm                                                    \
		    -u $$(id -u):$$(id -g)                                  \
		    -v $$(pwd):/src                                         \
		    -w /src                                                 \
		    -v $$(pwd)/.go/bin/$(OS)_$(ARCH):/go/bin                \
		    -v $$(pwd)/.go/bin/$(OS)_$(ARCH):/go/bin/$(OS)_$(ARCH)  \
		    -v $$(pwd)/.go/cache:/.cache                            \
		    --env HTTP_PROXY=$(HTTP_PROXY)                          \
		    --env HTTPS_PROXY=$(HTTPS_PROXY)                        \
		    $(BUILD_IMAGE)                                          \
		    upx --brute /go/$(OUTBIN);                              \
	fi
	@if ! cmp -s .go/$(OUTBIN) $(OUTBIN); then \
	    mv .go/$(OUTBIN) $(OUTBIN);            \
	    date >$@;                              \
	fi
	@echo

# Used to track state in hidden files.
DOTFILE_IMAGE    = $(subst /,_,$(IMAGE))-$(TAG)

container: bin/.container-$(DOTFILE_IMAGE)-PROD bin/.container-$(DOTFILE_IMAGE)-DBG
ifeq (,$(SRC_REG))
bin/.container-$(DOTFILE_IMAGE)-%: bin/$(OS)_$(ARCH)/$(BIN) $(DOCKERFILE_%)
	@echo "container: $(IMAGE):$(TAG_$*)"
	@sed                                    \
		-e 's|{ARG_BIN}|$(BIN)|g'           \
		-e 's|{ARG_ARCH}|$(ARCH)|g'         \
		-e 's|{ARG_OS}|$(OS)|g'             \
		-e 's|{ARG_FROM}|$(BASEIMAGE_$*)|g' \
		$(DOCKERFILE_$*) > bin/.dockerfile-$*-$(OS)_$(ARCH)
	@docker buildx build --platform $(OS)/$(ARCH) --load --pull -t $(IMAGE):$(TAG_$*) -f bin/.dockerfile-$*-$(OS)_$(ARCH) .
	@docker images -q $(IMAGE):$(TAG_$*) > $@
	@echo
else
bin/.container-$(DOTFILE_IMAGE)-%:
	@echo "container: $(IMAGE):$(TAG_$*)"
	@docker tag $(SRC_REG)/$(BIN):$(TAG_$*) $(IMAGE):$(TAG_$*)
	@echo
endif

push: bin/.push-$(DOTFILE_IMAGE)-PROD bin/.push-$(DOTFILE_IMAGE)-DBG
bin/.push-$(DOTFILE_IMAGE)-%: bin/.container-$(DOTFILE_IMAGE)-%
	@docker push $(IMAGE):$(TAG_$*)
	@echo "pushed: $(IMAGE):$(TAG_$*)"
	@echo

.PHONY: docker-manifest
docker-manifest: docker-manifest-PROD docker-manifest-DBG
docker-manifest-%:
	docker manifest create -a $(IMAGE):$(VERSION_$*) $(foreach PLATFORM,$(DOCKER_PLATFORMS),$(IMAGE):$(VERSION_$*)_$(subst /,_,$(PLATFORM)))
	docker manifest push $(IMAGE):$(VERSION_$*)

.PHONY: test
test: unit-tests e2e-tests

unit-tests: $(BUILD_DIRS)
	@docker run                                                 \
	    -i                                                      \
	    --rm                                                    \
	    -u $$(id -u):$$(id -g)                                  \
	    -v $$(pwd):/src                                         \
	    -w /src                                                 \
	    -v $$(pwd)/.go/bin/$(OS)_$(ARCH):/go/bin                \
	    -v $$(pwd)/.go/bin/$(OS)_$(ARCH):/go/bin/$(OS)_$(ARCH)  \
	    -v $$(pwd)/.go/cache:/.cache                            \
	    --env HTTP_PROXY=$(HTTP_PROXY)                          \
	    --env HTTPS_PROXY=$(HTTPS_PROXY)                        \
	    $(BUILD_IMAGE)                                          \
	    /bin/bash -c "                                          \
	        ARCH=$(ARCH)                                        \
	        OS=$(OS)                                            \
	        VERSION=$(VERSION)                                  \
	        ./hack/test.sh $(SRC_PKGS)                          \
	    "

# - e2e-tests can hold both ginkgo args (as GINKGO_ARGS) and program/test args (as TEST_ARGS).
#       make e2e-tests TEST_ARGS="--selfhosted-operator=false --storageclass=standard" GINKGO_ARGS="--flakeAttempts=2"
#
# - Minimalist:
#       make e2e-tests
#
# NB: -t is used to catch ctrl-c interrupt from keyboard and -t will be problematic for CI.

GINKGO_ARGS ?=
TEST_ARGS   ?=

.PHONY: e2e-tests
e2e-tests: $(BUILD_DIRS)
	@docker run                                                 \
	    -i                                                      \
	    --rm                                                    \
	    -u $$(id -u):$$(id -g)                                  \
	    -v $$(pwd):/src                                         \
	    -w /src                                                 \
	    --net=host                                              \
	    -v $(HOME)/.kube:/.kube                                 \
	    -v $(HOME)/.minikube:$(HOME)/.minikube                  \
	    -v $(HOME)/.credentials:$(HOME)/.credentials            \
	    -v $$(pwd)/.go/bin/$(OS)_$(ARCH):/go/bin                \
	    -v $$(pwd)/.go/bin/$(OS)_$(ARCH):/go/bin/$(OS)_$(ARCH)  \
	    -v $$(pwd)/.go/cache:/.cache                            \
	    --env HTTP_PROXY=$(HTTP_PROXY)                          \
	    --env HTTPS_PROXY=$(HTTPS_PROXY)                        \
	    --env KUBECONFIG=$(KUBECONFIG)                          \
	    --env-file=$$(pwd)/hack/config/.env                     \
	    $(BUILD_IMAGE)                                          \
	    /bin/bash -c "                                          \
	        ARCH=$(ARCH)                                        \
	        OS=$(OS)                                            \
	        VERSION=$(VERSION)                                  \
	        DOCKER_REGISTRY=$(REGISTRY)                         \
	        TAG=$(TAG)                                          \
	        KUBECONFIG=$${KUBECONFIG#$(HOME)}                   \
	        GINKGO_ARGS='$(GINKGO_ARGS)'                        \
	        TEST_ARGS='$(TEST_ARGS)'                            \
	        ./hack/e2e.sh                                       \
	    "

.PHONY: e2e-parallel
e2e-parallel:
	@$(MAKE) e2e-tests GINKGO_ARGS="-p -stream --flakeAttempts=2" --no-print-directory

ADDTL_LINTERS   := gofmt,goimports,unparam

.PHONY: lint
lint: $(BUILD_DIRS)
	@echo "running linter"
	@docker run                                                 \
	    -i                                                      \
	    --rm                                                    \
	    -u $$(id -u):$$(id -g)                                  \
	    -v $$(pwd):/src                                         \
	    -w /src                                                 \
	    -v $$(pwd)/.go/bin/$(OS)_$(ARCH):/go/bin                \
	    -v $$(pwd)/.go/bin/$(OS)_$(ARCH):/go/bin/$(OS)_$(ARCH)  \
	    -v $$(pwd)/.go/cache:/.cache                            \
	    --env HTTP_PROXY=$(HTTP_PROXY)                          \
	    --env HTTPS_PROXY=$(HTTPS_PROXY)                        \
	    --env GOFLAGS="-mod=vendor"                             \
	    $(BUILD_IMAGE)                                          \
	    golangci-lint run --enable $(ADDTL_LINTERS) --timeout=10m --exclude-files="generated.*\.go$\" --exclude-dirs-use-default --exclude-dirs=client,vendor

$(BUILD_DIRS):
	@mkdir -p $@

KUBE_NAMESPACE    ?= cert-manager
REGISTRY_SECRET   ?=
IMAGE_PULL_POLICY	?= IfNotPresent

ifeq ($(strip $(REGISTRY_SECRET)),)
	IMAGE_PULL_SECRETS =
else
	IMAGE_PULL_SECRETS = --set imagePullSecrets[0].name=$(REGISTRY_SECRET)
endif

.PHONY: install
install:
	@cd ../installer; \
	helm upgrade -i cert-manager-csi-driver-cacerts charts/cert-manager-csi-driver-cacerts --wait \
		--namespace=$(KUBE_NAMESPACE) --create-namespace \
		--set registryFQDN="" \
		--set driver.registry=$(REGISTRY) \
		--set driver.tag=$(TAG_PROD) \
		--set driver.pullPolicy=$(IMAGE_PULL_POLICY) \
		$(IMAGE_PULL_SECRETS); \

.PHONY: uninstall
uninstall:
	@cd ../installer; \
	helm uninstall cert-manager-csi-driver-cacerts --namespace=$(KUBE_NAMESPACE) || true

.PHONY: purge
purge: uninstall
	kubectl delete crds -l app.kubernetes.io/name=cert-manager

.PHONY: dev
dev: gen fmt push

.PHONY: verify
verify: verify-gen verify-modules

.PHONY: verify-modules
verify-modules:
	go mod tidy
	go mod vendor
	@if !(git diff --exit-code HEAD); then \
		echo "go module files are out of date"; exit 1; \
	fi

.PHONY: verify-gen
verify-gen: gen fmt
	@if !(git diff --exit-code HEAD); then \
		echo "generated files are out of date, run make gen fmt"; exit 1; \
	fi

.PHONY: add-license
add-license:
	@echo "Adding license header"
	@docker run --rm 	                                 \
		-u $$(id -u):$$(id -g)                           \
		-v /tmp:/.cache                                  \
		-v $$(pwd):$(DOCKER_REPO_ROOT)                   \
		-w $(DOCKER_REPO_ROOT)                           \
		--env HTTP_PROXY=$(HTTP_PROXY)                   \
		--env HTTPS_PROXY=$(HTTPS_PROXY)                 \
		$(BUILD_IMAGE)                                   \
		ltag -t "./hack/license" --excludes "vendor contrib bin" -v

.PHONY: check-license
check-license:
	@echo "Checking files have proper license header"
	@docker run --rm 	                                 \
		-u $$(id -u):$$(id -g)                           \
		-v /tmp:/.cache                                  \
		-v $$(pwd):$(DOCKER_REPO_ROOT)                   \
		-w $(DOCKER_REPO_ROOT)                           \
		--env HTTP_PROXY=$(HTTP_PROXY)                   \
		--env HTTPS_PROXY=$(HTTPS_PROXY)                 \
		$(BUILD_IMAGE)                                   \
		ltag -t "./hack/license" --excludes "vendor contrib bin" --check -v

.PHONY: ci
ci: check-license lint build #unit-tests cover verify

.PHONY: qa
qa:
	@if [ "$$APPSCODE_ENV" = "prod" ]; then                                              \
		echo "Nothing to do in prod env. Are you trying to 'release' binaries to prod?"; \
		exit 1;                                                                          \
	fi
	@if [ "$(version_strategy)" = "tag" ]; then               \
		echo "Are you trying to 'release' binaries to prod?"; \
		exit 1;                                               \
	fi
	@$(MAKE) clean all-push docker-manifest --no-print-directory

.PHONY: release
release:
	@if [ "$$APPSCODE_ENV" != "prod" ]; then      \
		echo "'release' only works in PROD env."; \
		exit 1;                                   \
	fi
	@if [ "$(version_strategy)" != "tag" ]; then                    \
		echo "apply tag to release binaries and/or docker images."; \
		exit 1;                                                     \
	fi
	@$(MAKE) clean all-push docker-manifest --no-print-directory

.PHONY: clean
clean:
	rm -rf .go bin

.PHONY: run
run:
	go run -mod=vendor ./cmd/csi-driver-cacerts run \
		--v=3 \
		--secure-port=8443 \
		--kubeconfig=$(KUBECONFIG) \
		--authorization-kubeconfig=$(KUBECONFIG) \
		--authentication-kubeconfig=$(KUBECONFIG) \
		--authentication-skip-lookup

.PHONY: push-to-kind
push-to-kind: container
	@echo "Loading docker image into kind cluster...."
	@kind load docker-image $(IMAGE):$(TAG_PROD)
	@echo "Image has been pushed successfully into kind cluster."

.PHONY: deploy-to-kind
deploy-to-kind: push-to-kind install

.PHONY: deploy
deploy: uninstall push install
