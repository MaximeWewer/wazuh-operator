# Image URL to use all building/pushing image targets
IMG ?= wazuh/wazuh-operator:latest

# Get the currently used golang install path
GOPATH ?= $(shell go env GOPATH)
GOBIN  ?= $(GOPATH)/bin

# Setting SHELL to bash allows bash commands to be executed by recipes.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet ## Run tests.
	go test ./... -coverprofile cover.out

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o bin/manager ./cmd/wazuh-operator/main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/wazuh-operator/main.go

.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	docker build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	docker push ${IMG}

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	kubectl apply -f config/crd/

.PHONY: uninstall
uninstall: manifests ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config.
	kubectl delete -f config/crd/

.PHONY: deploy
deploy: manifests ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	kubectl apply -f config/rbac/
	kubectl apply -f config/manager/

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config.
	kubectl delete -f config/manager/ --ignore-not-found=$(ignore-not-found)
	kubectl delete -f config/rbac/ --ignore-not-found=$(ignore-not-found)

##@ Clean & Redeploy

.PHONY: clean-bin
clean-bin: ## Remove old binary
	@echo "Cleaning old binary..."
	rm -f bin/manager
	@echo "Binary cleaned"

.PHONY: clean-crds
clean-crds: ## Remove old CRDs from cluster
	@echo "Cleaning old CRDs from cluster..."
	-kubectl delete wazuhclusters.wazuh.com --all --all-namespaces
	-kubectl delete wazuhrules.wazuh.com --all --all-namespaces
	-kubectl delete wazuhdecoders.wazuh.com --all --all-namespaces
	-kubectl delete -f config/crd/ --ignore-not-found=true
	@echo "CRDs cleaned"

.PHONY: clean-all
clean-all: clean-bin clean-crds undeploy ## Clean everything (binary, CRDs, deployment)
	@echo "Full cleanup completed"

.PHONY: redeploy
redeploy: clean-all build install deploy ## Complete redeploy: clean, build, install CRDs, deploy
	@echo "==========================="
	@echo "Redeploy completed!"
	@echo "==========================="

.PHONY: fresh-cluster
fresh-cluster: clean-all ## Delete all Wazuh clusters and prepare for fresh deployment
	@echo "Deleting all Wazuh cluster resources..."
	-kubectl delete secrets --all -n default --field-selector type=Opaque
	-kubectl delete configmaps --all -n default
	-kubectl delete pvc --all -n default
	-kubectl delete statefulsets --all -n default
	-kubectl delete deployments --all -n default
	-kubectl delete services --all -n default
	-kubectl delete jobs --all -n default
	-kubectl delete servicemonitors --all -n default
	-kubectl delete podmonitors --all -n default
	@echo "Cluster cleaned, ready for fresh deployment"

##@ Build Dependencies

CONTROLLER_GEN = $(shell pwd)/bin/controller-gen
.PHONY: controller-gen
controller-gen: ## Download controller-gen locally if necessary.
	$(call go-get-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen@v0.17.0)

# go-get-tool will 'go install' any package $2 and install it to $1.
PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
define go-get-tool
@[ -f $(1) ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Downloading $(2)" ;\
GOBIN=$(PROJECT_DIR)/bin go install $(2) ;\
rm -rf $$TMP_DIR ;\
}
endef
