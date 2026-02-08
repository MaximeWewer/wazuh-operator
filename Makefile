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
manifests: controller-gen ## Generate CRDs directly into Helm chart.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=charts/wazuh-operator/crds

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
test: manifests generate fmt vet envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) -p path)" go test ./... -coverprofile cover.out

.PHONY: test-coverage
test-coverage: test ## Run tests and show coverage report.
	go tool cover -html=cover.out

.PHONY: test-e2e
test-e2e: ## Run E2E tests (requires deployed cluster)
	./test/e2e/scripts/test-deployment.sh
	./test/e2e/scripts/test-configuration.sh

.PHONY: test-e2e-full
test-e2e-full: ## Run full E2E test suite including scaling tests
	./test/e2e/scripts/test-deployment.sh
	./test/e2e/scripts/test-configuration.sh
	./test/e2e/scripts/test-scaling.sh

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

##@ Deployment (Helm)

HELM_RELEASE_OPERATOR ?= wazuh-operator
HELM_RELEASE_CLUSTER ?= wazuh-cluster
HELM_NAMESPACE_OPERATOR ?= wazuh-system
HELM_NAMESPACE_CLUSTER ?= wazuh-system

.PHONY: install
install: manifests ## Install CRDs into the K8s cluster.
	kubectl apply --server-side -f charts/wazuh-operator/crds/

.PHONY: uninstall
uninstall: ## Uninstall CRDs from the K8s cluster.
	-kubectl delete -f charts/wazuh-operator/crds/

.PHONY: deploy
deploy: manifests ## Deploy operator using Helm.
	helm upgrade --install $(HELM_RELEASE_OPERATOR) ./charts/wazuh-operator \
		--namespace $(HELM_NAMESPACE_OPERATOR) --create-namespace

.PHONY: undeploy
undeploy: ## Undeploy operator using Helm.
	-helm uninstall $(HELM_RELEASE_OPERATOR) --namespace $(HELM_NAMESPACE_OPERATOR)

.PHONY: deploy-cluster
deploy-cluster: ## Deploy a Wazuh cluster using Helm.
	helm upgrade --install $(HELM_RELEASE_CLUSTER) ./charts/wazuh-cluster \
		--namespace $(HELM_NAMESPACE_CLUSTER) \
		--set sizing.profile=S

.PHONY: undeploy-cluster
undeploy-cluster: ## Undeploy Wazuh cluster using Helm.
	-helm uninstall $(HELM_RELEASE_CLUSTER) --namespace $(HELM_NAMESPACE_CLUSTER)

##@ Clean & Redeploy

.PHONY: clean-bin
clean-bin: ## Remove old binary
	@echo "Cleaning old binary..."
	rm -f bin/manager
	@echo "Binary cleaned"

.PHONY: clean-crds
clean-crds: ## Remove old CRDs from cluster
	@echo "Cleaning old CRDs from cluster..."
	-kubectl delete wazuhclusters.resources.wazuh.com --all --all-namespaces
	-kubectl delete wazuhrules.resources.wazuh.com --all --all-namespaces
	-kubectl delete wazuhdecoders.resources.wazuh.com --all --all-namespaces
	-kubectl delete -f charts/wazuh-operator/crds/ --ignore-not-found=true
	@echo "CRDs cleaned"

.PHONY: clean-all
clean-all: clean-bin undeploy undeploy-cluster clean-crds ## Clean everything (binary, Helm releases, CRDs)
	@echo "Full cleanup completed"

.PHONY: redeploy
redeploy: clean-all build install deploy ## Complete redeploy: clean, build, install CRDs, deploy operator
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

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest

## Tool Versions
CONTROLLER_TOOLS_VERSION ?= v0.19.0
ENVTEST_VERSION ?= latest
ENVTEST_K8S_VERSION = 1.31.0

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	test -s $(LOCALBIN)/controller-gen || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: envtest
envtest: $(ENVTEST) ## Download envtest-setup locally if necessary.
$(ENVTEST): $(LOCALBIN)
	test -s $(LOCALBIN)/setup-envtest || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@$(ENVTEST_VERSION)

##@ Validation

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run ./...

.PHONY: helm-lint
helm-lint: ## Lint Helm charts
	helm lint charts/wazuh-operator
	helm lint charts/wazuh-cluster

.PHONY: helm-docs
helm-docs: ## Generate Helm chart READMEs from values.yaml and format them
	@command -v helm-docs >/dev/null 2>&1 || { echo "helm-docs not found. Install with: go install github.com/norwoodj/helm-docs/cmd/helm-docs@latest"; exit 1; }
	helm-docs --chart-search-root=charts
	@if command -v npx >/dev/null 2>&1 && [ -f package.json ]; then \
		npx prettier --write charts/*/README.md; \
	else \
		echo "Prettier not available, skipping markdown formatting"; \
	fi

