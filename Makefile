# Image URL to use all building/pushing image targets
IMG ?= ack-ram-authenticator:latest
BINARY_NAME=ack-ram-authenticator

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec
BUILD_TIMESTAMP = $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
COMMIT ?= $(shell git rev-parse HEAD)
COMMIT_SHORT ?= $(shell git rev-parse --short HEAD)
IMAGE_TAG ?= $(shell git describe --tags --long|awk -F '-' '{print $$1"."$$2"-"$$3"-aliyun"}')
PACKAGE = github.com/AliyunContainerService/ack-ram-authenticator

GO_LDFLAGS := -extldflags "-static"
# GO_LDFLAGS += -w -s # Drop debugging symbols.
GO_LDFLAGS += -X $(PACKAGE)/pkg.Version=$(IMAGE_TAG) \
	-X $(PACKAGE)/pkg.CommitID=$(COMMIT_SHORT) \
	-X $(PACKAGE)/pkg.BuildDate=$(BUILD_TIMESTAMP)
GO_BUILD_FLAGS := -ldflags '$(GO_LDFLAGS)'

.PHONY: all
all: build

.PHONY: build
build:
	CGO_ENABLED=0 GO111MODULE=off go build $(GO_BUILD_FLAGS)  -o bin/$(BINARY_NAME) github.com/AliyunContainerService/$(BINARY_NAME)/cmd/ack-ram-authenticator

build-race:
	CGO_ENABLED=0 GO111MODULE=off go build -race $(GO_BUILD_FLAGS) -o bin/$(BINARY_NAME) github.com/AliyunContainerService/$(BINARY_NAME)/cmd/ack-ram-authenticator

build-all:
	CGO_ENABLED=0 GO111MODULE=off go build $(GO_BUILD_FLAGS) $$(glide nv)

build-image:
	CGO_ENABLED=0 GO111MODULE=off go build $(GO_BUILD_FLAGS) -o bin/$(BINARY_NAME) github.com/AliyunContainerService/$(BINARY_NAME)/cmd/ack-ram-authenticator
	docker build --build-arg AUTHENTICATOR_VERSION=${AUTHENTICATOR_VERSION} -t ${IMG} .

# Run tests
test: generate fmt vet manifests
	go test -v ./backend... ./errors/... ./controllers/... -coverprofile cover.out

# Build manager binary
manager: generate fmt vet
	go build ${BUILD_FLAGS} -o bin/${BINARY_NAME} main.go

# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate fmt vet
	go run ./main.go

# Install CRDs into a cluster
install: manifests
	kubectl apply -f config/crd/bases

# Deploy controller in the configured Kubernetes cluster in ~/.kube/config
deploy: manifests
	kubectl apply -f config/crd/bases
	kustomize build config/default | kubectl apply -f -

# Generate manifests e.g. CRD, RBAC etc.
manifests: controller-gen
	$(CONTROLLER_GEN) $(CRD_OPTIONS) rbac:roleName=manager-role webhook paths="./..." output:crd:artifacts:config=config/crd/bases

# Run go fmt against code
fmt:
	go fmt ./...

# Run go vet against code
vet:
	go vet ./...

# Generate code
generate: controller-gen
	$(CONTROLLER_GEN) object:headerFile=./hack/boilerplate.go.txt paths=./api/...

# Build the docker image
docker-build: test
	docker build --build-arg AUTHENTICATOR_VERSION=${AUTHENTICATOR_VERSION} -t ${IMG} .

# Push the docker image
docker-push:
	docker push ${IMG}

# find or download controller-gen
# download controller-gen if necessary
controller-gen:
ifeq (, $(shell which controller-gen))
	go get sigs.k8s.io/controller-tools/cmd/controller-gen@v0.2.0-beta.2
CONTROLLER_GEN=$(shell go env GOPATH)/bin/controller-gen
else
CONTROLLER_GEN=$(shell which controller-gen)
endif
