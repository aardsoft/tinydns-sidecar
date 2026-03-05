.PHONY: build build-all build-linux test clean fmt vet deps docker-image docker-image-standalone docker-image-rebuild help

BINARIES := tinydns-sidecar tinydns-client tinydns-rebuild

OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH := $(shell uname -m)

ifeq ($(ARCH),x86_64)
  ARCH := amd64
endif
ifeq ($(ARCH),aarch64)
  ARCH := arm64
endif

VERSION ?= $(shell \
  git rev-parse --short HEAD 2>/dev/null || echo dev)
LDFLAGS := -ldflags="-s -w -X main.version=$(VERSION)"

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build all binaries for the current platform
	go build $(LDFLAGS) -o ./build/tinydns-sidecar-$(OS)-$(ARCH)  ./cmd/tinydns-sidecar
	go build $(LDFLAGS) -o ./build/tinydns-client-$(OS)-$(ARCH)   ./cmd/tinydns-client
	go build $(LDFLAGS) -o ./build/tinydns-rebuild-$(OS)-$(ARCH)  ./cmd/tinydns-rebuild

build-linux: ## Build all binaries for linux/amd64 and linux/arm64 (prerequisite for docker-image)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o ./build/tinydns-sidecar-linux-amd64  ./cmd/tinydns-sidecar
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o ./build/tinydns-sidecar-linux-arm64  ./cmd/tinydns-sidecar
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o ./build/tinydns-rebuild-linux-amd64  ./cmd/tinydns-rebuild
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o ./build/tinydns-rebuild-linux-arm64  ./cmd/tinydns-rebuild

build-all: ## Build all binaries for all platforms
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o ./build/tinydns-sidecar-linux-amd64        ./cmd/tinydns-sidecar
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o ./build/tinydns-sidecar-linux-arm64        ./cmd/tinydns-sidecar
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o ./build/tinydns-sidecar-darwin-amd64       ./cmd/tinydns-sidecar
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o ./build/tinydns-sidecar-darwin-arm64       ./cmd/tinydns-sidecar
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o ./build/tinydns-sidecar-windows-amd64.exe  ./cmd/tinydns-sidecar
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o ./build/tinydns-sidecar-windows-arm64.exe  ./cmd/tinydns-sidecar
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o ./build/tinydns-client-linux-amd64         ./cmd/tinydns-client
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o ./build/tinydns-client-linux-arm64         ./cmd/tinydns-client
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o ./build/tinydns-client-darwin-amd64        ./cmd/tinydns-client
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o ./build/tinydns-client-darwin-arm64        ./cmd/tinydns-client
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o ./build/tinydns-client-windows-amd64.exe   ./cmd/tinydns-client
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o ./build/tinydns-client-windows-arm64.exe   ./cmd/tinydns-client
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o ./build/tinydns-rebuild-linux-amd64        ./cmd/tinydns-rebuild
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o ./build/tinydns-rebuild-linux-arm64        ./cmd/tinydns-rebuild

test: ## Run tests
	go test -v ./...

clean: ## Remove built binaries
	rm -f build/* tinydns-sidecar tinydns-sidecar-* tinydns-client tinydns-client-* tinydns-rebuild tinydns-rebuild-*

deps: ## Download and verify dependencies
	go mod download
	go mod verify

fmt: ## Format code
	go fmt ./...

vet: ## Run go vet
	go vet ./...

IMAGE ?= tinydns-sidecar
TAG   ?= $(VERSION)

docker-image: build-linux ## Build multi-arch scratch image (k3s default)
	docker buildx build --platform linux/amd64,linux/arm64 -t $(IMAGE):$(TAG) .

docker-image-standalone: build-linux ## Build multi-arch Alpine image (supports rebuild_command)
	docker buildx build --platform linux/amd64,linux/arm64 --target standalone -t $(IMAGE):$(TAG)-standalone .

TINYDNS_IMAGE ?=

docker-image-rebuild: build-linux ## Build multi-arch rebuild daemon image (TINYDNS_IMAGE=your-tinydns-image:tag required)
	@test -n "$(TINYDNS_IMAGE)" || (echo "ERROR: TINYDNS_IMAGE must be set, e.g. make docker-image-rebuild TINYDNS_IMAGE=your-tinydns:tag"; exit 1)
	docker buildx build --platform linux/amd64,linux/arm64 \
		--build-arg TINYDNS_IMAGE=$(TINYDNS_IMAGE) \
		-f Dockerfile.rebuild -t $(IMAGE)-rebuild:$(TAG) .
