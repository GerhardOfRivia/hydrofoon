OUTPUT ?= bin
SEMVER ?= 1.0.1
VERSION ?= $(SEMVER)-dev
RELEASE_TAG ?= v$(SEMVER)
LDFLAGS = -ldflags "-X main.Version=$(VERSION)"
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

.PHONY: all activate build build-linux-amd64 build-linux-arm64 fmt vet test race check release clean

all: build

activate:
	@printf 'Run this in your current Bash shell: source ./activate\n'

build-linux-amd64:
	$(MAKE) build GOOS=linux GOARCH=amd64 CGO_ENABLED=0 ONDERZEEER_OUTPUT=bin/onderzeeer-linux-amd64 ONDERZEEERD_OUTPUT=bin/onderzeeerd-linux-amd64

build-linux-arm64:
	$(MAKE) build GOOS=linux GOARCH=arm64 CGO_ENABLED=0 ONDERZEEER_OUTPUT=bin/onderzeeer-linux-arm64 ONDERZEEERD_OUTPUT=bin/onderzeeerd-linux-arm64

build:
	CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/hydrofoon ./cmd/hydrofoon

fmt:
	go fmt ./...

vet:
	go vet ./...

test:
	go test ./...

race:
	go test -race ./...

check: fmt vet test race

release:
	@test -z "$$(git status --porcelain)" || { echo "Refusing to release with a dirty working tree."; exit 1; }
	@if git rev-parse --verify --quiet "refs/tags/$(RELEASE_TAG)" >/dev/null; then echo "Tag $(RELEASE_TAG) already exists."; exit 1; fi
	git tag "$(RELEASE_TAG)"
	git push origin "$(RELEASE_TAG)"

clean:
	@echo "Cleaning up..."
	rm -f bin/*
