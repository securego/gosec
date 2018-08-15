GIT_TAG?= $(shell git describe --always --tags)
BIN = gosec
FMT_CMD = $(gofmt -s -l -w $(find . -type f -name '*.go' -not -path './vendor/*') | tee /dev/stderr)
IMAGE_REPO = docker.io

default:
	$(MAKE) bootstrap
	$(MAKE) build

bootstrap:
	dep ensure

test: bootstrap
	test -z '$(FMT_CMD)'
	go vet $(go list ./... | grep -v /vendor/)
	golint -set_exit_status $(shell go list ./... | grep -v vendor)
	gosec ./...
	ginkgo -r -v

build:
	go build -o $(BIN) ./cmd/gosec/

clean:
	rm -rf build vendor dist
	rm -f release image bootstrap $(BIN)

release: bootstrap
	@echo "Releasing the gosec binary..."
	goreleaser release

image: build
	@echo "Building the Docker image..."
	docker build -t $(IMAGE_REPO)/$(BIN):$(GIT_TAG) .
	docker tag $(IMAGE_REPO)/$(BIN):$(GIT_TAG) $(IMAGE_REPO)/$(BIN):latest
	touch image

image-push: image
	@echo "Pushing the Docker image..."

docker push $(IMAGE_REPO)/$(BIN):$(GIT_TAG)
	docker push $(IMAGE_REPO)/$(BIN):latest

.PHONY: test build clean release image image-push

