GIT_TAG?= $(shell git describe --always --tags)
BUILD_DATE = $(shell date +%Y-%m-%d)
BIN = gas
BUILD_CMD = go build -ldflags "-X main.Version=${VERSION} -X main.GitTag=${GIT_TAG} -X main.BuildDate=${BUILD_DATE}" -o build/$(BIN)-$(VERSION)-$${GOOS}-$${GOARCH} ./cmd/gas/ &
FMT_CMD = $(gofmt -s -l -w $(find . -type f -name '*.go' -not -path './vendor/*') | tee /dev/stderr)
IMAGE_REPO = docker.io

default:
	$(MAKE) bootstrap
	$(MAKE) build

test: bootstrap
	test -z '$(FMT_CMD)'
	go vet $(go list ./... | grep -v /vendor/)
	golint -set_exit_status $(shell go list ./... | grep -v vendor)
	gas ./...
	ginkgo -r -v
bootstrap:
	dep ensure
build:
	go build -o $(BIN) ./cmd/gas/
clean:
	rm -rf build vendor dist
	rm -f release image bootstrap $(BIN)
release: bootstrap
	goreleaser release --skip-publish

image: release
	@echo "Building the Docker image..."
	docker build -t $(IMAGE_REPO)/$(BIN):$(GIT_TAG) .
	docker tag $(IMAGE_REPO)/$(BIN):$(GIT_TAG) $(IMAGE_REPO)/$(BIN):latest
	touch image

image-push: image
	@echo "Pushing the Docker image..."
	docker push $(IMAGE_REPO)/$(BIN):$(GIT_TAG)
	docker push $(IMAGE_REPO)/$(BIN):latest

.PHONY: test build clean release image image-push

