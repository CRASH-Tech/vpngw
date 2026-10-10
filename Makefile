VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE   ?= vpngw:latest
# With client installers next to clients/info.txt the image includes them.
CLIENTS ?= $(shell ls clients 2>/dev/null | grep -qv '^info.txt$$' && echo include || echo none)

.PHONY: build test lint image run-dev e2e e2e-sites clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/vpngw ./cmd/vpngw

test:
	go test ./cmd/... ./internal/... ./templates/...

lint:
	gofmt -l cmd internal templates | tee /dev/stderr | (! read)
	go vet ./cmd/... ./internal/... ./templates/...

image:
	docker build --build-arg VERSION=$(VERSION) --build-arg CLIENTS=$(CLIENTS) -t $(IMAGE) .

# Development deployment on this host (see deploy/dev/).
run-dev: image
	docker compose -f deploy/dev/docker-compose.yml up -d --force-recreate

e2e: image
	./test/e2e/run.sh

# Two sites in containers: an exit node and a gateway for its hosts.
e2e-sites: image
	docker build -q -t vpngw-testclient test/e2e/client
	./test/e2e/sites.sh

clean:
	rm -rf bin
