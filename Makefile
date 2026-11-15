BIN ?= bin/app

.PHONY: build test check fmt lint vuln runtime-verify artifact-digests clean

build:
	go build ./...

test:
	go test -race -count=1 ./...

check:
	test -z "$$(gofmt -l .)"
	go vet ./...

fmt:
	gofmt -w .

lint:
	golangci-lint config verify
	golangci-lint run ./...

vuln:
	govulncheck ./...

runtime-verify:
	go test ./internal/manifest
	go test ./internal/artifact
	sh scripts/test-build-nerdbox-shim-output.sh

artifact-digests:
	@test -n "$(ARTIFACTS)" || { echo "usage: make artifact-digests ARTIFACTS='gvproxy=/path containerd-shim-nerdbox-v1=/path qemu=/path'" >&2; exit 2; }
	scripts/update-artifact-digests.sh $(ARTIFACTS)

clean:
	rm -rf bin
