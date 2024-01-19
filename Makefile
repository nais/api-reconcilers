.PHONY: all

all: generate test check fmt build

generate: generate-mocks

generate-mocks:
	go run github.com/vektra/mockery/v2 --config ./.configs/mockery.yaml
	find internal -type f -name "mock_*.go" -exec go run mvdan.cc/gofumpt -w {} \;

build:
	go build -o bin/api-reconcilers ./cmd/api-reconcilers

local:
	go run ./cmd/api-reconcilers

test:
	go test ./...

check: staticcheck vulncheck deadcode

staticcheck:
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

deadcode:
	go run golang.org/x/tools/cmd/deadcode@latest -test ./...

fmt:
	go run mvdan.cc/gofumpt@latest -w ./