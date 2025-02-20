.PHONY: all local

all: generate test check fmt build helm-lint

generate: generate-mocks

generate-mocks:
	find internal -type f -name "mock_*.go" -delete
	go tool github.com/vektra/mockery/v2 --config ./.configs/mockery.yaml
	find internal -type f -name "mock_*.go" -exec go tool mvdan.cc/gofumpt -w {} \;

build:
	go build -o bin/api-reconcilers ./cmd/api-reconcilers

local:
	go run ./cmd/api-reconcilers

test:
	go test ./...

check: staticcheck vulncheck deadcode gosec

staticcheck:
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

deadcode:
	go run golang.org/x/tools/cmd/deadcode@latest -test ./...

gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@latest --exclude-generated -terse ./...

fmt:
	go tool mvdan.cc/gofumpt -w ./

helm-lint:
	helm lint --strict ./charts
