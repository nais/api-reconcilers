#!/usr/bin/env bash
#MISE description="Test all code"
#USAGE flag "--coverage" help="Generate a coverage profile"

set -e

# shellcheck disable=SC2154
if [ "$usage_coverage" = "true" ]; then
	rm -f hack/coverprofile.txt
	go test \
	  -coverprofile=hack/coverprofile.txt \
	  -coverpkg github.com/nais/api-reconcilers/... \
	  -v \
	  -race \
	  ./...
else
	go test -cover -race ./...
fi
