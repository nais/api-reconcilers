#!/usr/bin/env bash
#MISE description="Generate mocks using mockery"

set -e

find internal -type f -name "mock_*.go" -delete
go tool github.com/vektra/mockery/v3 --config ./.configs/mockery.yaml
find internal -type f -name "mock_*.go" -exec go tool mvdan.cc/gofumpt -w {} \;
