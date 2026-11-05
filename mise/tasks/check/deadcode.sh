#!/usr/bin/env bash
#MISE description="Run deadcode"
#MISE wait_for=["fix", "fmt", "generate"]

set -e

go tool golang.org/x/tools/cmd/deadcode -test ./...
