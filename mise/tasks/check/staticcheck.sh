#!/usr/bin/env bash
#MISE description="Run staticcheck"
#MISE wait_for=["fix", "fmt", "generate"]

set -e

go tool honnef.co/go/tools/cmd/staticcheck ./...
