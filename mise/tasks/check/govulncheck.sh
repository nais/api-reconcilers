#!/usr/bin/env bash
#MISE description="Run govulncheck"
#MISE wait_for=["fix", "fmt", "generate"]

set -e

go tool golang.org/x/vuln/cmd/govulncheck ./...
