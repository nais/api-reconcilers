#!/usr/bin/env bash
#MISE description="Run govulncheck"

set -e

go tool golang.org/x/vuln/cmd/govulncheck ./...
