#!/usr/bin/env bash
#MISE description="Run staticcheck"

set -e

go tool honnef.co/go/tools/cmd/staticcheck ./...
