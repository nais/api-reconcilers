#!/usr/bin/env bash
#MISE description="Run deadcode"

set -e

go tool golang.org/x/tools/cmd/deadcode -test ./...
