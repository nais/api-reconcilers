#!/usr/bin/env bash
#MISE description="Run govet"
#MISE wait_for=["fix", "fmt", "generate"]

set -e

go vet ./...
