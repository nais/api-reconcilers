#!/usr/bin/env bash
#MISE description="Build api-reconcilers"
#MISE wait_for=["fix", "fmt", "generate"]

set -e

go build -o bin/api-reconcilers ./cmd/api-reconcilers
