#!/usr/bin/env bash
#MISE description="Build api-reconcilers"

set -e

go build -o bin/api-reconcilers ./cmd/api-reconcilers
