#!/usr/bin/env bash
#MISE description="Start local development server"
#MISE sources=["**/*.go"]

set -e

go run ./cmd/api-reconcilers
