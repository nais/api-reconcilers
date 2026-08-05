#!/usr/bin/env bash
#MISE description="Start local development server using dlv"

set -e

dlv debug --headless --listen=:2345 --api-version=2 ./cmd/api-reconcilers
