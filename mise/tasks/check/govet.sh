#!/usr/bin/env bash
#MISE description="Run govet"

set -e

go vet ./...
