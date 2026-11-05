#!/usr/bin/env bash
#MISE description="Format all code"
#MISE wait_for=["fix"]

set -e

go tool mvdan.cc/gofumpt -w ./
