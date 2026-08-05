#!/usr/bin/env bash
#MISE description="Format all code"

set -e

go tool mvdan.cc/gofumpt -w ./
