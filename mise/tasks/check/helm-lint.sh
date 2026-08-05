#!/usr/bin/env bash
#MISE description="Run helm lint"

set -e

helm lint --strict ./charts
