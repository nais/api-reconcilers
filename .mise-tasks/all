#!/usr/bin/env bash
#MISE description="Run all required generators, tests etc."

set -e

mise run generate
mise run check ::: build ::: test ::: fmt
