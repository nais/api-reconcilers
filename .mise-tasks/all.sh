#!/usr/bin/env bash
#MISE description="Run all required generators, tests etc."
#MISE depends=["generate"]

set -e

mise run check ::: build ::: test ::: fmt
