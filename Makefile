.PHONY: all local

all:
	mise run all

generate:
	mise run generate

build:
	mise run build

local:
	mise run local

test:
	mise run test

check:
	mise run check

staticcheck:
	mise run check:staticcheck

vulncheck:
	mise run check:vulncheck

deadcode:
	mise run check:deadcode

gosec:
	mise run check:gosec

fmt:
	mise run fmt

helm-lint:
	mise run check:helm-lint
