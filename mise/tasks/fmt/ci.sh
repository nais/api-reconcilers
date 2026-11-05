#!/usr/bin/env bash
#MISE description="Ensure all code is fixed, formatted, and generated"
#MISE depends=["fix", "fmt", "generate"]

set -e

if ! git diff --exit-code --name-only; then
	echo "The file(s) listed above need fixing, formatting, or regeneration. Please run \`mise run fix\`, \`mise run fmt\`, and \`mise run generate\`, then commit the changes."
	exit 1
fi
