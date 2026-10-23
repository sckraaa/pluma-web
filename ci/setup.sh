#!/usr/bin/env bash
# Installs what the build job needs on a GitHub runner: the pnpm of
# upstream.env (the version upstream's package.json declares; ci/patch.py
# checks they match). Node.js comes from actions/setup-node; this checks it
# is the NODE_VERSION of upstream.env.
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env

retry() {
	local attempt
	for attempt in 1 2 3; do
		if "$@"; then
			return 0
		fi
		echo "setup: attempt $attempt of '$*' failed" >&2
		sleep $((attempt * 15))
	done
	return 1
}

node=$(node --version)
if [ "$node" != "v$NODE_VERSION" ]; then
	echo "setup: node $node, upstream.env pins $NODE_VERSION" >&2
	exit 1
fi
retry timeout 5m npm install --global --no-audit --no-fund "pnpm@$PNPM_VERSION"
pnpm=$(pnpm --version)
if [ "$pnpm" != "$PNPM_VERSION" ]; then
	echo "setup: pnpm $pnpm, upstream.env pins $PNPM_VERSION" >&2
	exit 1
fi
echo "setup: node $NODE_VERSION, pnpm $PNPM_VERSION"
