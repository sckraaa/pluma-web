#!/usr/bin/env bash
# Patches ./upstream for the server the repository variables name or, when
# none is named, for the development server of config/dev. Prints
# target=server|dev to $GITHUB_OUTPUT.
#
# Environment: SERVER_URL (the WebSocket URL of the server's MTProto
# gateway, wss://<host>/apiws), RSA_PUBLIC_KEY (PKCS#1 PEM).
set -euo pipefail
cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [ -n "${SERVER_URL:-}${RSA_PUBLIC_KEY:-}" ]; then
	# Half a configuration would build a client that cannot sign in.
	for v in SERVER_URL RSA_PUBLIC_KEY; do
		if [ -z "${!v:-}" ]; then
			echo "configure: PLUMA_$v is not set, while other server variables are" >&2
			exit 1
		fi
	done
	printf '%s\n' "$RSA_PUBLIC_KEY" >"$tmp/key.pem"
	target=server
else
	. config/dev/server.env
	SERVER_URL=$PLUMA_SERVER_URL
	cp config/dev/server_public.pem "$tmp/key.pem"
	target=dev
fi

# The edits expect upstream's own text: patch a fresh checkout only.
if [ ! -d upstream/.git ]; then
	echo "configure: no ./upstream; run ci/fetch-upstream.sh" >&2
	exit 1
fi
if [ -n "$(git -C upstream status --porcelain)" ]; then
	echo "configure: ./upstream is patched already; run ci/fetch-upstream.sh again" >&2
	exit 1
fi

python3 -I ci/patch.py --source upstream --upstream upstream.env --app config/app.env \
	--server-url "$SERVER_URL" --rsa-public-key "$tmp/key.pem" --target "$target"
echo "configure: $target build"
echo "target=$target" >>"${GITHUB_OUTPUT:-/dev/null}"
