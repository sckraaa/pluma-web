#!/usr/bin/env bash
# Signs in to a local stand of the Pluma server with the web client, the way
# a user does, in headless Chromium (e2e/web.spec.mjs):
#
#   PLUMA_SERVER_DIR=~/pluma e2e/run.sh
#
# Starts the e2e stand of the server checkout (its test/e2e/run.sh) with the
# gateway's WebSocket port on 127.0.0.1, builds the client for the stand's
# throwaway key, serves it on 127.0.0.1 and runs the scenario: a phone on the
# allowlist signs in with the code from pluma-admin, signs up, sends a
# message to Saved Messages and creates a chat folder; a second browser signs
# in and finds the message and the folder.
# Screenshots of the steps go to .e2e/screenshots (and, if the run fails, the
# stand's logs to .e2e/logs); the stand and the browser's files are removed
# at the end.
#
# Environment:
#   PLUMA_SERVER_DIR     the checkout of the server repository (required)
#   E2E_PROJECT, E2E_DIR the stand's compose project and work directory
#                        (default: pluma-web-e2e and ./.e2e)
#   E2E_GATEWAY_WS_PORT  the port of the gateway's WebSocket transport
#                        (default: a free one)
#   E2E_WEB_PORT         the port the client is served on (default: a free one)
#
# Needs Docker for the stand, Go for the server's tools, Node.js and pnpm of
# upstream.env, Python 3 and curl; Playwright puts its Chromium into its own
# cache.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD

server=${PLUMA_SERVER_DIR:?set PLUMA_SERVER_DIR to the checkout of the server repository}
server=$(cd "$server" && pwd)
if [ ! -x "$server/test/e2e/run.sh" ]; then
	echo "e2e: $server has no test/e2e/run.sh" >&2
	exit 1
fi
export E2E_PROJECT=${E2E_PROJECT:-pluma-web-e2e}
export E2E_DIR=${E2E_DIR:-$root/.e2e}

free_port() {
	python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}
ws_port=${E2E_GATEWAY_WS_PORT:-$(free_port)}
web_port=${E2E_WEB_PORT:-$(free_port)}

log() { printf '[web-e2e %s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

stand() { (cd "$server" && E2E_GATEWAY_WS_PORT=$ws_port test/e2e/run.sh "$@"); }

screenshots=$E2E_DIR/screenshots
artifacts=$E2E_DIR/playwright
build_output=$(mktemp)
web_pid=

cleanup() {
	local status=$?
	if [ -n "$web_pid" ]; then
		kill "$web_pid" 2>/dev/null || true
		wait "$web_pid" 2>/dev/null || true
	fi
	if [ "$status" != 0 ]; then
		stand logs || true
	fi
	log "stopping the stand"
	stand down || true
	rm -rf "$artifacts" "$build_output"
	log "finished with status $status; screenshots in ${screenshots#"$root"/}"
	exit "$status"
}

trap 'rm -f "$build_output"' EXIT

# Everything that does not need the stand comes first.
log "fetching the upstream and the browser"
ci/fetch-upstream.sh
(cd e2e && npm ci --no-audit --no-fund --loglevel=error && npx playwright install --only-shell chromium)

rm -rf "$screenshots" "$artifacts"
trap cleanup EXIT
log "starting the stand (gateway WebSocket on 127.0.0.1:$ws_port)"
stand up

# The client for the stand: its URL and the public part of its throwaway key.
key=$E2E_DIR/server_pkcs1.key
pem=$(cd "$server" && go run ./tools/genserverkey -show "$key" |
	sed -n '/^-----BEGIN RSA PUBLIC KEY-----$/,/^-----END RSA PUBLIC KEY-----$/p')
if [ -z "$pem" ]; then
	echo "e2e: genserverkey printed no public key for $key" >&2
	exit 1
fi
SERVER_URL=ws://localhost:$ws_port/apiws RSA_PUBLIC_KEY=$pem ci/configure.sh
GITHUB_OUTPUT=$build_output ci/build.sh server
site=$(sed -n 's/^site=//p' "$build_output")

log "serving out/$site on http://localhost:$web_port/"
python3 -m http.server --bind 127.0.0.1 --directory "out/$site" "$web_port" >/dev/null 2>&1 &
web_pid=$!
for attempt in $(seq 50); do
	if curl -fsS -o /dev/null "http://127.0.0.1:$web_port/"; then
		break
	fi
	if [ "$attempt" = 50 ]; then
		echo "e2e: the client is not served on port $web_port" >&2
		exit 1
	fi
	sleep 0.2
done

# A number reserved for fiction (201-555-0100..0199), as the server's own
# e2e tests use: never someone's real phone.
phone=$(printf '+1201555%04d' $((100 + RANDOM % 100)))
stand admin allowlist add "$phone" "web client e2e" >/dev/null

mkdir -p "$screenshots"
log "running the scenario"
(cd e2e && PLUMA_E2E_URL=http://localhost:$web_port/ PLUMA_E2E_PHONE=$phone PLUMA_SERVER_DIR=$server \
	PLUMA_E2E_SCREENSHOTS=$screenshots PLUMA_E2E_OUTPUT=$artifacts npx playwright test)
