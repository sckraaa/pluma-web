#!/usr/bin/env bash
# Builds the patched ./upstream into ./out: the static site
# pluma-web-<version>-<target>/, its archive pluma-web-<version>-<target>.tar.gz
# and the archive's SHA-256. The site is checked (ci/check_bundle.py) before
# it is archived.
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env
target=${1:?usage: build.sh server|dev}

record=upstream/.pluma-patch.json
if [ ! -f "$record" ]; then
	echo "build: ./upstream is not patched; run ci/configure.sh first" >&2
	exit 1
fi
patched=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["target"])' "$record")
if [ "$patched" != "$target" ]; then
	echo "build: ./upstream is patched for a $patched build, not $target" >&2
	exit 1
fi

# Vite prefers build variables from the environment to the .env files the
# patch sets them in.
while read -r var; do
	unset "$var"
done < <(compgen -e | grep '^VITE_' || true)

echo "build: node $(node --version), pnpm $(pnpm --version)"
(
	cd upstream
	pnpm install --frozen-lockfile
	# As upstream's own build: the patched sources must typecheck.
	pnpm run typecheck
	pnpm exec vite build
)

name="pluma-web-$UPSTREAM_VERSION-$UPSTREAM_BUILD-$target"
site="out/$name"
rm -rf "$site" "out/$name.tar.gz" "out/$name.tar.gz.sha256"
mkdir -p "$site"
# What upstream's build.js publishes: the bundle (dist/) over the run-time
# assets of public/ that its keepAsset.js names. The rest of public/ is
# upstream's own previous build.
node -e '
const fs = require("fs");
const path = require("path");
const [pub, site] = process.argv.slice(1);
const keepAsset = require(path.resolve("upstream/keepAsset.js"));
for(const entry of fs.readdirSync(pub, {withFileTypes: true})) {
  if(entry.isDirectory() || keepAsset(entry.name)) {
    fs.cpSync(path.join(pub, entry.name), path.join(site, entry.name), {recursive: true});
  }
}' upstream/public "$site"
cp -R upstream/dist/. "$site/"

if ! python3 -I ci/check_bundle.py --record "$record" --target "$target" "$site"; then
	rm -rf "$site"
	exit 1
fi

tar -czf "out/$name.tar.gz" -C out "$name"
(cd out && sha256sum "$name.tar.gz" >"$name.tar.gz.sha256")
echo "build: out/$name.tar.gz ($(du -h "out/$name.tar.gz" | cut -f1)), site out/$name/"
echo "site=$name" >>"${GITHUB_OUTPUT:-/dev/null}"
