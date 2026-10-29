#!/usr/bin/env python3
"""Checks the built Pluma web client before it leaves the build.

The site must carry what ci/patch.py applied to the checkout (the server
URL and key, the api_hash, the layer, the app's name, icons and plm://
sign-in link) and no trace of
Telegram's servers: no datacenter address, no MTProto endpoint of
Telegram's web clients, no server key or credential of Telegram's
deployments. Every file is read, source maps included: they are published
with the site.

Standard library only, as ci/patch.py.
"""

import argparse
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import patch  # noqa: E402
from patch import PatchError  # noqa: E402

MANIFESTS = ("site.webmanifest", "site_apple.webmanifest")

# Query switches that tweb compiles in only with its HTTP transport on
# (src/config/modes.ts): ?http=1, and ?noMultipleTransports=1 of the mode
# that starts on HTTP.
HTTP_TRANSPORT_SWITCHES = ("noMultipleTransports=1", "'http=1'", "`http=1`", '"http=1"')


def check(site, record, target):
    """Returns the number of files checked; raises PatchError on the first
    problem."""
    if record.get("target") != target:
        raise PatchError(f"the checkout was patched for a {record.get('target')} build, not {target}")
    site = pathlib.Path(site)
    files = sorted(p for p in site.rglob("*") if p.is_file())
    if not files:
        raise PatchError(f"{site}: no files")

    scripts = []
    for p in files:
        rel = p.relative_to(site).as_posix()
        # Latin-1 maps every byte to a character: binary files are read too,
        # and the ASCII the traces consist of stays as it is.
        text = p.read_bytes().decode("latin-1")
        traces = patch.telegram_traces(text)
        if traces:
            kind, what = traces[0]
            raise PatchError(f"{rel}: Telegram's {kind} {what!r}")
        if p.suffix == ".js":
            scripts.append(text)

    # The code connects to the server, and to nothing else over WebSocket;
    # tweb's HTTP transport is off.
    code = "\n".join(scripts)
    urls = set(re.findall(r"wss?://[^\s'\"`\\]*", code))
    if urls != {record["server_url"]}:
        raise PatchError(f"the code's WebSocket URLs are {sorted(urls)}, expected {record['server_url']}")
    for s in HTTP_TRANSPORT_SWITCHES:
        if s in code:
            raise PatchError(f"the code has tweb's HTTP transport on ({s}); see .env.production.local of ci/patch.py")
    for what, s in (("server key", record["modulus"]), ("api_hash", record["api_hash"])):
        if s not in code:
            raise PatchError(f"the code has no {what} {s[:16]}...")
    if not re.search(rf"[\"']?layer[\"']?:{record['layer']}\b", code):
        raise PatchError(f"the code's schema is not layer {record['layer']}")

    name = record["app_name"]
    index = site / "index.html"
    if not index.is_file() or f"<title>{name}</title>" not in index.read_text(encoding="utf-8"):
        raise PatchError(f"index.html: no <title>{name}</title>")
    for rel in MANIFESTS:
        try:
            m = json.loads((site / rel).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise PatchError(f"{rel}: {e}")
        if m.get("name") != name or m.get("short_name") != name:
            raise PatchError(f"{rel}: the app is not named {name}")

    # Pluma's icons and its name on the sign-in page.
    for rel, _ in patch.ICONS:
        p = site / rel
        if not p.is_file() or p.read_bytes() != (patch.BRAND / "web" / rel).read_bytes():
            raise PatchError(f"{rel}: not Pluma's (brand/web)")
    if (site / patch.SCREENSHOT[0]).exists():
        raise PatchError(f"{patch.SCREENSHOT[0]}: Telegram's screenshot is in the site")
    if f"Sign in to {name}" not in code or "Sign in to Telegram" in code or "Scan with Telegram" in code:
        raise PatchError(f"the code's sign-in page does not say {name}")
    return len(files)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--record", required=True, help=f"the {patch.RECORD} ci/patch.py left in the checkout")
    ap.add_argument("--target", required=True, help="server or dev, as ci/build.sh was asked")
    ap.add_argument("site", help="the site ci/build.sh assembled")
    a = ap.parse_args(argv)
    try:
        record = json.loads(pathlib.Path(a.record).read_text())
    except (OSError, ValueError) as e:
        print(f"check-bundle: {a.record}: {e}; is the checkout patched (ci/configure.sh)?", file=sys.stderr)
        return 1
    try:
        count = check(a.site, record, a.target)
    except PatchError as e:
        print(f"check-bundle: {e}", file=sys.stderr)
        return 1
    print(f"check-bundle: {count} files, no trace of Telegram's servers; "
          f"server {record['server_url']}, key {record['fingerprint']}, layer {record['layer']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
