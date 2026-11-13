#!/usr/bin/env python3
"""Turns a checkout of morethanwords/tweb (Telegram Web K) into the Pluma web client.

Every change is an exact edit: the text it replaces must occur the expected
number of times, or the whole run fails. An upstream update that moves any
of these places stops the build here instead of producing a client that
talks to Telegram or does not sign in. After the edits the result is checked
again (no Telegram server address or key is left in the sources), and
ci/check_bundle.py checks the built bundle the same way.

Standard library only, so the CI and a developer machine run it as is.
"""

import argparse
import base64
import hashlib
import ipaddress
import json
import pathlib
import re
import sys

# Telegram's networks (https://core.telegram.org/resources/cidr.txt): the
# datacenter addresses tweb carries for its HTTP transport, and any other a
# future version could add.
TELEGRAM_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.56.0/22",
    "149.154.160.0/20",
    "2001:b28:f23d::/48", "2001:b28:f23f::/48", "2001:67c:4e8::/48",
))

# What else marks a client that talks to Telegram, by kind (matched in any
# case):
TELEGRAM_TRACES = {
    # Telegram's server keys as tweb carries them (rsaKeysManager.ts: the
    # production and test keys, older production keys in a comment), as
    # hex moduli and PEM, and the fingerprints of the production and test keys.
    "server key": (
        "e8bb3305c0b52c6cf2afdf7637313489", "c8c11d635691fac091dd9489aedced29",
        "c150023e2f70db7985ded064759cfecf", "aeec36c8ffc109cb099624685b978154",
        "bdf2c77d81f6afd47bd30f29ac76e55a", "b3f762b739be98f343eb1921cf0148cf",
        "be6a71558ee577ff03023cfa17aab4e6",
        "MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaO", "MIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO",
        "MIIBCgKCAQEBadMIUYSKhyznMh+Pg+OxTLyDZrWE",
        "d09d1d85de64fd85", "b25898df208d2603",
    ),
    # The MTProto endpoints of Telegram's web clients (kws1.web.telegram.org,
    # pluto.web.telegram.org, ...) and the t.me session sync.
    "endpoint": (".web.telegram.org", "_websync_"),
    # The credentials of Telegram's own deployments: the api_hash tweb uses
    # on web.telegram.org, its web push key and GCM sender id.
    "credential": (
        "8da85b0d5bfe62527e5b244c209159c3",
        "BHEbKOXt-GD8MCTTYiAYT3I5R4MB0epIE7Tbbymj1uR0xJRE_7m27eXTVAC_P19TeZnO9413lRz-0oZ87JRPKPM",
        "122867383838",
    ),
}

_IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\.?\d)")
_IPV6 = re.compile(r"2001:0?b28:f23[df]:|2001:0?67c:0?4e8:", re.IGNORECASE)

# The build-time flags of tweb's MTProto transports (import.meta.env). The
# patch sets the first group; the second picks where MTProto runs (shared
# worker, service worker) and stays as upstream sets it.
TRANSPORT_FLAGS = {
    "VITE_MTPROTO_HAS_WS": "1",
    "VITE_MTPROTO_HAS_HTTP": "",
    "VITE_MTPROTO_HTTP": "",
    "VITE_MTPROTO_HTTP_UPLOAD": "",
    "VITE_MTPROTO_AUTO": "",
}
UPSTREAM_FLAGS = ("VITE_MTPROTO_WORKER", "VITE_MTPROTO_SW")

# What the patch leaves in the checkout for ci/check_bundle.py.
RECORD = ".pluma-patch.json"

# Pluma's icons and logos: the SVGs of the brand kit (brand/src) and what
# brand/render.sh renders from them (brand/web, at the paths of public/).
BRAND = pathlib.Path(__file__).resolve().parent.parent / "brand"


# The home datacenter: an account's state is kept under its auth key.
BASE_DC = "src/lib/accounts/authKeyFingerprint.ts"


class PatchError(Exception):
    pass


def telegram_traces(text):
    """Returns (kind, what) for every trace of Telegram's servers in text."""
    found = []
    for m in _IPV4.finditer(text):
        try:
            addr = ipaddress.ip_address(m.group())
        except ValueError:
            continue
        if any(addr in net for net in TELEGRAM_NETWORKS):
            found.append(("address", m.group()))
    found += [("address", m.group()) for m in _IPV6.finditer(text)]
    lower = text.lower()
    found += [(kind, s) for kind, needles in TELEGRAM_TRACES.items() for s in needles if s.lower() in lower]
    return found


# --- RSA key -----------------------------------------------------------------


def _der_read(data, pos, tag):
    if data[pos] != tag:
        raise PatchError(f"RSA key: DER tag {data[pos]:#x} at {pos}, expected {tag:#x}")
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    if pos + length > len(data):
        raise PatchError("RSA key: truncated DER")
    return data[pos:pos + length], pos + length


def parse_pkcs1_public_key(pem):
    """Returns (n, e) as big-endian bytes without leading zeros."""
    lines = [l.strip() for l in pem.strip().splitlines()]
    if not lines or lines[0] != "-----BEGIN RSA PUBLIC KEY-----" or lines[-1] != "-----END RSA PUBLIC KEY-----":
        raise PatchError("RSA key: expected a PKCS#1 PEM (BEGIN RSA PUBLIC KEY)")
    try:
        der = base64.b64decode("".join(lines[1:-1]), validate=True)
    except ValueError:
        raise PatchError("RSA key: the PEM body is not base64")
    try:
        seq, end = _der_read(der, 0, 0x30)
        if end != len(der):
            raise PatchError("RSA key: trailing data after the key")
        n, pos = _der_read(seq, 0, 0x02)
        e, pos = _der_read(seq, pos, 0x02)
    except IndexError:
        raise PatchError("RSA key: truncated DER")
    if pos != len(seq):
        raise PatchError("RSA key: unexpected fields in the key")
    return n.lstrip(b"\0"), e.lstrip(b"\0")


def _tl_bytes(b):
    if len(b) < 254:
        out = bytes([len(b)]) + b
    else:
        out = b"\xfe" + len(b).to_bytes(3, "little") + b
    return out + b"\0" * (-len(out) % 4)


def key_fingerprint(n, e):
    """MTProto fingerprint: the low 64 bits of SHA1 over the TL-serialized
    modulus and exponent (tweb computes it the same way from the hex)."""
    digest = hashlib.sha1(_tl_bytes(n) + _tl_bytes(e)).digest()
    return int.from_bytes(digest[-8:], "little")


# --- server URL --------------------------------------------------------------

_HOST_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")
_LOOPBACK = ("localhost", "127.0.0.1", "[::1]")


def parse_server_url(url):
    """The WebSocket URL of the server's MTProto gateway. wss:// for a real
    server; ws:// only on the machine of the browser: a page served over
    https may not open ws://, and a page served over http from elsewhere is
    no secure context (no service worker, no Web Crypto)."""
    m = re.fullmatch(r"(wss?)://(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::(\d{1,5}))?(/[A-Za-z0-9._~/-]*)", url)
    if not m:
        raise PatchError(f"server URL {url!r}: expected wss://<host>[:<port>]/<path>, e.g. wss://pluma.chat/apiws")
    scheme, host, port, path = m.groups()
    host = host.lower()
    if host.startswith("["):
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            raise PatchError(f"server URL {url!r}: {host} is not an IPv6 address")
    elif re.fullmatch(r"[\d.]+", host):
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            raise PatchError(f"server URL {url!r}: {host} is not an IPv4 address")
    elif len(host) > 253 or not all(_HOST_LABEL.fullmatch(l) for l in host.split(".")):
        raise PatchError(f"server URL {url!r}: {host} is not a host name")
    if port is not None and not 0 < int(port) < 65536:
        raise PatchError(f"server URL {url!r}: {port} is not a port")
    if scheme == "ws" and host not in _LOOPBACK:
        raise PatchError(f"server URL {url!r}: ws:// is for a server on this machine only (localhost); "
                         "a real server needs wss://")
    return f"{scheme}://{host}{':' + port if port else ''}{path}"


# --- Node.js engines -----------------------------------------------------------


def _version(s, what):
    m = re.fullmatch(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", s)
    if not m:
        raise PatchError(f"{what}: {s!r} is not a version")
    return tuple(int(x or 0) for x in m.groups())


def node_satisfies(version, spec):
    """Whether a Node.js version satisfies a package.json engines range:
    alternatives joined by ||, each a list of comparators (^, ~, >=, >, <=,
    <, = or a bare version)."""
    v = _version(version, "NODE_VERSION")
    alternatives = []
    for alternative in spec.split("||"):
        comparators = []
        for c in alternative.split():
            m = re.fullmatch(r"(\^|~|>=|>|<=|<|=)?(v?[\d.]+)", c)
            if not m:
                raise PatchError(f"engines.node {spec!r}: cannot read {c!r}; check NODE_VERSION by hand")
            comparators.append((m.group(1) or "=", _version(m.group(2), f"engines.node {spec!r}")))
        if not comparators:
            raise PatchError(f"engines.node {spec!r}: an empty alternative")
        alternatives.append(comparators)

    def holds(op, base):
        if op == "^":
            return base <= v < (base[0] + 1, 0, 0)
        if op == "~":
            return base <= v < (base[0], base[1] + 1, 0)
        return {">=": v >= base, ">": v > base, "<=": v <= base, "<": v < base, "=": v == base}[op]

    return any(all(holds(op, base) for op, base in comparators) for comparators in alternatives)


# --- edits -------------------------------------------------------------------


class Tree:
    def __init__(self, root):
        self.root = pathlib.Path(root)
        if not (self.root / "src/lib/mtproto/dcConfigurator.ts").is_file():
            raise PatchError(f"{root}: not a morethanwords/tweb checkout")

    def read(self, rel):
        return (self.root / rel).read_text(encoding="utf-8")

    def write(self, rel, text):
        (self.root / rel).write_text(text, encoding="utf-8")

    def replace(self, rel, old, new, count=1):
        text = self.read(rel)
        found = text.count(old)
        if found != count:
            raise PatchError(f"{rel}: {found} occurrences of {old!r}, expected {count}")
        self.write(rel, text.replace(old, new))

    def sub(self, rel, pattern, repl, count=1, flags=0):
        text = self.read(rel)
        out, found = re.subn(pattern, repl, text, flags=flags)
        if found != count:
            raise PatchError(f"{rel}: {found} matches of /{pattern}/, expected {count}")
        self.write(rel, out)

    def replace_body(self, rel, head, tail, body, must_contain=()):
        """Replaces what lies between head and the first tail after it."""
        text = self.read(rel)
        if text.count(head) != 1:
            raise PatchError(f"{rel}: {text.count(head)} occurrences of {head!r}, expected 1")
        start = text.index(head) + len(head)
        end = text.find(tail, start)
        if end < 0:
            raise PatchError(f"{rel}: no {tail!r} after {head!r}")
        for s in must_contain:
            if s not in text[start:end]:
                raise PatchError(f"{rel}: the replaced block has no {s!r}; upstream changed it")
        self.write(rel, text[:start] + body + text[end:])

    def replace_block(self, rel, head, tail, block, must_contain=()):
        """Replaces head, the first tail after it and what lies between."""
        text = self.read(rel)
        if text.count(head) != 1:
            raise PatchError(f"{rel}: {text.count(head)} occurrences of {head!r}, expected 1")
        start = text.index(head)
        end = text.find(tail, start + len(head))
        if end < 0:
            raise PatchError(f"{rel}: no {tail!r} after {head!r}")
        for s in must_contain:
            if s not in text[start:end]:
                raise PatchError(f"{rel}: the replaced block has no {s!r}; upstream changed it")
        self.write(rel, text[:start] + block + text[end + len(tail):])

    def replace_within(self, rel, head, tail, edits):
        """Makes the edits ((old, new, count), ...) between head and the first
        tail after it, where each old occurs count times."""
        text = self.read(rel)
        if text.count(head) != 1:
            raise PatchError(f"{rel}: {text.count(head)} occurrences of {head!r}, expected 1")
        start = text.index(head) + len(head)
        end = text.find(tail, start)
        if end < 0:
            raise PatchError(f"{rel}: no {tail!r} after {head!r}")
        body = text[start:end]
        for old, new, count in edits:
            if body.count(old) != count:
                raise PatchError(f"{rel}: {body.count(old)} occurrences of {old!r} after {head!r}, expected {count}")
            body = body.replace(old, new)
        self.write(rel, text[:start] + body + text[end:])

    def expect(self, rel, text, count=1):
        """Checks that text the patch relies on is there as it was."""
        found = self.read(rel).count(text)
        if found != count:
            raise PatchError(f"{rel}: {found} occurrences of {text!r}, expected {count}")

    def write_bytes(self, rel, data):
        (self.root / rel).write_bytes(data)

    def remove(self, rel):
        (self.root / rel).unlink()

    def sha256(self, rel):
        p = self.root / rel
        if not p.is_file():
            raise PatchError(f"{rel}: missing; upstream changed it")
        return hashlib.sha256(p.read_bytes()).hexdigest()

    def replace_file(self, rel, sha256, data):
        """Replaces a file that is the one expected (by its SHA-256); data
        None removes it."""
        found = self.sha256(rel)
        if found != sha256:
            raise PatchError(f"{rel}: SHA-256 {found}, expected {sha256}; upstream changed it")
        if data is None:
            self.remove(rel)
        else:
            self.write_bytes(rel, data)

    def sources(self):
        """The client's own sources: what the bundle is built from, without
        tests, their mocks and fixtures, and the build scripts."""
        for p in sorted((self.root / "src").rglob("*")):
            rel = p.relative_to(self.root).as_posix()
            if (p.suffix not in (".ts", ".tsx", ".js", ".mjs", ".scss") or not p.is_file()
                    or re.search(r"\.(test|spec)\.|^src/(tests|scripts|mock)/|/fixtures/", rel)):
                continue
            yield rel


# --- configuration -----------------------------------------------------------


def load_env(path):
    out = {}
    for n, line in enumerate(pathlib.Path(path).read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            raise PatchError(f"{path}:{n}: expected KEY=VALUE")
        out[key.strip()] = value.strip()
    return out


class Config:
    def __init__(self, upstream, app, server_url, rsa_pem, target, build_id):
        def need(env, key):
            if not env.get(key):
                raise PatchError(f"{key} is not set")
            return env[key]

        def number(env, key):
            value = need(env, key)
            if not re.fullmatch(r"[1-9]\d*", value):
                raise PatchError(f"{key} {value!r} is not a positive number")
            return int(value)

        self.layer = number(upstream, "UPSTREAM_LAYER")
        self.version = need(upstream, "UPSTREAM_VERSION")
        self.build = need(upstream, "UPSTREAM_BUILD")
        self.node = need(upstream, "NODE_VERSION")
        _version(self.node, "NODE_VERSION")
        self.pnpm = need(upstream, "PNPM_VERSION")

        self.app_name = need(app, "PLUMA_APP_NAME")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 .-]*", self.app_name):
            raise PatchError(f"PLUMA_APP_NAME {self.app_name!r}: letters, digits, spaces, dots and dashes only")
        self.api_id = number(app, "PLUMA_API_ID")
        self.api_hash = need(app, "PLUMA_API_HASH")
        if not re.fullmatch(r"[0-9a-f]{32}", self.api_hash):
            raise PatchError("PLUMA_API_HASH must be 32 lowercase hex digits")

        # The release of the site (update_prompts): the commit of this
        # repository it is built from, and the epoch of mandatory releases.
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", build_id):
            raise PatchError(f"build id {build_id!r}: the full commit hash of this repository")
        self.build_id = build_id
        epoch = need(app, "PLUMA_REQUIRED_EPOCH")
        if not re.fullmatch(r"0|[1-9]\d{0,8}", epoch):
            raise PatchError(f"PLUMA_REQUIRED_EPOCH {epoch!r} is not a number from 0")
        self.required_epoch = int(epoch)

        self.server_url = parse_server_url(server_url)

        n, e = parse_pkcs1_public_key(rsa_pem)
        if len(n) * 8 != 2048:
            raise PatchError(f"RSA key: {len(n) * 8} bits, the clients expect 2048")
        self.modulus = n.hex()
        self.exponent = e.hex()
        self.fingerprint = key_fingerprint(n, e)

        if target not in ("server", "dev"):
            raise PatchError(f"target {target!r}: server or dev")
        self.target = target

    def record(self):
        return {
            "target": self.target,
            "app_name": self.app_name,
            "api_id": self.api_id,
            "api_hash": self.api_hash,
            "layer": self.layer,
            "server_url": self.server_url,
            "modulus": self.modulus,
            "exponent": self.exponent,
            "fingerprint": f"{self.fingerprint:#018x}",
            "build_id": self.build_id,
            "required_epoch": self.required_epoch,
        }


# --- the patch ---------------------------------------------------------------


def patch_manifest(tree, rel, c):
    """The name of the installed app; no claim on t.me and telegram.me links,
    no GCM sender id of Telegram's web push and no screenshot of Telegram's
    interface for the install sheet."""
    m = json.loads(tree.read(rel))
    if m.get("name") != "Telegram Web" or m.get("short_name") != "Telegram Web" or "description" not in m:
        raise PatchError(f"{rel}: no name \"Telegram Web\" and description; upstream changed it")
    origins = [s.get("origin") for s in m.get("scope_extensions", [])]
    if origins != ["https://t.me", "https://telegram.me"]:
        raise PatchError(f"{rel}: scope_extensions {origins}, expected t.me and telegram.me; upstream changed it")
    if "gcm_sender_id" not in m:
        raise PatchError(f"{rel}: no gcm_sender_id; upstream changed it")
    screenshots = [s.get("src") for s in m.get("screenshots", [])]
    if screenshots != [SCREENSHOT[0]]:
        raise PatchError(f"{rel}: screenshots {screenshots}, expected {SCREENSHOT[0]}; upstream changed it")
    m["name"] = m["short_name"] = m["description"] = c.app_name
    del m["scope_extensions"], m["gcm_sender_id"], m["screenshots"]
    tree.write(rel, json.dumps(m, indent=4, ensure_ascii=False) + "\n")


# --- the brand -----------------------------------------------------------------
#
# Pluma's name, icons, link scheme and colours instead of Telegram's (task
# 017 of the server repository). What the user sees and the links the
# client makes change; keys, identifiers, file names, storage, the mini-app
# API (window.Telegram) and the URLs of Telegram's sites stay as they are.

# Where the footer of the menu points: the source of this build (GPL).
SOURCE_URL = "https://github.com/sckraaa/pluma-web"

# Pluma's icons and logos (brand/web, rendered from brand/src by
# brand/render.sh) over Telegram's, file for file: (path in public/, SHA-256
# of upstream's file). The file names stay: the page, the manifests and the
# code refer to them.
ICONS = (
    ("assets/img/android-chrome-144x144.png", "26de77d7358a970649c4d464f84fcb4792cdd1734b028218e8e6a1eb058eea97"),
    ("assets/img/android-chrome-192x192.png", "25aa724658da8e71f5cc7c35ccbb43075866af5bed964edb09979caace667b0b"),
    ("assets/img/android-chrome-256x256.png", "c79b93e9363f51defd6b5553b95eff52fe981224ca59377f6d03e735f0d60047"),
    ("assets/img/android-chrome-36x36.png", "ab5b4acf3dd5f492328173bff187337e40306d75a1391c6c63d0098836a3e2eb"),
    ("assets/img/android-chrome-384x384.png", "46b3e824026103c48696e4a38c8c5dcb04bdb5999c1fa22650637812ffc7a51e"),
    ("assets/img/android-chrome-48x48.png", "d81b6945766e03d375eafd31ad4c133846eadc67ce4a990a09b2443150d664c7"),
    ("assets/img/android-chrome-512x512.png", "7b5056e3a67bf8af7221fb4150355a0c837c0eef4d7d68a7540a7b4879e9d64a"),
    ("assets/img/android-chrome-72x72.png", "728cf233c46950970b075e48e43dea0953950d7199239902a3a77cdbdc3105c8"),
    ("assets/img/android-chrome-96x96.png", "3b81f06abd10b77e6cd1459abebb3ed0f561182cafb3202c5eb60791b75db29d"),
    ("assets/img/apple-touch-icon-precomposed.png", "565ea1384a3192a5157aaf7778e611b43ffbee16c48eafb1fc125ab7447f5860"),
    ("assets/img/apple-touch-icon.png", "926cc27874313cb1f3a6fc23d89d98d5cde0e63a3bfd360beb5d02e9c62ea38e"),
    ("assets/img/favicon-16x16.png", "0d67b7e8ea46e3c959329a0e79a8c8b236187f452edc7049524245e4aa6bee21"),
    ("assets/img/favicon-194x194.png", "acea3f3abb19dcc93bfa9bdf04ca72c486f2cebb92763b1bc61a597e4af27077"),
    ("assets/img/favicon-32x32.png", "8e18aee6e70418e31cb2bb69f441ef33083586dd3a5c5d1d335562b840a9ac87"),
    ("assets/img/favicon.ico", "7e2388ec283fe17472ef02829a93da550af8f3ad4a975f50a0110bff61afe523"),
    ("assets/img/favicon_unread.ico", "56961b80cb7fb1c6e77c9b1dcf1d995f892e06188f6192732410155ad453edb4"),
    ("assets/img/icon_square_192.png", "2e56ea0195c439c727e5600fbb176970a538adb90528181364e7958f85cd0710"),
    ("assets/img/icon_square_384.png", "9b4fa9782486ef7df3c2f26bad6db92ebff7fa680f3e4dcd3fdbb89e140b97e5"),
    ("assets/img/icon_square_512.png", "b2ae9d5c074651e5b8f046b721c2347e9a1b24c889955f3b53e7fc56b4c2d7ab"),
    ("assets/img/logo.svg", "99af9dbb97466c5aee7f24d195945670173a53674c6b0c54145b85cfa4de2f9a"),
    ("assets/img/logo_512.png", "fca7b065e3ec334e6079df22d6d9ff995de72ffa8f22624fefcd0f80b30f9168"),
    ("assets/img/logo_filled.svg", "f85f2b6f6742602656fecf24cc7db86c688d80d156603812043da8b1dc6f9ac6"),
    ("assets/img/logo_filled_rounded.png", "8ab1180b4a61c62cff09a758560a0de4dcbc0e1f5ba9964b38d06b8c7d8dbc56"),
    ("assets/img/logo_padded.svg", "eeb79b0ae5da35d3433de6edeec3a0e3cce9c24f517dbad26ed97e852666c8f4"),
    ("assets/img/logo_plain.svg", "9965ccf211b32e0b65422e36104457981488eda7846a159e8194bead08efebd7"),
    ("assets/img/masked copy.svg", "c5d4d2bf0a128dcfcea1a2dc2a60c54801aa0c5cb6a82463c2e3cb0d01d0ea87"),
    ("assets/img/masked.svg", "69303a550a2d739ec1e9d5cf7704dc9e09fc05886b190780ec96c1cbefbabf92"),
    ("assets/img/mstile-144x144.png", "38f3f7b80b5b511de76b9d1b3f18803e532eb896081acf2ab96e581d1df219e7"),
    ("assets/img/mstile-150x150.png", "38293e121dc13c201f737fcfdb004f9edc8234f257373bb61f32844299bc7523"),
    ("assets/img/mstile-310x150.png", "4b7b6fd06c7d9331a5b6a97857a1577cee15dcd18535d120bb3f98b7bbed8714"),
    ("assets/img/mstile-310x310.png", "c711dbfec7bbab5b812b3ff36a18d41ab9a492739d93ba950cfcdfc3e212ff0e"),
    ("assets/img/mstile-70x70.png", "1c0d3d1571e91eceebd4441fcfb4e3b2643cc5cd01fbbba95d80ee56f3fccf4a"),
    ("assets/img/safari-pinned-tab.svg", "69303a550a2d739ec1e9d5cf7704dc9e09fc05886b190780ec96c1cbefbabf92"),
)

# Telegram's interface in a screenshot, for the install sheet of the web app
# (path in public/, SHA-256): removed, and the manifests lose it.
SCREENSHOT = ("assets/img/screenshot.jpg", "af2c7c5422f764adbc7f2f1febc254c978dc7d05d97b5d7934c15eeef6e8c1f0")

# Upstream's message about the new version, put in the service chat of every
# signed-in account once per version: it names Telegram and Telegram Premium
# and links to t.me. A version with no file has no message
# (apiUpdatesManager.deliverChangelog): (path in public/, SHA-256), removed.
CHANGELOGS = (
    ("changelogs/en_2.3.md", "620765b8b83588fd97cb9f3911a1ccb45cdb89683a2d13fe0bb5c57ca083eaad"),
    ("changelogs/ru_2.3.md", "2b945d67852625b00ecc77fd39dbeedaecbab344c312e16472db7a10741663a0"),
)

# The built-in English strings. The word Telegram in a value becomes the
# app's name ("Pluma Premium", "Sign in to Pluma"); in a key, a comment or a
# URL (t.me/TelegramTips) it stays: (file, words renamed, words left).
STRINGS = (
    ("src/lang.ts", 272, 45),
    ("src/langSign.ts", 7, 0),
)
_STRING_ENTRY = re.compile(r"^(\s*'(?:[^'\\]|\\.)*':\s*)(.*)$")
_TELEGRAM_WORD = re.compile(r"(?:(?<![\w./@-])|(?<=\\n))Telegram(?!\w)")

# The link scheme: Pluma's apps speak plm://, so that tg:// stays with
# Telegram's apps installed beside them, and a QR code of one signs in only
# Pluma's. The links the client makes: (file, text, occurrences); wrapUrl
# reads plm: links (rebrand) and gives them to the same handlers (tg_*).
PLM_LINKS = (
    ("src/pages/cards/SignQRCard.tsx", "'tg://login?token='", 1),
    ("src/components/instantView.tsx", "'tg://iv?url='", 2),
    ("src/lib/richTextProcessor/wrapTelegramRichText.ts", "'tg://iv?url='", 1),
    ("src/components/wrappers/joinVoiceChatAnchor.ts", "`tg://voicechat?", 1),
    ("src/lib/richTextProcessor/wrapRichText.ts", "'tg://bot_command?", 1),
    ("src/lib/richTextProcessor/index.ts", "'tg://search_hashtag?", 1),
    ("src/lib/settingsSearch/link.ts", "'tg://settings'", 1),
    # A TON address in a message.
    ("src/lib/richTextProcessor/wrapRichText.ts", "'tg://sendgrams?to='", 1),
    # The rich message composer and its checks: the schemes a link may have,
    # and a mention written as a link.
    ("src/components/chat/inputEditor/richMessage.ts", "url.startsWith('tg://user?')", 1),
    ("src/helpers/string/normalizeLinkUrl.ts", "  'tg:',\n", 1),
    ("src/helpers/string/normalizeLinkUrl.ts", "url.protocol === 'tg:'", 1),
    ("src/lib/appManagers/utils/richMessage/validateRichMessage.ts", "['http:', 'https:', 'tg:', 'tonsite:']", 1),
    # What makes the composer's text a candidate for an automatic link.
    ("src/lib/richTextProcessor/inferRichMessageNoAutolink.ts", "|tg:\\/\\/|", 1),
    # What a plm: link nothing handles is told apart by.
    ("src/lib/internalLinkProcessor.ts", "element.href.replace(/^tg:(?:", 1),
)
_TG_LINK = re.compile(r"['\"`]tg:|\^tg:|\btg:\\?/\\?/")
_COMMENT = re.compile(r"/\*.*?\*/|(?<![:\\])//[^\n]*", re.S)

# The accent of the light theme (the dark one's is #9dbb9f): the Windows
# tile and the unread count drawn over the favicon.
ACCENT = "#5b7a5e"

# The colours of the default light (day) and dark (night) themes, "graphite
# and sage": (colour, upstream's, Pluma's). The light, dark-blue and
# accent presets the user picks stay as upstream has them.
THEME_COLORS = {
    "day": (
        ("primary-color", "#3390ec", "#5b7a5e"),
        ("message-out-primary-color", "#5CA853", "#5b7a5e"),
        ("message-background-color", "#ffffff", "#f1f2f0"),
        ("primary-text-color", "#000000", "#111111"),
        ("secondary-text-color", "#707579", "#6b6f6b"),
        ("saved-color", "#359AD4", "#5b7a5e"),
        ("background-color", "#f4f4f5", "#f4f5f4"),
        ("border-color", "#dfe1e5", "#dfe2df"),
        ("secondary-color", "#c4c9cc", "#c4c9c4"),
    ),
    "night": (
        ("primary-color", "#8774E1", "#9dbb9f"),
        ("message-out-primary-color", "#8774E1", "#b2ceb4"),
        ("message-background-color", "#212121", "#232623"),
        ("surface-color", "#212121", "#131513"),
        ("primary-text-color", "#ffffff", "#e8ece8"),
        ("secondary-text-color", "#aaaaaa", "#9aa29a"),
        ("saved-color", "#8774E1", "#9dbb9f"),
        ("background-color", "#181818", "#0c0e0c"),
        ("body-background-color", "#181818", "#0c0e0c"),
        ("border-color", "#0f0f0f", "#070807"),
        ("secondary-color", "#707579", "#6e756e"),
        ("input-search-background-color", "#181818", "#0c0e0c"),
    ),
}

# The default themes' settings (state.ts): the accent, the outgoing bubble
# (Web K draws no gradient: the first colour of the palette's), its time and
# checks (outbox accent), and the wallpaper's gradient, sage instead of
# Telegram's green and purple-blue; (Telegram's, Pluma's).
THEME_SETTINGS = (
    ("    accent_color: 0x3390ec,\n    message_colors: [0x5CA853],\n",
     "    // pluma: graphite and sage.\n"
     "    accent_color: 0x5B7A5E,\n    message_colors: [0xE3EAE2],\n    outbox_accent_color: 0x5B7A5E,\n"),
    ("        background_color: 0xdbddbb,\n        second_background_color: 0x6ba587,\n"
     "        third_background_color: 0xd5d88d,\n        fourth_background_color: 0x88b884\n",
     "        background_color: 0xd5ddd3,\n        second_background_color: 0x8fa992,\n"
     "        third_background_color: 0xc9d4c5,\n        fourth_background_color: 0xa3b8a4\n"),
    ("    accent_color: 0x8774E1,\n    message_colors: [0x8774E1],\n",
     "    // pluma: graphite and sage.\n"
     "    accent_color: 0x9DBB9F,\n    message_colors: [0x2C3A2D],\n    outbox_accent_color: 0xB2CEB4,\n"),
    ("        background_color: 0xfec496,\n        second_background_color: 0xdd6cb9,\n"
     "        third_background_color: 0x962fbf,\n        fourth_background_color: 0x4f5bd5\n",
     "        background_color: 0x9dbb9f,\n        second_background_color: 0x4f6e52,\n"
     "        third_background_color: 0x7fa082,\n        fourth_background_color: 0x5b7a5e\n"),
    # What the wallpapers' average gives (highlightingColor), until the
    # client computes it: service messages, and the title bar of the
    # installed app on a desktop.
    ("  baseThemeClassic: 'hsla(86.4, 43.846153%, 45.117647%, .4)',\n"
     "  baseThemeNight: 'hsla(299.142857, 44.166666%, 37.470588%, .4)',\n",
     "  baseThemeClassic: 'hsla(120, 26.503759%, 48.049019%, .4)',\n"
     "  baseThemeNight: 'hsla(123.870967, 26.115537%, 33.009803%, .4)',\n"),
)

# People's identity colours: the seven Telegram gives a user or chat by its
# id, or the one a user picked (getPeerColorIndexByPeer: peer.color, else
# id % 7), in the order of DialogColors. Web K draws each with a letter
# avatar gradient, the same in every theme (base.scss, avatar-color: top,
# bottom), and a name colour for names in groups and the bars of replies and
# link previews (getPeerColorById.ts, DialogColorsFg): one for every theme,
# unless the server's help.getPeerColors gives colours for the identity
# (setPeerColors, replaceColors). Ids 7 and above have the server's colours
# only and stay as they are.
IDENTITIES = ("red", "orange", "violet", "green", "cyan", "blue", "pink")

# Pluma's identity colours; the other five stay Telegram's. Blue is the
# palette's sage and cyan a teal without Telegram's blue. A dark theme takes
# its own name colour where Pluma's differs from the light one: blue a light
# sage, cyan the one of Telegram's Android app at night, a teal as well
# (upstream has no dark name colour of its own: None).
# (colour, upstream's, Pluma's)
IDENTITY_COLORS = {
    "cyan": (
        ("avatar top", "#53edd6", "#5BCBC4"),
        ("avatar bottom", "#28c9b7", "#2C9C98"),
        ("name", "#309EBA", "#1F8A80"),
        ("dark name", None, "#53CCC6"),
    ),
    "blue": (
        ("avatar top", "#5CAFFA", "#7FA082"),
        ("avatar bottom", "#408ACF", "#5B7A5E"),
        ("name", "#368AD1", "#4F6E52"),
        ("dark name", None, "#9DBB9F"),
    ),
}
_IDENTITY_KEYS = ("avatar top", "avatar bottom", "name", "dark name")

# Telegram's blue avatar gradient as a plain blue, the avatar of Archived
# Chats in the chat list and the icon of its popup: the identity's avatar
# colours, sage. (file, identity)
IDENTITY_AS_PLAIN = (
    ("src/components/archiveDialog.module.scss", "blue"),
    ("src/components/featureDetailsIconSticker.module.scss", "blue"),
)

# White text and icons on an accent fill. The dark theme's accent is a light
# sage, so they take --on-primary-color, which themeController sets from
# the accent: dark on a light one, white on the others. (file, rule): the
# one colour declaration in each changes.
ON_PRIMARY = (
    ("src/scss/partials/_button.scss",
     ".btn-color-primary {\n" "  background: var(--primary-color);\n" "  color: #fff;\n"),
    ("src/scss/partials/_button.scss",
     "  background-color: var(--primary-color);\n" "  text-align: center;\n" "  font-size: 1.5rem;\n"
     "  color: #fff;\n"),
    ("src/scss/partials/_chat.scss",
     "\t.btn-send {\n" "    --size: 2.5rem;\n" "    color: #fff !important;\n" "    background-color: var(--primary-color) !important;\n"),
    ("src/scss/partials/_chat.scss",
     "      background-color: var(--primary-color);\n" "      display: flex;\n" "      align-items: center;\n"
     "      padding: 0 .75rem;\n" "      // justify-content: center;\n"
     "      margin-inline-start: var(--commands-margin-left);\n" "      cursor: pointer;\n" "      color: #fff;\n"),
    ("src/scss/partials/_chat.scss",
     "        background-color: var(--primary-color);\n" "        font-size: 1.375rem;\n" "        color: #fff;\n"),
    ("src/scss/partials/_chatInlineHelper.scss",
     "          &.empty {\n" "            color: #fff;\n" "            text-transform: uppercase;\n"
     "            font-size: 1.75rem;\n" "            background-color: var(--primary-color);\n"),
    ("src/scss/partials/_chatMarkupTooltip.scss",
     "\t\t&.active {\n" "\t\t\tcolor: #fff !important;\n" "\t\t\tbackground-color: var(--primary-color) !important;\n"),
    ("src/scss/partials/_chatPinned.scss",
     "    background-color: var(--primary-color);\n" "    color: #fff;\n" "    border: none;\n"),
    ("src/scss/partials/_checkbox.scss",
     "      use {\n" "        stroke: #fff;\n"),
    ("src/scss/partials/_poll.scss",
     "        color: #fff;\n" "        background: var(--primary-color);\n"),
    ("src/scss/partials/_searchSuper.scss",
     "        color: #fff;\n" "        text-transform: uppercase;\n" "        background-color: var(--primary-color);\n"),
    ("src/scss/partials/_topbarSearch.scss",
     "          background-color: var(--primary-color) !important;\n" "          color: #fff;\n"),
    ("src/scss/partials/_voiceRecordingPanel.scss",
     "    background-color: var(--primary-color);\n" "    color: #fff !important;\n"),
    ("src/scss/partials/_leftSidebar.scss",
     "      color: var(--badge-text-color) !important;\n"
     "      background-color: var(--primary-color) !important;\n"),
    ("src/scss/partials/popups/_datePicker.scss",
     "        color: var(--badge-text-color) !important;\n"
     "        background-color: var(--primary-color) !important;\n"),
    ("src/scss/partials/popups/_datePicker.scss",
     "      &.active {\n" "        color: var(--badge-text-color);\n" "\n" "        &::before {\n"
     "          background-color: var(--primary-color) !important;\n"),
    ("src/scss/partials/popups/_giftPremium.scss",
     "    background-color: var(--primary-color);\n" "    border-radius: 6px;\n" "    color: #fff;\n"),
    ("src/components/call/callLogo.module.scss",
     "  background-color: var(--primary-color);\n" "  color: #fff;\n"),
    ("src/components/featureDetailsIconSticker.module.scss",
     "  background-color: var(--primary-color);\n" "\n" "  color: white;\n"),
    ("src/components/popups/sendGift.module.scss",
     "  background-color: var(--primary-color);\n" "  color: #fff;\n"),
    ("src/components/popups/starGiftValue.module.scss",
     "  background: var(--primary-button-color);\n" "  color: #fff;\n"),
    ("src/components/wallet/tonConnect/tonConnect.module.scss",
     "  background-color: var(--primary-color);\n" "  color: #fff;\n"),
    ("src/components/chat/inputEditor/style.scss",
     "    background-color: var(--primary-color);\n" "    border: 0;\n" "    border-radius: .3125rem;\n" "    color: #fff;\n"),
    ("src/components/popups/webAppLocationAccess.module.scss",
     "  background: var(--primary-color);\n" "  color: var(--white);\n"),
)
_WHITE_ON_PRIMARY = re.compile(r"(?<![\w-])((?:color|stroke): )(?:#fff|white|var\(--white\)|var\(--badge-text-color\))")

# The verified badge (generateVerifiedIcon.ts) of verified users, bots,
# groups and channels, wherever a name carries it: Telegram's rosette, a
# symbol of index.html with the check cut out of it, over a square that
# shows through as the check. The rosette is the theme's accent, as upstream
# draws it, so it is sage in Pluma's themes; the check is what sits on an
# accent fill (--on-primary-color): white as upstream has it on a dark
# accent, dark on the dark theme's light sage. The selected chat and a
# profile over its photo turn the rosette over and hide the check, as
# upstream does (the selected chat's colours are changed with the rest of
# that row). (file, upstream's, Pluma's)
VERIFIED_BADGE = (
    ("src/scss/base.scss",
     ".verified-icon {\n  &-svg {\n    width: 1rem;\n    height: 1rem;\n  }\n\n"
     "  &-check {\n    fill: #fff;\n  }\n\n"
     "  &-background {\n    fill: var(--primary-color);\n  }\n}\n",
     ".verified-icon {\n  &-svg {\n    width: 1rem;\n    height: 1rem;\n  }\n\n"
     "  &-check {\n    fill: var(--on-primary-color); // pluma: what sits on the accent\n  }\n\n"
     "  &-background {\n    fill: var(--primary-color);\n  }\n}\n"),
    # The verification row of a profile draws the rosette in the grey of its
    # text, no accent fill: the check stays white there, as upstream has it.
    ("src/scss/partials/_profile.scss",
     "    .verified-icon {\n      &-background {\n        fill: currentColor;\n      }\n    }\n",
     "    .verified-icon {\n      &-background {\n        fill: currentColor;\n      }\n\n"
     "      &-check {\n        fill: #fff; // pluma: a grey rosette, not the accent fill\n      }\n    }\n"),
)
# What these colours rely on: the badge's two layers, the square under the
# rosette that shows through as the check, as upstream draws them.
# (file, text)
VERIFIED_BADGE_SHAPE = (
    ("src/components/generateVerifiedIcon.ts",
     "  use.setAttributeNS(null, 'href', '#verified-icon-background');\n"
     "  use.classList.add('verified-icon-background');\n"),
    ("src/components/generateVerifiedIcon.ts",
     "  use2.setAttributeNS(null, 'href', '#verified-icon-check');\n"
     "  use2.classList.add('verified-icon-check');\n"),
    ("src/components/generateVerifiedIcon.ts", "  svg.append(use2, use);\n"),
    ("index.html", '        <path id="verified-icon-check" d="M8 8H18V18H8V8Z" />\n'),
)
# A white check of the badge in a stylesheet: only the profile's grey one.
_WHITE_CHECK = re.compile(r"&-check \{\n\s*fill: (?:#fff\b|#ffffff\b|white\b|var\(--white\))", re.IGNORECASE)


def verify_verified_badge(sources):
    for rel, _, new in VERIFIED_BADGE:
        if sources[rel].count(new) != 1:
            raise PatchError(f"{rel}: the verified badge is not in Pluma's colours")
    for rel, text in sources.items():
        found = len(_WHITE_CHECK.findall(text)) if rel.endswith(".scss") else 0
        if found != (1 if rel == VERIFIED_BADGE[1][0] else 0):
            raise PatchError(f"{rel}: {found} white checks of the verified badge; on the accent it is "
                             "--on-primary-color")


def mark_logo():
    """The sign-in page's logo, from brand/src/pluma-mark.svg: the ring in
    the theme's text colour and the feathers in it at the opacities that
    give the kit's greys on white, so that it reads on a dark theme too.
    160 units square, as the logo it replaces."""
    svg = (BRAND / "src/pluma-mark.svg").read_text(encoding="utf-8")
    if 'viewBox="64 80 392 336"' not in svg:
        raise PatchError("brand/src/pluma-mark.svg: not the viewBox 64 80 392 336 the logo is laid out for")
    strokes = re.findall(r'<path fill="none" stroke="#([0-9A-F]{6})" stroke-width="(\d+)"([^>]*?) d="([^"]+)"/>', svg)
    if [s[0] for s in strokes] != ["111111", "4A4A4A", "8A8A8A", "BDBDBD"]:
        raise PatchError("brand/src/pluma-mark.svg: not the ring and three feathers in the kit's greys")
    paths = []
    for color, width, rest, d in strokes:
        opacity = (255 - int(color[:2], 16)) / (255 - 0x11)
        attrs = f' stroke-width="{width}"' + (f' stroke-opacity="{opacity:.2f}"' if opacity < 1 else "")
        if "stroke-linejoin" in rest:
            attrs += ' stroke-linejoin="round"'
        paths.append(f'<path{attrs} d="{d}"/>')
    # The mark is 392 units wide around (260, 248): 152 of the 160.
    return ('<g id="logo" fill="none" stroke-linecap="round" style="stroke: var(--primary-text-color)" '
            'transform="translate(80 80) scale(.3878) translate(-260 -248)">' + "".join(paths) + "</g>")


def rename_strings(tree, rel, name, renamed, left):
    """The word Telegram in the values of a language file becomes name."""
    count = 0
    lines = []
    for line in tree.read(rel).split("\n"):
        m = _STRING_ENTRY.match(line)
        if m:
            value, n = _TELEGRAM_WORD.subn(name, m.group(2))
            line = m.group(1) + value
            count += n
        lines.append(line)
    text = "\n".join(lines)
    if count != renamed:
        raise PatchError(f"{rel}: Telegram in {count} strings, expected {renamed}; review the new ones")
    if text.count("Telegram") != left:
        raise PatchError(f"{rel}: Telegram {text.count('Telegram')} times in keys, comments and URLs, "
                         f"expected {left}; review the new ones")
    tree.write(rel, text)


PEER_COLORS = "src/lib/appManagers/utils/peers/getPeerColorById.ts"
_NAME_COLORS = re.compile(r"^const DialogColorsFg: Array<string\[\]> = \[(\['#[0-9A-Fa-f]{6}'\](?:, \['#[0-9A-Fa-f]{6}'\])*)\];$",
                          re.M)


def identity_colors(tree):
    """People's identity colours as IDENTITY_COLORS has them: the letter
    avatars (and the notification's picture, which reads their colours), the
    name colours of the light themes and of the dark ones, and the places
    that take an identity's avatar gradient as a plain colour."""
    rel = PEER_COLORS
    tree.expect("src/lib/appManagers/utils/peers/dialogColors.ts",
                "export const DialogColors = [" + ", ".join(f"'{n}'" for n in IDENTITIES) + "] as const;\n")
    colors = {}
    for identity, table in IDENTITY_COLORS.items():
        if identity not in IDENTITIES or tuple(k for k, _, _ in table) != _IDENTITY_KEYS:
            raise PatchError(f"IDENTITY_COLORS: {identity!r}: one of {IDENTITIES}, with {_IDENTITY_KEYS}")
        colors[identity] = {k: (old, new) for k, old, new in table}

    # The letter avatars.
    for identity, c in colors.items():
        tree.replace("src/scss/base.scss",
                     f'  @include avatar-color("{identity}", {c["avatar top"][0]}, {c["avatar bottom"][0]});\n',
                     f'  @include avatar-color("{identity}", {c["avatar top"][1]}, {c["avatar bottom"][1]}); // pluma\n')
    # The wallet's own blue, Telegram's blue identity at its end.
    tree.replace("src/components/wallet/wallet.module.scss", "background: linear-gradient(#70a7db, #408acf);",
                 "background: linear-gradient(var(--peer-avatar-blue-top), var(--peer-avatar-blue-bottom)); // pluma")
    for plain, identity in IDENTITY_AS_PLAIN:
        if identity not in colors:
            raise PatchError(f"IDENTITY_AS_PLAIN: {identity!r} is not in IDENTITY_COLORS")
        c = colors[identity]
        tree.replace(plain, f"background: linear-gradient({c['avatar top'][0]}, {c['avatar bottom'][0]});",
                     f"background: linear-gradient(var(--peer-avatar-{identity}-top), "
                     f"var(--peer-avatar-{identity}-bottom)); // pluma: the {identity} identity's")

    # The name colours: Pluma's of the light themes in the built-in list.
    found = _NAME_COLORS.findall(tree.read(rel))
    if len(found) != 1:
        raise PatchError(f"{rel}: {len(found)} lists DialogColorsFg of one colour per identity, expected 1")
    names = re.findall(r"'(#[0-9A-Fa-f]{6})'", found[0])
    if len(names) != len(IDENTITIES):
        raise PatchError(f"{rel}: DialogColorsFg has {len(names)} colours, expected {len(IDENTITIES)}")
    old_names = list(names)
    for identity, c in colors.items():
        i = IDENTITIES.index(identity)
        if names[i] != c["name"][0]:
            raise PatchError(f"{rel}: the name colour of {identity} is {names[i]}, expected {c['name'][0]}; "
                             "upstream changed it")
        names[i] = c["name"][1]

    def name_list(values):
        return "const DialogColorsFg: Array<string[]> = [" + ", ".join(f"['{v}']" for v in values) + "];\n"

    tree.replace(rel, name_list(old_names),
                 f"// pluma: Pluma's {' and '.join(colors)}; the light themes' colours.\n" + name_list(names))
    # A dark theme's own where Pluma's differ. Web K keeps one name colour
    # for every theme and takes a dark one only from the server's
    # help.getPeerColors. setPeerColors also writes a theme's colours over
    # the built-in list, which the next theme would start from: it starts
    # from a copy.
    dark = ", ".join(f"{IDENTITIES.index(identity)}: ['{c['dark name'][1]}']" for identity, c in colors.items()
                     if c["dark name"][1] != c["name"][1])
    tree.replace(rel, "const _DialogColorsFg = DialogColorsFg;\n",
                 "// pluma: a dark theme's name colours where Pluma's differ from the light\n"
                 "// ones above.\n"
                 f"const DialogColorsFgNight: {{[colorId: number]: string[]}} = {{{dark}}};\n"
                 "\n"
                 "// pluma: a copy: setPeerColors writes a theme's colours into DialogColorsFg,\n"
                 "// and the next theme starts from the built-in ones.\n"
                 "const _DialogColorsFg = DialogColorsFg.slice();\n")
    tree.replace(rel,
                 "  let newColors = replaceColors(_DialogColorsFg.slice(), peerColorOptions);\n"
                 "  if(themeController.isNight()) {\n",
                 "  // pluma: the theme's built-in colours, then the server's.\n"
                 "  const isNight = themeController.isNight();\n"
                 "  let newColors = replaceColors(\n"
                 "    _DialogColorsFg.map((colors, colorId) => (isNight && DialogColorsFgNight[colorId]) || colors),\n"
                 "    peerColorOptions\n"
                 "  );\n"
                 "  if(isNight) {\n")


def rebrand(tree, c):
    name = c.app_name

    # Icons and logos.
    for rel, sha256 in ICONS:
        tree.replace_file("public/" + rel, sha256, (BRAND / "web" / rel).read_bytes())
    tree.replace_file("public/" + SCREENSHOT[0], SCREENSHOT[1], None)
    # The file the message about this version is read from.
    tree.expect("src/lib/appManagers/apiUpdatesManager.ts",
                "fetch(`changelogs/${lang}_${newVersion.split(' ')[0]}.md`)")
    for rel, sha256 in CHANGELOGS:
        tree.replace_file("public/" + rel, sha256, None)
    # The sign-in page's logo, a symbol of the page used as 160 units square.
    tree.replace_block("index.html", '        <path id="logo" fill-rule="evenodd" d="M80,0 ', '"/>\n',
                       "        " + mark_logo() + "\n",
                       must_contain=("M114.262551,46.4516129",))
    tree.expect("src/pages/cards/SignInCard.tsx",
                '<svg class={styles.logo} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 160 160">\n'
                '                <use href="#logo"/>\n')
    # The QR code's logo (logo_padded.svg) carries its own colours: the code
    # tints the first CSS fill of the file, and Pluma's has none.
    tree.expect("src/helpers/qrCode/paintQrCode.ts", "text.replace(/(fill:).+?(;)/, `$1${logoColor}$2`)")
    # Windows tiles.
    tree.replace("index.html", '    <meta name="msapplication-TileColor" content="#2d89ef">\n',
                 f'    <meta name="msapplication-TileColor" content="{ACCENT}">\n')
    tree.replace("public/browserconfig.xml", "<TileColor>#2d89ef</TileColor>", f"<TileColor>{ACCENT}</TileColor>")
    # The unread count over the favicon.
    tree.replace("src/lib/uiNotificationsManager.ts", "    ctx.fillStyle = '#3390ec';\n",
                 f"    ctx.fillStyle = '{ACCENT}'; // pluma: the accent\n")

    # The name.
    for rel, renamed, left in STRINGS:
        rename_strings(tree, rel, name, renamed, left)
    side = "src/components/sidebarLeft/index.ts"
    tree.replace(side,
                 "  btnMenuFooter.href = 'https://github.com/morethanwords/tweb/blob/master/CHANGELOG.md';\n",
                 "  // pluma: the source of this build.\n"
                 f"  btnMenuFooter.href = '{SOURCE_URL}';\n")
    tree.expect(side, "  t.textContent = getAppVersionText();\n")
    tree.replace("src/config/app.ts", "  return `Telegram Web${App.suffix} ${App.version} (${App.build})`;\n",
                 f"  return `{name} Web ${{App.version}} (${{App.build}})`;\n")
    tree.replace("src/lib/appManagers/apiUpdatesManager.ts",
                 "const pre = `**Telegram Web${App.suffix} ${langStr} ${newVersion}**\\n\\n`;",
                 f"const pre = `**{name} Web ${{langStr}} ${{newVersion}}**\\n\\n`;")
    # The service account (777000) until the server's user arrives.
    tree.replace("src/lib/appManagers/appMessagesManager.ts", "        first_name: 'Telegram',\n        phone: '42777'",
                 f"        first_name: '{name}',\n        phone: '42777'")
    push = "src/lib/serviceWorker/push.ts"
    tree.replace(push, "    push_message_error: 'Telegram is syncing in the background...',\n",
                 f"    push_message_error: '{name} is syncing in the background...',\n")
    tree.replace(push, "ctx.registration.showNotification('Telegram Web', {", f"ctx.registration.showNotification('{name}', {{")
    tree.replace(push, "  let title = obj.title || 'Telegram';\n", f"  let title = obj.title || '{name}';\n")
    tree.replace(push, "    title = 'Telegram';\n    body = lang.push_message_nopreview;\n",
                 f"    title = '{name}';\n    body = lang.push_message_nopreview;\n")

    # Entry points to Telegram's own services, of no use with Pluma.
    tree.replace(side,
                 "    }, {\n"
                 "      icon: 'help',\n"
                 "      text: 'TelegramFeatures',\n"
                 "      onClick: () => {\n"
                 "        const url = I18n.format('TelegramFeaturesUrl', true);\n"
                 "        appImManager.openUrl(url);\n"
                 "      },\n"
                 "      separator: !App.isMainDomain\n"
                 "    }, {\n"
                 "      icon: 'bug',\n"
                 "      text: 'ReportBug',\n"
                 "      onClick: () => {\n"
                 "        const a = document.createElement('a');\n"
                 "        setBlankToAnchor(a);\n"
                 "        a.href = 'https://bugs.telegram.org/?tag_ids=40&sort=time';\n"
                 "        document.body.append(a);\n"
                 "        a.click();\n"
                 "        setTimeout(() => {\n"
                 "          a.remove();\n"
                 "        }, 0);\n"
                 "      }\n"
                 "    }, {\n",
                 "    }, {\n"
                 "      // pluma: no \"Telegram Features\" (t.me/TelegramTips) and \"Report Bug\"\n"
                 "      // (bugs.telegram.org): Telegram's own services.\n")

    # The link scheme.
    for rel, text, count in PLM_LINKS:
        tree.replace(rel, text, text.replace("tg:", "plm:"), count)
    tree.replace("src/lib/richTextProcessor/wrapUrl.ts",
                 "  } else if((tgMatch = url.match(/^tg:(?:\\/\\/)?(.+?)(?:\\?|$)/))) {\n",
                 "  } else if((tgMatch = url.match(/^plm:(?:\\/\\/)?(.+?)(?:\\?|$)/))) { // pluma: plm://, not tg://\n")

    # The colours.
    theme = "src/helpers/themeController.ts"
    for base, colors in THEME_COLORS.items():
        tree.replace_within(theme, f"  {base}: {{\n", "\n  },\n",
                            [(f"'{key}': '{old}'", f"'{key}': '{new}'", 1) for key, old, new in colors])
    tree.replace(theme,
                 "import {changeColorAccent, ColorRgb, ensureTextContrast, getAccentColor, ",
                 "import {changeColorAccent, ColorRgb, computePerceivedBrightness, ensureTextContrast, getAccentColor, ")
    tree.replace(theme,
                 "    applyAppColor({\n"
                 "      name: 'primary-color',\n"
                 "      hex: newAccentHex,\n"
                 "      darkenAlpha: 0.04\n"
                 "    });\n",
                 "    applyAppColor({\n"
                 "      name: 'primary-color',\n"
                 "      hex: newAccentHex,\n"
                 "      darkenAlpha: 0.04\n"
                 "    });\n"
                 "\n"
                 "    // pluma: what sits on an accent fill (buttons, badges, the selected\n"
                 "    // chat): dark on a light accent such as the dark theme's sage, white\n"
                 "    // on the others.\n"
                 "    element.style.setProperty('--on-primary-color', "
                 "computePerceivedBrightness(newAccentRgb) > .65 ? '#131513' : '#ffffff');\n")
    tree.replace(theme,
                 "    let newMessageOutBackgroundColor = mixColors(myMessagesAccent, surfaceForMessage, messageLightenAlpha);\n"
                 "\n"
                 "    if(!isNight/*  || true */) {\n",
                 "    // pluma: a light, muted message colour (the sage of Pluma's light\n"
                 "    // theme) is the bubble as it is: mixed into the surface and saturated\n"
                 "    // by 63 points, it would turn bright green.\n"
                 "    const myMessagesHsla = rgbaToHsla(...myMessagesAccent);\n"
                 "    const isBubbleColor = !isNight && myMessagesHsla.l >= 85 && myMessagesHsla.s <= 30;\n"
                 "    let newMessageOutBackgroundColor = isBubbleColor ?\n"
                 "      myMessagesAccent :\n"
                 "      mixColors(myMessagesAccent, surfaceForMessage, messageLightenAlpha);\n"
                 "\n"
                 "    if(!isNight && !isBubbleColor) {\n")
    tree.replace(theme,
                 "      hex: isNight ? '#ffffff' : outgoingGradient ? keepReadableOnOutgoingMessageGradient(outgoingAccent, "
                 "outgoingGradient) : outgoingAccent,\n",
                 "      // pluma: the outbox accent colours the time and checks of a dark theme too.\n"
                 "      hex: isNight && !accentColor2 ? '#ffffff' : outgoingGradient ? "
                 "keepReadableOnOutgoingMessageGradient(outgoingAccent, outgoingGradient) : outgoingAccent,\n")
    for old, new in THEME_SETTINGS:
        tree.replace("src/config/state.ts", old, new)
    # Settings saved by a build before Pluma's colours keep Telegram's
    # defaults, which the theme does not reset by itself.
    load = "src/lib/appManagers/utils/state/loadState.ts"
    tree.replace(load,
                 "import {CommonState as StateCommon, State, COMMON_STATE_INIT, STATE_INIT, AppTheme} from '@config/state';\n",
                 "import {CommonState as StateCommon, State, COMMON_STATE_INIT, STATE_INIT, AppTheme, SETTINGS_INIT} "
                 "from '@config/state';\n")
    tree.replace(load,
                 "        theme.settings = [theme.settings as any];\n"
                 "        migrated = true;\n"
                 "      }\n"
                 "    });\n",
                 "        theme.settings = [theme.settings as any];\n"
                 "        migrated = true;\n"
                 "      }\n"
                 "    });\n"
                 "    // pluma: themes saved by a build before Pluma's colours keep Telegram's\n"
                 "    // default accent, bubbles and wallpaper; they get Pluma's.\n"
                 "    const telegramDefaults: {[base: string]: {accent: number, message: number, wallpaper: number}} = {\n"
                 "      baseThemeClassic: {accent: 0x3390ec, message: 0x5CA853, wallpaper: 0xdbddbb},\n"
                 "      baseThemeNight: {accent: 0x8774E1, message: 0x8774E1, wallpaper: 0xfec496}\n"
                 "    };\n"
                 "    themes.forEach((theme) => {\n"
                 "      theme.settings?.forEach((settings) => {\n"
                 "        const telegram = telegramDefaults[settings.base_theme?._];\n"
                 "        const pluma = SETTINGS_INIT.themes[0].settings.find((s) => s.base_theme._ === settings.base_theme?._);\n"
                 "        if(!telegram || !pluma) return;\n"
                 "        if(settings.accent_color === telegram.accent && settings.message_colors?.length === 1 &&\n"
                 "          settings.message_colors[0] === telegram.message) {\n"
                 "          settings.accent_color = pluma.accent_color;\n"
                 "          settings.message_colors = copy(pluma.message_colors);\n"
                 "          settings.outbox_accent_color = pluma.outbox_accent_color;\n"
                 "          migrated = true;\n"
                 "        }\n"
                 "        if(settings.wallpaper?.id === '' && settings.wallpaper.settings?.background_color === telegram.wallpaper) {\n"
                 "          settings.wallpaper = copy(pluma.wallpaper);\n"
                 "          settings.highlightingColor = pluma.highlightingColor;\n"
                 "          migrated = true;\n"
                 "        }\n"
                 "      });\n"
                 "    });\n")
    tree.replace("src/helpers/rowIconBackground.ts", "  blue: '#2196F3',\n", f"  blue: '{ACCENT}', // pluma: the accent, not blue\n")
    # People's identity colours: letter avatars, names, reply and link
    # preview bars.
    identity_colors(tree)

    base = "src/scss/base.scss"
    tree.replace(base, "  --badge-text-color: #fff;\n  --original-ripple-color: rgba(0, 0, 0, #{$hover-alpha});\n",
                 "  --badge-text-color: #fff;\n"
                 "  // pluma: what sits on an accent fill; themeController sets it per theme.\n"
                 "  --on-primary-color: #fff;\n"
                 "  --original-ripple-color: rgba(0, 0, 0, #{$hover-alpha});\n")
    tree.replace(base, "  --avatar-color-story-unread-from: #34c76f;\n  --avatar-color-story-unread-to: #3da1fd;\n",
                 "  // pluma: sage, not green and blue.\n"
                 "  --avatar-color-story-unread-from: #9DBB9F;\n  --avatar-color-story-unread-to: #5B7A5E;\n")
    tree.replace(base, "  --message-checkbox-color: #61c642;\n", "  --message-checkbox-color: var(--primary-color); // pluma\n")
    tree.replace(base,
                 "  --message-out-status-color: #fff;\n"
                 "  --message-out-time-color: rgba(255, 255, 255, .6);\n",
                 "  // pluma: the outbox accent (white unless a theme has one), as in the day theme.\n"
                 "  --message-out-status-color: var(--message-out-primary-color);\n"
                 "  --message-out-time-color: var(--message-out-status-color);\n")
    for rel, rule in ON_PRIMARY:
        new, n = _WHITE_ON_PRIMARY.subn(r"\1var(--on-primary-color)", rule)
        if n != 1:
            raise PatchError(f"ON_PRIMARY: {rule!r} has {n} colours, expected 1")
        tree.replace(rel, rule, new)
    # The feature icon's gradients are no accent fill: the glyph on them
    # stays white, as upstream draws it and as on letter avatars (the
    # archive's has the blue identity's colours).
    rel = "src/components/featureDetailsIconSticker.module.scss"
    tree.expect(rel, "  &:global(.background-gradient-", 3)
    for gradient in ("avatar", "archive", "stories"):
        tree.replace(rel, f"  &:global(.background-gradient-{gradient}) {{\n",
                     f"  &:global(.background-gradient-{gradient}) {{\n"
                     "    color: white; // pluma: a gradient, not the accent fill\n")
    tree.replace("src/scss/partials/_badge.scss",
                 "  &-primary {\n    background-color: var(--primary-color);\n  }\n",
                 "  &-primary {\n    background-color: var(--primary-color);\n    color: var(--on-primary-color); // pluma\n  }\n")
    tree.replace("src/scss/partials/_slider.scss",
                 "        .badge {\n          background-color: var(--primary-color);\n        }\n",
                 "        .badge {\n          background-color: var(--primary-color);\n"
                 "          color: var(--on-primary-color); // pluma\n        }\n")
    chatlist = "src/scss/partials/_chatlist.scss"
    tree.replace(chatlist,
                 "  .is-muted.backwards .dialog-subtitle-badge-gram {\n"
                 "    background-color: var(--chatlist-status-color);\n  }\n",
                 "  .is-muted.backwards .dialog-subtitle-badge-gram {\n"
                 "    background-color: var(--chatlist-status-color);\n"
                 "    color: var(--on-primary-color); // pluma\n  }\n")
    tree.replace(chatlist,
                 "  .no-unmuted-topic .dialog-subtitle-badge-pollvote {\n"
                 "    background-color: var(--secondary-color);\n  }\n",
                 "  .no-unmuted-topic .dialog-subtitle-badge-pollvote {\n"
                 "    background-color: var(--secondary-color);\n"
                 "    color: var(--badge-text-color); // pluma\n  }\n")
    # The selected chat, filled with the accent.
    tree.replace_within(chatlist, "      &.active {\n        --background: var(--primary-color) !important;\n",
                        "\n      }\n", (
                            ("#fff", "var(--on-primary-color)", 11),
                            ("color: white;", "color: var(--on-primary-color);", 1),
                            ("rgba(255, 255, 255, .7)", "color-mix(in srgb, var(--on-primary-color) 70%, transparent)", 1),
                            ("rgba(255, 255, 255, .2)", "color-mix(in srgb, var(--on-primary-color) 20%, transparent)", 1),
                        ))
    # The verified badge.
    for rel, text in VERIFIED_BADGE_SHAPE:
        tree.expect(rel, text)
    for rel, old, new in VERIFIED_BADGE:
        tree.replace(rel, old, new)


# --- birthdays -----------------------------------------------------------------
#
# The banner above the chat list when contacts have a birthday today. Pluma
# sells no Premium and has no gifts (help.getAppConfig sets
# premium_purchase_blocked): upstream would hide the banner, and its tap leads
# to a gift. Pluma shows it and its tap opens the chat (the owner's decision,
# task 020 of the server repository); when it shows, how it looks and how it
# closes stay as upstream has them.

BIRTHDAYS = "src/components/sidebarLeft/birthdaySuggestions.tsx"

# The strings the banner and its list take where upstream's offer a gift:
# entries of lang.ts, the English that every language pack falls back to.
BIRTHDAY_STRINGS = (
    "  'SendMessageTitle': 'Send message',\n",
    "  'Suggestion.BirthdayContacts.Today': 'Birthday today',\n",
)


def birthday_banner(tree):
    """The banner of contacts' birthdays shows without Premium for sale. Its
    tap opens the chat with the contact or, when several have a birthday
    today, the list of them, where the one picked opens their chat. It
    offers no gift: not in its subtitle, not in the toast after closing it."""
    rel = BIRTHDAYS
    for s in BIRTHDAY_STRINGS:
        tree.expect("src/lang.ts", s)
    tree.expect("src/components/popups/pickUser.tsx",
                "export default function showPickUserPopup(options: PopupPickUserOptions) {\n")
    tree.expect("src/lib/appImManager.ts",
                "  public async setPeer(options: Partial<ChatSetInnerPeerOptions> = {}, animate?: boolean): Promise<boolean> {\n")

    tree.replace(rel,
                 "import showSendGiftPicker from '@components/popups/sendGiftPicker';\n"
                 "import showSendGiftPopup from '@components/popups/sendGift';\n",
                 "import showPickUserPopup from '@components/popups/pickUser';\n")
    tree.replace(rel, "import {toastNew} from '@components/toast';\n", "")
    tree.replace(rel, "import {i18n} from '@lib/langPack';\n",
                 "import appImManager from '@lib/appImManager';\n"
                 "import {i18n} from '@lib/langPack';\n")
    tree.replace(rel, "import {useAppState} from '@stores/appState';\n", "")

    # The tap: the chat, not a gift.
    tree.replace(rel,
                 "  const nearbyContacts = createMemo(() => [\n"
                 "    ...props.state.today,\n"
                 "    ...props.state.yesterday,\n"
                 "    ...props.state.tomorrow\n"
                 "  ]);\n"
                 "  const birthdayPeerIds = createMemo(() => new Set(nearbyContacts().map(({peerId}) => peerId)));\n"
                 "  const yesterdayPeerIds = createMemo(() => new Set(props.state.yesterday.map(({peerId}) => peerId)));\n"
                 "  const todayPeerIds = createMemo(() => new Set(props.state.today.map(({peerId}) => peerId)));\n"
                 "\n"
                 "  const openGift = (peerId: PeerId) => {\n"
                 "    showSendGiftPopup({peerId, birthday: birthdayPeerIds().has(peerId)});\n"
                 "  };\n"
                 "\n"
                 "  const onClick = () => {\n"
                 "    if(contacts().length === 1) {\n"
                 "      openGift(contacts()[0].peerId);\n"
                 "      return;\n"
                 "    }\n"
                 "\n"
                 "    showSendGiftPicker({\n"
                 "      prependPeerIds: nearbyContacts().map(({peerId}) => peerId),\n"
                 "      getSubtitleForElement: (peerId) => {\n"
                 "        const key = todayPeerIds().has(peerId) ? 'Suggestion.BirthdayContacts.Today' :\n"
                 "          yesterdayPeerIds().has(peerId) ? 'Suggestion.BirthdayContacts.Yesterday' :\n"
                 "          birthdayPeerIds().has(peerId) ? 'Suggestion.BirthdayContacts.Tomorrow' : undefined;\n"
                 "        return key ? i18n(key) : undefined;\n"
                 "      },\n"
                 "      onSelect: ([{peerId}]) => openGift(peerId)\n"
                 "    });\n"
                 "  };\n",
                 "  // pluma: Pluma has no gifts. The banner (\"Send message\" under the\n"
                 "  // title) opens the chat with the contact or, when several have a\n"
                 "  // birthday today, the list of them, where the one picked opens their chat,\n"
                 "  // as a tap in the chat list opens it (setPeer, appDialogsManager).\n"
                 "  const openChat = (peerId: PeerId) => {\n"
                 "    appImManager.setPeer({peerId});\n"
                 "  };\n"
                 "\n"
                 "  const onClick = () => {\n"
                 "    if(contacts().length === 1) {\n"
                 "      openChat(contacts()[0].peerId);\n"
                 "      return;\n"
                 "    }\n"
                 "\n"
                 "    // Taken now: the list loads them a tick later, when a close or the\n"
                 "    // midnight refresh may have taken the banner's state away.\n"
                 "    const todayPeerIds = contacts().map(({peerId}) => peerId);\n"
                 "    showPickUserPopup({\n"
                 "      titleLangKey: 'SendMessageTitle',\n"
                 "      peerType: ['custom'],\n"
                 "      getMoreCustom: async() => ({result: todayPeerIds, isEnd: true}),\n"
                 "      getSubtitleForElement: () => i18n('Suggestion.BirthdayContacts.Today'),\n"
                 "      noSearch: true,\n"
                 "      onSelect: ([{peerId}]) => openChat(peerId)\n"
                 "    });\n"
                 "  };\n")
    tree.replace(rel,
                 "          <PendingSuggestion.Subtitle>{i18n('Suggestion.BirthdayContacts.Subtitle')}"
                 "</PendingSuggestion.Subtitle>\n",
                 "          <PendingSuggestion.Subtitle>{i18n('SendMessageTitle')}</PendingSuggestion.Subtitle>\n")

    # Shown whether or not Premium is for sale: the Premium gate goes, and
    # with it the effect that followed it, now a load on mount (an effect that
    # reads no signal runs once, as onMount does). No gift options loaded
    # ahead for the tap, no toast that points to gifts in Settings.
    tree.replace(rel,
                 "import {createEffect, createMemo, createResource, createSignal, onCleanup, onMount, Show} from 'solid-js';\n",
                 "import {createMemo, createResource, createSignal, onCleanup, onMount, Show} from 'solid-js';\n")
    tree.replace(rel, "  const [{appConfig}] = useAppState();\n", "")
    tree.replace(rel,
                 "  const canLoadBirthdayContacts = () => !appConfig.premium_purchase_blocked;\n"
                 "  const canShowBirthdayContacts = () => (\n"
                 "    canLoadBirthdayContacts() &&\n"
                 "    promoDataLoaded() &&\n",
                 "  // pluma: whether Premium is for sale does not matter: the banner leads\n"
                 "  // to the chat, not to a gift.\n"
                 "  const canShowBirthdayContacts = () => (\n"
                 "    promoDataLoaded() &&\n")
    tree.replace(rel,
                 "    if(canLoadBirthdayContacts()) void loadContactBirthdays(true);\n",
                 "    void loadContactBirthdays(true);\n")
    tree.replace(rel,
                 "    if(canLoadBirthdayContacts()) {\n"
                 "      void loadContactBirthdays();\n"
                 "    }\n",
                 "    void loadContactBirthdays();\n")
    tree.replace(rel,
                 "  createEffect(() => {\n"
                 "    if(!canLoadBirthdayContacts()) {\n"
                 "      ++contactBirthdaysRequest;\n"
                 "      setContactBirthdays(undefined);\n"
                 "      return;\n"
                 "    }\n"
                 "\n"
                 "    void loadContactBirthdays();\n"
                 "  });\n",
                 "  // pluma: no Premium gate to follow: loaded once, and again at midnight.\n"
                 "  onMount(() => {\n"
                 "    void loadContactBirthdays();\n"
                 "  });\n")
    tree.replace(rel,
                 "  createEffect(() => {\n"
                 "    if(canShowBirthdayContacts() && contactBirthdays()?.today.length) {\n"
                 "      void rootScope.managers.appGiftsManager.getStarGiftOptions().catch(() => {});\n"
                 "    }\n"
                 "  });\n"
                 "\n",
                 "  // pluma: no gift options to load ahead for the banner's tap.\n"
                 "\n")
    tree.replace(rel, "    toastNew({langPackKey: 'Suggestion.BirthdayContacts.Dismissed'});\n",
                 "    // pluma: no toast that a gift can be sent later in Settings.\n")


PROFILE = "src/components/peerProfile.tsx"


def birthday_row(tree):
    """The Birthday row of a profile offers a gift on the contact's birthday
    only while Premium can be bought, as the chat's own gift entry
    (Chat.canGiftPremium) and the Android app's profile (ProfileActivity
    containsGift) do. Pluma has no gifts, so the row copies the date then, as
    on any other day. The birthday banner leads to that profile in two taps."""
    tree.replace(PROFILE,
                 "PeerProfile.Birthday = () => {\n"
                 "  const context = useContext(PeerProfileContext);\n",
                 "PeerProfile.Birthday = () => {\n"
                 "  const context = useContext(PeerProfileContext);\n"
                 "  const appConfig = useAppConfig();\n")
    tree.replace(PROFILE,
                 "    if(isToday()) {\n"
                 "      return () => showSendGiftPopup({\n",
                 "    // pluma: no gift while Premium cannot be bought.\n"
                 "    if(isToday() && !appConfig.premium_purchase_blocked) {\n"
                 "      return () => showSendGiftPopup({\n")


SAVED_TAGS = "src/lib/appManagers/utils/reactions/savedTagsAvailable.ts"
SAVED_TAGS_IMPORT = "import savedTagsAvailable from '@appManagers/utils/reactions/savedTagsAvailable';\n"
CONTEXT_MENU = "src/components/chat/contextMenu.ts"
BUBBLES = "src/components/chat/bubbles.ts"
TOPBAR_SEARCH = "src/components/chat/topbarSearch.tsx"
REACTIONS_MENU = "src/components/chat/reactionsMenu.ts"
# The files of the tag gates, the only ones that call savedTagsAvailable,
# and the import each adds to (they open the popup through hotReloadGuard).
_GUARD_WITH_PROVIDER = "import SolidJSHotReloadGuardProvider, {hotReloadGuard} from '@lib/solidjs/hotReloadGuardProvider';\n"
_GUARD = "import {hotReloadGuard} from '@lib/solidjs/hotReloadGuardProvider';\n"
SAVED_TAG_GATES = {CONTEXT_MENU: _GUARD_WITH_PROVIDER, BUBBLES: _GUARD_WITH_PROVIDER, TOPBAR_SEARCH: _GUARD, REACTIONS_MENU: _GUARD}


def saved_tags(tree):
    """Tags of Saved Messages (reactions in the chat with oneself, a filter of
    its search) are open to every user: Pluma sells no Premium, and its
    server serves the tags (messages.getSavedReactionTags,
    updateSavedReactionTag, messages.search with saved_reaction) to everyone.
    Upstream sends a user without Premium to the Premium popup at each place
    a tag is put, opened, filtered by or renamed. Those places, and only
    those, ask savedTagsAvailable() instead of the user's Premium; every other
    Premium feature stays behind rootScope.premium. How many tags a message
    takes is the limit of reactions (appReactionsManager.sendReaction,
    apiManager.getLimit('reactions')), which the server's appConfig sets:
    reactions_user_max_default for a user without Premium."""
    if (tree.root / SAVED_TAGS).exists():
        raise PatchError(f"{SAVED_TAGS}: upstream ships one now; review what it does")
    tree.write(SAVED_TAGS,
               "// pluma: tags of Saved Messages are open to every user. Pluma sells no\n"
               "// Premium, and its server serves the tags to everyone. Only the tag gates\n"
               "// ask this; every other Premium feature stays behind rootScope.premium.\n"
               "export default function savedTagsAvailable() {\n"
               "  return true;\n"
               "}\n")
    for rel, guard in SAVED_TAG_GATES.items():
        tree.replace(rel, guard, guard + SAVED_TAGS_IMPORT)
    # How many tags a message takes: the server's limit, none of the client's.
    tree.expect("src/lib/appManagers/apiManagerMethods.ts",
                "        reactions: ['reactions_user_max_default', 'reactions_user_max_premium'],\n")
    tree.expect("src/lib/appManagers/appReactionsManager.ts", "      this.apiManager.getLimit('reactions'),\n")

    # A right click on a tag opens its menu (filter by it, rename it).
    tree.replace(CONTEXT_MENU,
                 "      if(this.isTag && !rootScope.premium) {\n"
                 "        hotReloadGuard.showPremiumPopup({feature: 'saved_tags'});\n",
                 "      if(this.isTag && !savedTagsAvailable()) {\n"
                 "        hotReloadGuard.showPremiumPopup({feature: 'saved_tags'});\n")
    # A tag picked in the reactions of the context menu is put on the message.
    tree.replace(CONTEXT_MENU,
                 "          if(!rootScope.premium && tags) {\n"
                 "            hotReloadGuard.showPremiumPopup({feature: 'saved_tags'});\n",
                 "          if(!savedTagsAvailable() && tags) {\n"
                 "            hotReloadGuard.showPremiumPopup({feature: 'saved_tags'});\n")
    # A click on a tag of a message filters the chat by it.
    tree.replace(BUBBLES,
                 "      if(reactionsElement.getType() === ReactionLayoutType.Tag) {\n"
                 "        if(!rootScope.premium) {\n"
                 "          hotReloadGuard.showPremiumPopup({feature: 'saved_tags'});\n",
                 "      if(reactionsElement.getType() === ReactionLayoutType.Tag) {\n"
                 "        if(!savedTagsAvailable()) {\n"
                 "          hotReloadGuard.showPremiumPopup({feature: 'saved_tags'});\n")
    # The tags above the search of Saved Messages: not locked, no "Unlock"
    # tag, and a click filters by the tag. The file asked Premium for nothing
    # else.
    tree.replace(TOPBAR_SEARCH, "import usePremium from '@stores/premium';\n", "")
    tree.replace(TOPBAR_SEARCH, "  const isPremium = usePremium();\n", "")
    tree.replace(TOPBAR_SEARCH,
                 "    const premium = isPremium();\n"
                 "    element.classList.toggle('is-locked', !premium);\n",
                 "    const premium = savedTagsAvailable();\n"
                 "    element.classList.toggle('is-locked', !premium);\n")
    tree.replace(TOPBAR_SEARCH,
                 "      if(!isPremium()) {\n"
                 "        hotReloadGuard.showPremiumPopup({feature: 'saved_tags'});\n",
                 "      if(!savedTagsAvailable()) {\n"
                 "        hotReloadGuard.showPremiumPopup({feature: 'saved_tags'});\n")
    # The hint above the tags of the reactions menu: what tags are for, not
    # the offer of Premium.
    tree.replace(REACTIONS_MENU,
                 "        rootScope.premium ? 'Reactions.Tag.Description' : 'Reactions.Tag.PremiumHint',\n",
                 "        savedTagsAvailable() ? 'Reactions.Tag.Description' : 'Reactions.Tag.PremiumHint',\n")


# --- premium stickers ---------------------------------------------------------
#
# A premium sticker (a document with video_thumbs, getStickerEffectThumb) is
# sent and played by every user, as with Premium in Telegram (task 058 of the
# server repository): Pluma sells no Premium and the owner reported the gate as
# a defect. premium_purchase_blocked, which the server sends, even hides such
# stickers from the sets (tabs/stickers.ts, isPremiumFeaturesHidden). The
# recipient plays the effect from the document alone (wrappers/sticker.ts:742,
# unless the server sends nopremium, which Pluma's does not). Only the places
# below ask premiumStickersAvailable(); the Premium effects of the send menu
# and custom emoji stay as they are.

PREMIUM_STICKERS = "src/lib/appManagers/utils/stickers/premiumStickersAvailable.ts"
PREMIUM_STICKERS_IMPORT = "import premiumStickersAvailable from '@appManagers/utils/stickers/premiumStickersAvailable';\n"
EFFECT_THUMB_IMPORT = "import getStickerEffectThumb from '@appManagers/utils/stickers/getStickerEffectThumb';\n"
# (file, upstream, Pluma)
PREMIUM_STICKER_GATES = (
    # Sending from the panel, the suggestions and a message: the Premium popup.
    ("src/components/chat/input.ts",
     "    if(document.sticker && getStickerEffectThumb(document) && !rootScope.premium && !ignoreNoPremium) {\n",
     "    if(document.sticker && getStickerEffectThumb(document) && !premiumStickersAvailable() && !rootScope.premium && !ignoreNoPremium) {\n"),
    # A forward: the local copy without the effect.
    ("src/lib/appManagers/appMessagesManager.ts",
     "        if(document.sticker && !this.rootScope.premium) {\n",
     "        if(document.sticker && !premiumStickersAvailable() && !this.rootScope.premium) {\n"),
    # The sets of the panel leave them out while Premium cannot be bought.
    ("src/components/emoticonsDropdown/tabs/stickers.ts",
     "        if(isPremiumFeaturesHidden && getStickerEffectThumb(document)) {\n",
     "        if(isPremiumFeaturesHidden && !premiumStickersAvailable() && getStickerEffectThumb(document)) {\n"),
    # Stickers found for an emoji.
    ("src/lib/appManagers/appStickersManager.ts",
     "        (excludePremiumEffectStickers && !this.rootScope.premium && getStickerEffectThumb(sticker))) {\n",
     "        (excludePremiumEffectStickers && !premiumStickersAvailable() && !this.rootScope.premium && getStickerEffectThumb(sticker))) {\n"),
    # The lock on them.
    ("src/components/wrappers/sticker.ts",
     "  const willHaveLock = effectThumb && withLock;\n",
     "  const willHaveLock = effectThumb && withLock && !premiumStickersAvailable();\n"),
)


def premium_stickers(tree):
    """Premium stickers for every user, as with Premium; see the note above."""
    if (tree.root / PREMIUM_STICKERS).exists():
        raise PatchError(f"{PREMIUM_STICKERS}: upstream ships one now; review what it does")
    tree.write(PREMIUM_STICKERS,
               "// pluma: premium stickers are open to every user. Pluma sells no Premium.\n"
               "// Only the gates of premium stickers ask this; everything else stays\n"
               "// behind rootScope.premium.\n"
               "export default function premiumStickersAvailable() {\n"
               "  return true;\n"
               "}\n")
    for rel, old, new in PREMIUM_STICKER_GATES:
        tree.replace(rel, EFFECT_THUMB_IMPORT, EFFECT_THUMB_IMPORT + PREMIUM_STICKERS_IMPORT)
        tree.replace(rel, old, new)


def verify_premium_stickers(tree, sources):
    if "export default function premiumStickersAvailable() {\n  return true;\n}\n" not in tree.read(PREMIUM_STICKERS):
        raise PatchError(f"{PREMIUM_STICKERS}: premiumStickersAvailable() does not return true")
    gates = {rel for rel, _, _ in PREMIUM_STICKER_GATES}
    for rel, text in sources.items():
        if rel != PREMIUM_STICKERS and rel not in gates and "premiumStickersAvailable" in text:
            raise PatchError(f"{rel}: asks premiumStickersAvailable, which only the gates of premium stickers may")
    for rel, old, new in PREMIUM_STICKER_GATES:
        text = sources[rel]
        if old in text or new not in text or text.count(PREMIUM_STICKERS_IMPORT) != 1:
            raise PatchError(f"{rel}: a gate of premium stickers still asks Premium")


# --- links -----------------------------------------------------------------------
#
# pluma.chat is Pluma's link host, as t.me is Telegram's (task 026 of the
# server repository): the server gives its invite links and me_url_prefix on
# it. The client opens pluma.chat links inside the app as it opens t.me ones,
# and the links it makes itself for the user to copy, share, see or scan are
# pluma.chat ones. Web K ignores me_url_prefix and builds them from literals.
# t.me, telegram.me and their subdomains stay internal hosts, as upstream has
# them.

LINK_HOST = "pluma.chat"
LINK_HOST_MATCH = "src/lib/richTextProcessor/matchTelegramUrlHost.ts"
# The pages of the site pluma.chat itself: its root and the first segments
# of its paths. Such a link opens in the browser as any site's does, not as a
# username; the same list in every client (task 026 of the server repository).
LINK_SITE_PATHS = ("iphone", "ipad", "android", "mac", "windows", "linux", "web", "pero", "app", "en", "dl",
                   "ios", "collect", "assets", "_l", ".well-known",
                   "favicon.svg", "og.png", "apple-touch-icon.png", "404.html", "progress.json")
LINK_SITE_PATHS_TS = ("const PLUMA_SITE_PATHS = new Set([" + ", ".join(f"'{p}'" for p in LINK_SITE_PATHS)
                      + "]);\n")
LINK_SITE_CHECK = ("  if(matchUrlHost(url, [PLUMA_LINK_HOST])?.subdomain === '') {\n"
                   "    // pluma: the site's own pages (its root, its sections, its files) open in the browser\n"
                   "    const first = url.pathname.split('/')[1].toLowerCase();\n"
                   "    if(!first || PLUMA_SITE_PATHS.has(first)) {\n"
                   "      return;\n"
                   "    }\n"
                   "\n"
                   "    return {prefix: undefined};\n"
                   "  }\n")

# The links the client makes: (file, text, occurrences); the t.me/ in the
# text becomes pluma.chat/.
LINK_BUILDERS = (
    # The profile's username and t.me links (Settings, the chat's info).
    ("src/helpers/copyContact.ts", "export const T_ME = 'https://t.me/';\n", 1),
    # Message links: Copy Link of the context menu and of the forward popup.
    (CONTEXT_MENU, "    let url = 'https://t.me/';\n", 1),
    ("src/components/popups/forward.tsx", "    let url = 'https://t.me/';\n", 1),
    # The link row of a group's or channel's info (and of a topic's).
    (PROFILE, "      let url = 't.me/';\n", 1),
    (PROFILE, "        url: 't.me/' + usernames[0],\n", 1),
    # QR codes of the My QR code popup: username, phone, channel.
    ("src/helpers/qrCode/paintQrCode.ts", "  return `https://t.me/${username}`;\n", 1),
    ("src/components/popups/myQrCode.tsx", "    return `https://t.me/c/${peerId.toChatId()}`;\n", 1),
    ("src/components/popups/myQrCode/link.ts", "  return `https://t.me/+${phone}`;\n", 1),
    # The links of a Business account, shown and copied.
    ("src/components/sidebarLeft/tabs/businessChatLinks.tsx", "copyLink('https://t.me/' + path)", 1),
    ("src/components/sidebarLeft/tabs/businessChatLinks.tsx", "a.textContent = 't.me/' + path;", 1),
    # Stories, story albums and gift collections of a profile.
    ("src/lib/appManagers/utils/stories/storyLink.ts", "  return `https://t.me/${username}/s/${storyId}`;\n", 1),
    ("src/components/stories/profileList.tsx", "copyTextToClipboard(`https://t.me/${username}/a/${id}`);", 1),
    ("src/components/stargifts/profileList.tsx", "copyTextToClipboard(`https://t.me/${username}/c/${id}`)", 1),
    # Sticker and emoji sets.
    ("src/components/popups/stickers.tsx", "const prefix = `https://t.me/${isEmojis ? 'addemoji' : 'addstickers'}/`;", 1),
    # A public chat's link as an invite link row, and the prefix of the
    # public link field of a group or channel.
    ("src/components/sidebarRight/tabs/chatInviteLinkShared.ts",
     "this.setUrl(isUsername ? 't.me/' + username : chatInvite.link);", 1),
    ("src/components/sidebarRight/tabs/chatType.tsx", "    const placeholder = 't.me/';\n", 1),
    # The recent actions of a chat: its public link changed (shown, linked
    # and copied).
    ("src/components/chat/bubbleParts/adminLogsResolver/index.tsx", "t.me/${action.", 4),
    # The share link of a channel's live stream.
    ("src/lib/rtmp/url.ts", "`https://t.me/${username}?livestream`", 1),
    ("src/lib/rtmp/url.ts", "`https://t.me/c/${chat.id}?livestream`", 1),
    # The channel post of a giveaway in a transaction.
    ("src/components/popups/starsPay.tsx", "`https://t.me/c/${peerId.toChatId()}/${serverMsgId}`", 1),
    # The link of a new bot, under its username.
    ("src/components/popups/createBot/CreateBotPopup.tsx", "                  t.me/{fullUsername()}\n", 1),
    # The built-in English strings that name the public link's form.
    ("src/lang.ts", "'Reserve up to %d t.me/username links'", 1),
    ("src/lang.ts", "'Public links such as t.me/title'", 1),
)

# The Telegram link hosts left in the code (comments aside), by file: the
# number of t.me, telegram.me and telegram.dog in each. A new one upstream
# stops the patch until someone decides whether it is a link the client
# makes (LINK_BUILDERS) or one of these.
LINK_KEEP = {
    # The host list itself: t.me and telegram.me stay internal.
    LINK_HOST_MATCH: 2,
    # Turned back into an in-app route at once (wrapUrl), never shown: a
    # mention, a topic's anchor, a link a mini app asks to open.
    "src/lib/richTextProcessor/wrapRichText.ts": 1,
    "src/lib/richTextProcessor/wrapTopicThreadAnchor.ts": 1,
    "src/helpers/getWebViewTgLink.ts": 1,
    "src/components/popups/premium.tsx": 1,
    "src/components/stories/viewer.tsx": 1,
    # The base a relative link is parsed against, for its scheme.
    "src/lib/appManagers/utils/richMessage/validateRichMessage.ts": 1,
    # Mini apps and widgets: their API is Telegram's as window.Telegram is
    # (openTelegramLink takes these hosts), and a TON Connect link is told by
    # it; the wallet is not released (lib/wallet/release.ts) and the server
    # does not serve it.
    "src/vendor/widget-sandbox/src/sandbox/globals.ts": 4,
    "src/vendor/widget-sandbox/src/shared/sdk-policy.ts": 3,
    "src/lib/wallet/tonConnectWire.ts": 1,
    # Telegram's own: gift codes, NFT gifts, styles, BotFather, its tips
    # channel and its account (frozen accounts).
    "src/lang.ts": 2,
    "src/components/popups/giftLink.tsx": 2,
    "src/components/popups/starGiftInfo.tsx": 2,
    "src/components/stargifts/stargiftsGrid.tsx": 2,
    "src/components/premium/promoSlide.tsx": 1,
    "src/components/popups/starsPay.tsx": 1,
    "src/components/popups/aiEditorPopup/styleTab.tsx": 1,
    "src/components/sidebarRight/tabs/editBot.tsx": 1,
    "src/components/popups/frozen.tsx": 1,
    # The popup sandbox's sample data (a development page).
    "src/components/popupSandbox/fixtures.ts": 1,
    "src/components/popupSandbox/mockManagers.ts": 1,
    "src/components/popupSandbox/stories/calls.ts": 3,
    "src/components/popupSandbox/stories/chat.ts": 2,
    "src/components/popupSandbox/stories/pickers.ts": 1,
    "src/components/popupSandbox/stories/walletTonConnect.ts": 1,
    "src/components/popupSandbox/stories/featureDetails.ts": 1,
}
_TELEGRAM_LINK_HOST = re.compile(r"(?<![\w.-])(?:t|telegram)\.(?:me|dog)(?![\w-])")

# The telegram.org hosts left in the code (comments aside), by file. A new
# one upstream stops the patch until someone decides whether the user can
# reach it: the links that lead to Telegram's services are taken away (the
# FAQ of help_section); these stay.
SITE_KEEP = {
    # Terms, privacy and ad policies of Stars, gifts, mini apps and bots,
    # and the unsupported-message hints, in the built-in English strings.
    "src/lang.ts": 23,
    "src/components/popups/starGiftInfo.tsx": 1,
    "src/helpers/getBotPrivacyPolicy.ts": 1,
    # The switch to Web A and the choice made for it: on Telegram's own
    # domains only, and MAIN_DOMAINS is empty here.
    "src/components/sidebarLeft/index.ts": 1,
    "src/index.ts": 1,
    # The wallet's proof of ownership, which names a domain and goes nowhere;
    # the wallet is not released (lib/wallet/release.ts).
    "src/lib/wallet/tonConnectWire.ts": 1,
    "src/lib/wallet/walletSession.ts": 2,
    # Sample data of the development pages.
    "src/components/bubbleSandbox/states.ts": 1,
    "src/components/chat/inputEditor/testData.ts": 8,
    "src/components/popupSandbox/fixtures.ts": 3,
    "src/components/popupSandbox/stories/misc.ts": 3,
    "src/components/popupSandbox/stories/pickers.ts": 2,
    "src/components/popupSandbox/stories/richEditor.ts": 1,
    "src/components/popupSandbox/stories/walletTonConnect.ts": 1,
}
_TELEGRAM_SITE = re.compile(r"(?<![\w-])(?:[\w-]+\.)*telegram\.org(?![\w-])")

# Links to Telegram's site that an ordinary screen shows: Telegram's apps on
# the chat list of an account with no contacts, and "Learn More" of the chat
# automation tab, which the Settings search opens. Applied before rebrand
# renames the word in the strings: (file, text, replacement).
TELEGRAM_SITE_EDITS = (
    ("src/lang.ts",
     "'ChatList.Main.EmptyPlaceholder.SubtitleNoContacts': 'Use Telegram app on your "
     "[Android](https://telegram.org/android) or [iOS](https://telegram.org/dl/ios) device to sync your contacts',\n",
     "'ChatList.Main.EmptyPlaceholder.SubtitleNoContacts': 'Use Telegram app on your "
     "Android or iOS device to sync your contacts',\n"),
    ("src/lang.ts",
     "'ChatAutomation.HeroDescription': 'Add a bot to your account to help you automatically process and respond "
     "to the messages you receive. [Learn More >]()',\n",
     "'ChatAutomation.HeroDescription': 'Add a bot to your account to help you automatically process and respond "
     "to the messages you receive.',\n"),
    ("src/components/sidebarLeft/tabs/chatAutomation.tsx",
     "  const learnMoreAnchor = document.createElement('a');\n"
     "  learnMoreAnchor.href = 'https://telegram.org';\n"
     "  learnMoreAnchor.target = '_blank';\n"
     "  learnMoreAnchor.rel = 'noopener noreferrer';\n\n",
     ""),
    ("src/components/sidebarLeft/tabs/chatAutomation.tsx",
     "{i18n('ChatAutomation.HeroDescription', [learnMoreAnchor])}",
     "{i18n('ChatAutomation.HeroDescription')}"),
)


def link_host(tree):
    # The host is Pluma's own, as t.me is Telegram's: the host itself only,
    # since its subdomains (web.pluma.chat) are sites, not the usernames that
    # durov.t.me spells.
    tree.replace(LINK_HOST_MATCH, "export const TELESCOPE_LINK_HOST = 'telesco.pe';\n",
                 "export const TELESCOPE_LINK_HOST = 'telesco.pe';\n"
                 "// pluma: Pluma's link host, as t.me is Telegram's, and the paths of its site.\n"
                 f"export const PLUMA_LINK_HOST = '{LINK_HOST}';\n"
                 + LINK_SITE_PATHS_TS)
    tree.expect(LINK_HOST_MATCH, "const TELEGRAM_LINK_HOSTS = ['t.me', 'telegram.me'];\n")
    tree.replace(LINK_HOST_MATCH,
                 "export default function matchTelegramUrlHost(url: URL): {prefix?: string} | undefined {\n"
                 "  const match = matchUrlHost(url, TELEGRAM_LINK_HOSTS);\n",
                 "export default function matchTelegramUrlHost(url: URL): {prefix?: string} | undefined {\n"
                 "  // pluma: the exact host, never a subdomain, which is a site, not a user\n"
                 + LINK_SITE_CHECK +
                 "\n"
                 "  const match = matchUrlHost(url, TELEGRAM_LINK_HOSTS);\n")
    # Every Telegram link host the app knows goes through it: wrapUrl (links
    # in messages, appImManager.openUrl, #?tgaddr=) and the anchors' handlers.
    for rel in ("src/lib/richTextProcessor/wrapUrl.ts", "src/helpers/addAnchorListener.ts"):
        tree.expect(rel, "matchTelegramUrlHost(")

    for rel, text, count in LINK_BUILDERS:
        tree.replace(rel, text, text.replace("t.me/", f"{LINK_HOST}/"), count)
    # The link row of a private group's or channel's info shows its invite
    # link from the point where t.me/ starts, which a pluma.chat link has
    # not (indexOf -1: the last character only).
    tree.replace(PROFILE,
                 "        url: exportedInvite.link.slice(exportedInvite.link.indexOf('t.me/'))\n",
                 "        // pluma: the link as the server made it, without the scheme\n"
                 "        url: exportedInvite.link.replace(/^https?:\\/\\//, '')\n")


def patch(tree, c):
    # The upstream is the one upstream.env describes: the schema layer the
    # server speaks (ADR 0045), the version, and the toolchain the CI installs.
    layers = re.findall(r'"layer":(\d+)', tree.read("src/lib/mtproto/schema.ts"))
    if layers != [str(c.layer)]:
        raise PatchError(f"src/lib/mtproto/schema.ts: layer {', '.join(layers) or 'missing'}, "
                         f"the server speaks {c.layer} (UPSTREAM_LAYER)")
    version = tree.read("public/version").strip()
    if version != f"{c.version} ({c.build})":
        raise PatchError(f"public/version: {version!r}, upstream.env says {c.version} ({c.build})")
    package = json.loads(tree.read("package.json"))
    if package.get("packageManager") != f"pnpm@{c.pnpm}":
        raise PatchError(f"package.json: packageManager {package.get('packageManager')!r}, "
                         f"upstream.env pins pnpm@{c.pnpm}")
    engines = package.get("engines", {}).get("node", "")
    if not node_satisfies(c.node, engines):
        raise PatchError(f"package.json: engines.node {engines!r} does not accept NODE_VERSION {c.node}")
    # The build flags of the MTProto transports are the ones the patch
    # decides on (below) or leaves to upstream.
    used = {}
    for rel in tree.sources():
        for name in re.findall(r"import\.meta\.env\.(VITE_MTPROTO_\w+)", tree.read(rel)):
            used.setdefault(name, rel)
    known = set(TRANSPORT_FLAGS) | set(UPSTREAM_FLAGS)
    for name, rel in sorted(used.items()):
        if name not in known:
            raise PatchError(f"{rel}: the build flag {name} is new to the patch; decide what it must be")
    if set(used) != known:
        raise PatchError(f"src: the build flags {sorted(known - set(used))} are not used any more; "
                         "review the transport flags of the patch")

    # The server: one WebSocket URL for every datacenter, connection type
    # (client, download, upload) and mode (test, premium).
    dc = "src/lib/mtproto/dcConfigurator.ts"
    tree.replace_body(dc,
                      "export function constructTelegramWebSocketUrl(_dcId: DcId, connectionType: ConnectionType, premium?: boolean) {\n",
                      "\n}\n",
                      "  if(!import.meta.env.VITE_MTPROTO_HAS_WS) {\n"
                      "    return;\n"
                      "  }\n"
                      "\n"
                      "  // pluma: every datacenter, connection type and mode (test, premium) is\n"
                      "  // the one Pluma server.\n"
                      "  assertValidDcId(_dcId);\n"
                      f"  return '{c.server_url}';",
                      must_contain=(".web.telegram.org/${path}",))
    tree.replace(dc,
                 "// A dcId can arrive from the service worker's `stream/` route, i.e. from a URL any page\n"
                 "// can craft: interpolated unchecked it turns the endpoint into an attacker-chosen host\n"
                 "// (`1.evil.com/` -> wss://kws1.evil.com/-1.web.telegram.org/apiws). Telegram has exactly\n"
                 "// five DCs, so validate here, before the value can reach a URL or a storage key.\n",
                 "// A dcId can arrive from the service worker's `stream/` route, i.e. from a URL any page\n"
                 "// can craft. Telegram has exactly five DCs, so validate here, before the value can\n"
                 "// reach a storage key (pluma: no URL is built from it, every DC is the Pluma server).\n")

    # No HTTP transport: the Pluma gateway takes MTProto over WebSocket only.
    # The build flags switch tweb's HTTP transport off (never the first
    # choice, no fallback, no uploads over it), and its Telegram addresses go.
    tree.replace_body(dc, "export class DcConfigurator {\n", "  public chosenServers: Servers",
                      "  // pluma: no HTTP transport (transportHTTP), so no addresses for it.\n\n",
                      must_contain=("sslSubdomains", "private dcOptions", "149.154.175.50"))
    tree.replace_block(dc, "  private transportHTTP = (", "\n  };\n",
                       "  // pluma: the Pluma gateway takes MTProto over WebSocket only, and the\n"
                       "  // build switches tweb's HTTP transport off: there is no HTTP endpoint.\n"
                       "  private transportHTTP = (dcId: DcId, connectionType: ConnectionType, premium?: boolean): HTTP => {\n"
                       "    return undefined;\n"
                       "  };\n",
                       must_contain=("this.sslSubdomains", "this.dcOptions", ".web.telegram.org/", "new HTTP("))
    # The two reads of the flags that ci/check_bundle.py looks for in the code:
    # what the flags compile out. Another form here makes that check blind.
    tree.expect("src/config/modes.ts", "  const httpOnly = Modes.http = isFlagOn('http');\n")
    tree.expect("src/config/modes.ts", " && !isFlagOn('noMultipleTransports'),\n")
    if (tree.root / ".env.production.local").exists():
        raise PatchError(".env.production.local: upstream ships one now; review what it sets")
    tree.write(".env.production.local",
               "# pluma: MTProto over WebSocket only; the Pluma gateway has no HTTP\n"
               "# transport (ci/patch.py). Vite reads this file after .env.\n"
               + "".join(f"{k}={v}\n" for k, v in TRANSPORT_FLAGS.items()))

    # The server key replaces Telegram's production and test keys: the test
    # mode (?test=1) talks to the same server.
    rsa = "src/lib/mtproto/rsaKeysManager.ts"
    tree.replace_body(rsa, "export class RSAKeysManager {\n", "  private publicKeysParsed: {",
                      f"  // pluma: the key of the Pluma server (fingerprint {c.fingerprint:#018x})\n"
                      "  // replaces Telegram's production and test keys.\n"
                      "  private publisKeysHex: RSAPublicKeyHex[] = [{\n"
                      f"    modulus: '{c.modulus}',\n"
                      f"    exponent: '{c.exponent}'\n"
                      "  }];\n\n",
                      must_contain=("e8bb3305c0b52c6cf2afdf7637313489", "private testPublicKeysHex", "private publisKeysHex"))
    tree.replace(rsa,
                 "  constructor() {\n"
                 "    if(Modes.test) {\n"
                 "      this.publisKeysHex = this.testPublicKeysHex;\n"
                 "    }\n"
                 "  }\n\n", "")
    tree.replace(rsa, "import Modes from '@config/modes';\n", "")

    # Application identity, and none of the behaviour of Telegram's own
    # deployment (web.telegram.org: its credentials, the switch to Web A).
    app = "src/config/app.ts"
    tree.replace(app, "export const MAIN_DOMAINS = ['web.telegram.org', 'webk.telegram.org'];\n",
                 "// pluma: never Telegram's own deployment.\n"
                 "export const MAIN_DOMAINS: string[] = [];\n")
    tree.replace(app, "  id: +import.meta.env.VITE_API_ID,\n",
                 "  // pluma: the api_id and api_hash of the Pluma web app.\n"
                 f"  id: {c.api_id},\n")
    tree.replace(app, "  hash: import.meta.env.VITE_API_HASH,\n", f"  hash: '{c.api_hash}',\n")
    tree.replace(app, "  pushServerKey: import.meta.env.VITE_PUSH_SERVER_KEY,\n",
                 "  // pluma: no web push until the server sends it with a key of its own.\n"
                 "  pushServerKey: '',\n")
    tree.expect(app, "  baseDcId: BASE_DC_ID as TrueDcId,\n")
    tree.replace(BASE_DC, "export const BASE_DC_ID = 2;\n",
                 "// pluma: the Pluma server is datacenter 1.\n"
                 "export const BASE_DC_ID = 1;\n")
    tree.sub(app, r"if\(App\.isMainDomain\) \{ // use Webogram credentials then\n(?:  App\.\w+ = '?[\w-]+'?;\n){3}\}\n\n", "")

    # Sign-in warms up connections to datacenters 2-5 for Telegram; the
    # Pluma server is the only one.
    tree.replace("src/pages/cards/SignInCard.tsx", "      const dcs = new Set([1, 2, 3, 4, 5]);\n",
                 "      // pluma: the Pluma server is the only datacenter.\n"
                 "      const dcs = new Set<number>();\n")

    # No session sync with t.me and telegram.me (scripts the client loads
    # from Telegram's sites after sign-in).
    tree.replace_body("src/lib/telegramMeWebManager.ts", "  public setAuthorized(canRedirect: boolean) {\n", "\n  }\n}\n",
                      "    // pluma: no session sync with t.me and telegram.me, Telegram's sites.\n"
                      "    return;",
                      must_contain=("_websync_", "'//t.me/' + path", "loadScript(url)"))

    # Web push: no subscription without a key of the server (Telegram's web
    # push key is gone with the build variables and the main-domain block).
    tree.replace("src/lib/webPushApiManager.ts",
                 "  public subscribe = (): Promise<PushSubscriptionNotify | void> => {\n"
                 "    if(!this.isAvailable) {\n",
                 "  public subscribe = (): Promise<PushSubscriptionNotify | void> => {\n"
                 "    // pluma: no web push subscription without the server's key.\n"
                 "    if(!this.isAvailable || !App.pushServerKey) {\n")

    # The page title and the installed app are "Pluma". The page names no
    # canonical address: where the server serves it is not known here.
    tree.replace_body("vite.config.ts", "const handlebarsPlugin = handlebars({\n  context: {\n", "\n  }\n});\n",
                      f"    title: '{c.app_name}',\n"
                      f"    description: '{c.app_name}'",
                      must_contain=("title: 'Telegram Web'", "url: 'https://web.telegram.org/k/'",
                                    "origin: 'https://web.telegram.org/'"))
    for line in ('    <meta property="og:url" content="{{url}}">\n',
                 '    <meta property="twitter:url" content="{{url}}">\n',
                 '    <link rel="canonical" href="{{origin}}">\n'):
        tree.replace("index.html", line, "")
    for rel in ("public/site.webmanifest", "public/site_apple.webmanifest"):
        patch_manifest(tree, rel, c)

    # The banner of contacts' birthdays opens the chat, not a gift.
    birthday_banner(tree)
    birthday_row(tree)

    # Tags of Saved Messages for every user, not only with Premium.
    saved_tags(tree)

    # Premium stickers for every user.
    premium_stickers(tree)
    premium_for_everyone(tree)
    no_ai_editor(tree)
    service_account(tree)
    transcription(tree)
    e2e_group_calls(tree)
    call_colors(tree)

    # Telegram's site off the screens a user reaches.
    for rel, old, new in TELEGRAM_SITE_EDITS:
        tree.replace(rel, old, new)

    # Pluma's name, icons, link scheme and colours.
    rebrand(tree, c)

    # The screens of a code sent through Telegram; their strings name the
    # real Telegram, so they come after the rename.
    login_code_screens(tree)

    # pluma.chat links instead of t.me ones.
    link_host(tree)

    help_section(tree)

    # A release of the site reaches open tabs.
    update_prompts(tree, c)


def verify(tree, c):
    """Checks the result independently of how the edits were made."""
    sources = {rel: tree.read(rel) for rel in tree.sources()}
    for rel in ("index.html", "vite.config.ts", "public/site.webmanifest", "public/site_apple.webmanifest"):
        sources[rel] = tree.read(rel)
    for rel, text in sources.items():
        traces = telegram_traces(text)
        if traces:
            kind, what = traces[0]
            raise PatchError(f"{rel}: Telegram's {kind} {what!r} is still there")
        m = re.search(r"import\.meta\.env\.(VITE_API_ID|VITE_API_HASH|VITE_PUSH_SERVER_KEY)\b", text)
        if m:
            raise PatchError(f"{rel}: the client still takes {m.group(1)} from the build variables")

    dc = sources["src/lib/mtproto/dcConfigurator.ts"]
    if dc.count(f"'{c.server_url}'") != 1 or len(re.findall(r"['`]wss?://", dc)) != 1:
        raise PatchError("dcConfigurator.ts: the server URL is not the only one")
    rsa = sources["src/lib/mtproto/rsaKeysManager.ts"]
    if rsa.count("modulus: '") != 1 or f"modulus: '{c.modulus}'" not in rsa:
        raise PatchError("rsaKeysManager.ts: the server key is not the only one")
    app = sources["src/config/app.ts"]
    for s in (f"  id: {c.api_id},\n", f"  hash: '{c.api_hash}',\n"):
        if s not in app:
            raise PatchError(f"app.ts: no {s.strip()!r}")
    if "export const BASE_DC_ID = 1;\n" not in sources[BASE_DC]:
        raise PatchError(f"{BASE_DC}: the base datacenter is not 1")
    if "{{url}}" in sources["index.html"] or "{{origin}}" in sources["index.html"]:
        raise PatchError("index.html: a canonical address is still there")
    for rel in ("public/site.webmanifest", "public/site_apple.webmanifest"):
        m = json.loads(sources[rel])
        if m["name"] != c.app_name or "t.me" in sources[rel]:
            raise PatchError(f"{rel}: not the app's manifest")
    env = load_env(tree.root / ".env.production.local")
    if env != TRANSPORT_FLAGS:
        raise PatchError(f".env.production.local: {env}, expected {TRANSPORT_FLAGS}")

    # The brand: Pluma's icons, no Telegram in the strings, plm:// links.
    for rel, _ in ICONS:
        if tree.sha256("public/" + rel) != hashlib.sha256((BRAND / "web" / rel).read_bytes()).hexdigest():
            raise PatchError(f"public/{rel}: not Pluma's (brand/web)")
    if (tree.root / "public" / SCREENSHOT[0]).exists():
        raise PatchError(f"public/{SCREENSHOT[0]}: Telegram's screenshot is still there")
    for p in sorted((tree.root / "public/changelogs").glob(f"*_{c.version}.md")):
        raise PatchError(f"public/changelogs/{p.name}: upstream's message about this version is still there")
    for rel, _, _ in STRINGS:
        for line in sources[rel].split("\n"):
            m = _STRING_ENTRY.match(line)
            if rel == LANG_SIGN and line in LOGIN_CODE_STRING_LINES:
                continue  # the real Telegram, where the login code went
            if m and _TELEGRAM_WORD.search(m.group(2)):
                raise PatchError(f"{rel}: {m.group(2)[:60]!r} still says Telegram")
    code = {rel: _COMMENT.sub("", text) for rel, text in sources.items()}
    for rel, link in TELEGRAM_APP_LINKS:
        if code[rel].count(link) != 1:
            raise PatchError(f"{rel}: {code[rel].count(link)} occurrences of the Telegram app's link {link}, expected 1")
        code[rel] = code[rel].replace(link, "")
    for rel, text in code.items():
        m = _TG_LINK.search(text)
        if m:
            raise PatchError(f"{rel}: a tg: link ({m.group()!r}); Pluma's links are plm://")
    if "'plm://login?token='" not in sources["src/pages/cards/SignQRCard.tsx"]:
        raise PatchError("SignQRCard.tsx: the QR code does not sign in with plm://login")
    if '<g id="logo"' not in sources["index.html"]:
        raise PatchError("index.html: not Pluma's logo on the sign-in page")
    # People's identity colours: none of Telegram's that Pluma replaced is
    # left anywhere, as a CSS colour or a number.
    for identity, table in IDENTITY_COLORS.items():
        kept = {new.lower() for _, _, new in table}
        for _, old, _ in table:
            if old is None or old.lower() in kept:
                continue
            token = re.compile(rf"(?<![0-9A-Fa-f]){old[1:]}(?![0-9A-Fa-f])", re.IGNORECASE)
            for rel, text in sources.items():
                if token.search(text):
                    raise PatchError(f"{rel}: Telegram's {identity} identity colour {old} is still there")

    # The birthday banner: nothing of the gift flow or the Premium gate left.
    for s in ("premium_purchase_blocked", "showSendGift", "popups/sendGift", "appGiftsManager",
              "Suggestion.BirthdayContacts.Subtitle", "Suggestion.BirthdayContacts.Dismissed"):
        if s in sources[BIRTHDAYS]:
            raise PatchError(f"{BIRTHDAYS}: {s!r} is still there; the birthday banner must open the chat")

    # Tags of Saved Messages: no gate of theirs asks Premium, and nothing but
    # the tag gates asks savedTagsAvailable, so no other Premium feature opens.
    if "export default function savedTagsAvailable() {\n  return true;\n}\n" not in sources.get(SAVED_TAGS, ""):
        raise PatchError(f"{SAVED_TAGS}: tags of Saved Messages are not open to every user")
    for rel, text in sources.items():
        if rel != SAVED_TAGS and rel not in SAVED_TAG_GATES and "savedTagsAvailable" in text:
            raise PatchError(f"{rel}: asks savedTagsAvailable, which only the tag gates may")
    for rel in SAVED_TAG_GATES:
        text = sources[rel]
        if "savedTagsAvailable()" not in text:
            raise PatchError(f"{rel}: no tag gate asks savedTagsAvailable")
        gates = re.findall(r"if\(([^\n]*)\) \{\n\s*hotReloadGuard\.showPremiumPopup\(\{feature: 'saved_tags'\}\);", text)
        if text.count("feature: 'saved_tags'") != len(gates) + (rel == REACTIONS_MENU):
            raise PatchError(f"{rel}: a way to the Premium popup of tags the patch does not know")
        for condition in gates:
            if "savedTagsAvailable()" not in condition or re.search(r"premium", condition, re.IGNORECASE):
                raise PatchError(f"{rel}: the tag gate if({condition}) still asks Premium")
    if re.search(r"(?i)premium[^\n]*'Reactions\.Tag\.Description'", sources[REACTIONS_MENU]):
        raise PatchError(f"{REACTIONS_MENU}: the hint of tags still asks Premium")
    if "isPremium" in sources[TOPBAR_SEARCH] or "usePremium" in sources[TOPBAR_SEARCH]:
        raise PatchError(f"{TOPBAR_SEARCH}: the tags of the search still ask Premium")

    verify_premium_stickers(tree, sources)
    verify_premium_for_everyone(tree)
    verify_no_ai_editor(sources)
    verify_service_account(sources)
    verify_transcription(sources)
    verify_e2e_group_calls(sources)
    verify_call_colors(sources)

    # Links: pluma.chat is a link host of the app, its exact host only, and
    # no Telegram link host is left but the ones LINK_KEEP knows.
    match = sources[LINK_HOST_MATCH]
    if (f"export const PLUMA_LINK_HOST = '{LINK_HOST}';\n" not in match
            or "  if(matchUrlHost(url, [PLUMA_LINK_HOST])?.subdomain === '') {\n" not in match):
        raise PatchError(f"{LINK_HOST_MATCH}: {LINK_HOST} is not a link host of the app")
    if match.count(LINK_SITE_PATHS_TS) != 1 or match.count(LINK_SITE_CHECK) != 1:
        raise PatchError(f"{LINK_HOST_MATCH}: the pages of the site {LINK_HOST} would open as usernames")
    if re.search(r"const TELEGRAM_LINK_HOSTS = [^\n]*pluma", match):
        raise PatchError(f"{LINK_HOST_MATCH}: {LINK_HOST} must not take subdomains as usernames")
    for rel, text in sources.items():
        found = len(_TELEGRAM_LINK_HOST.findall(_COMMENT.sub("", text)))
        if found != LINK_KEEP.get(rel, 0):
            raise PatchError(f"{rel}: {found} Telegram link hosts (t.me), expected {LINK_KEEP.get(rel, 0)}; "
                             f"a link the client makes is {LINK_HOST}")
    if "exportedInvite.link.indexOf(" in sources[PROFILE]:
        raise PatchError(f"{PROFILE}: the invite link row cuts the link at t.me/")
    for rel, text in sources.items():
        if rel.startswith("src/"):
            found = len(_TELEGRAM_SITE.findall(_COMMENT.sub("", text)))
            if found != SITE_KEEP.get(rel, 0):
                raise PatchError(f"{rel}: {found} telegram.org hosts, expected {SITE_KEEP.get(rel, 0)}; "
                                 "does it lead the user to Telegram's services?")

    verify_verified_badge(sources)
    verify_help_section(sources)
    verify_login_code_screens(sources)
    verify_update_prompts(tree, c, sources)



# --- Premium for everyone -----------------------------------------------------
# Task 071 (ADR 0041): every user has Premium and every boost-gated feature is
# open, so the server sends the Premium flag for everybody. Only what the flag
# would make wrong is edited: the star by every name, the purchase rows that
# show for anyone with Premium, and what the server does not serve.
PREMIUM_FOR_EVERYONE_EDITS = (
    ("src/components/generateTitleIcons.ts",
     "    } else if((peer as User.user).pFlags.premium && !isPremiumFeaturesHidden) {\n",
     "    } else if(false) { // pluma: no star: everybody has Premium\n"),
    ("src/components/sidebarLeft/index.ts",
     "      if(isPremium) sidebarHeader.append(statusBtnIcon);\n      else statusBtnIcon.remove();\n",
     "      // pluma: the server does not serve account.updateEmojiStatus.\n      statusBtnIcon.remove();\n"),
    # The other way to an emoji status: the menu of a custom emoji.
    ("src/helpers/dom/createStickersContextMenu.ts",
     "    verify: () => !!(rootScope.premium && doc)\n",
     "    verify: () => false // pluma: the server does not serve account.updateEmojiStatus\n"),
    # The remaining ways to an emoji status: a mini app, which asks the user
    # and then calls the method, and a link, whose fallback is the Premium promo.
    ("src/components/webApp.tsx",
     "    if(!doc) {\n"
     "      telegramWebView.dispatchWebViewEvent('emoji_status_failed', {error: 'SUGGESTED_EMOJI_INVALID'});\n",
     "    if(true) { // pluma: the server does not serve account.updateEmojiStatus\n"
     "      telegramWebView.dispatchWebViewEvent('emoji_status_failed', {error: 'SERVER_ERROR'});\n"),
    ("src/components/webApp.tsx",
     "    if(peer.pFlags.bot_can_manage_emoji_status) {\n"
     "      telegramWebView.dispatchWebViewEvent('emoji_status_access_requested', {status: 'allowed'});\n",
     "    if(true) { // pluma: the server does not serve bots.toggleUserEmojiStatusPermission\n"
     "      telegramWebView.dispatchWebViewEvent('emoji_status_access_requested', {status: 'cancelled'});\n"),
    ("src/lib/internalLinkProcessor.ts",
     "    // no button means no premium \u2014 the same promo the control itself\n"
     "    // shows when it is used without it (tdesktop: ShowPremiumPreviewBox).\n"
     "    // Nothing to reach, so nothing is closed to reach it.\n"
     "    if(!statusBtn) {\n"
     "      return showPremiumPopup({feature: 'emoji_status'});\n",
     "    // pluma: no button: the server does not serve account.updateEmojiStatus.\n"
     "    if(!statusBtn) {\n"
     "      return;\n"),
    # Gifts are sold for Stars, which do not exist here. tweb ignores the
    # stargifts_blocked of the app config, so its entries stay without an edit.
    ("src/components/chat/topbar.ts",
     "      verify: async() => (\n"
     "        this.chat.isChannel || (this.chat.peerId.isUser() && !this.chat.isBot && "
     "(await this.managers.appUsersManager.isRegularUser(this.peerId)))\n"
     "      ) && !(this.chat.type === ChatType.Logs)\n",
     "      verify: async() => false // pluma: no gifts (ADR 0041)\n"),
    ("src/components/peerProfile.tsx",
     "    verify: async() => isUser ?\n"
     "      await rootScope.managers.appUsersManager.isRegularUser(peerId.toUserId()) :\n"
     "      isBroadcast() && !context.isTopic\n",
     "    verify: async() => false // pluma: no gifts (ADR 0041)\n"),
    # The panel of collectibles in the QR code screen, whose "Browse Gifts" opens the store.
    ("src/components/popups/myQrCode.tsx",
     "    {id: 'emoji', icon: 'smile', iconClass: styles.iconEmoji, title: 'Emoji'},\n"
     "    {id: 'gifts', icon: 'gift', iconClass: styles.iconGifts, title: 'StarGiftTitle'}\n",
     "    {id: 'emoji', icon: 'smile', iconClass: styles.iconEmoji, title: 'Emoji'} // pluma: no gifts panel (ADR 0041)\n"),
    # The side button of the plate of a channel the user cannot post in, and
    # the links to the store.
    ("src/components/chat/input.ts",
     "        const hasGift = good && isBroadcast;\n",
     "        const hasGift = false; // pluma: no gifts (ADR 0041)\n"),
    ("src/lib/internalLinkProcessor.ts",
     "          case 'send-gift':\n"
     "            return showSendGiftPicker();\n"
     "          case 'send-gift/self':\n"
     "            return showSendGiftPopup({peerId: rootScope.myId});\n",
     "          // pluma: no gifts (ADR 0041)\n"
     "          case 'send-gift':\n"
     "          case 'send-gift/self':\n"
     "            return;\n"),
    # Boosts do not exist here: nothing waits for a level of a channel, no
    # screen, prompt or link offers one.
    ("src/components/chat/topbar.ts",
     "      text: 'BoostChannel',\n      onClick: onBoostClick,\n      verify: async() => this.chat.isBroadcast\n",
     "      text: 'BoostChannel',\n      onClick: onBoostClick,\n      verify: async() => false // pluma: boosts do not exist here (ADR 0041)\n"),
    ("src/components/chat/topbar.ts",
     "      text: 'BoostGroup',\n      onClick: onBoostClick,\n      verify: async() => this.chat.isMegagroup\n",
     "      text: 'BoostGroup',\n      onClick: onBoostClick,\n      verify: async() => false // pluma: boosts do not exist here (ADR 0041)\n"),
    ("src/lib/internalLinkProcessor.ts",
     "    showBoostPopup(peerId);\n  };\n\n  public processPremiumFeaturesLink",
     "    // pluma: a boost link opens the channel.\n    appImManager.setInnerPeer({peerId});\n  };\n\n  public processPremiumFeaturesLink"),
    ("src/components/sidebarRight/tabs/groupPermissions/groupPermissions.tsx",
     "        show: () => !!solidState.store.slowModeSeconds\n",
     "        show: () => false // pluma: boosts do not exist here (ADR 0041)\n"),
)


# --- help ------------------------------------------------------------------
#
# The section that ends Settings: the FAQ on telegram.org and the volunteers'
# support of Telegram (help.getSupport), as the other Pluma clients have none.

SETTINGS = "src/components/sidebarLeft/tabs/settings.tsx"
SETTINGS_SEARCH = "src/lib/settingsSearch/generated.ts"
SETTINGS_SEARCH_OPENERS = "src/lib/settingsSearch/openers.ts"
SETTINGS_SEARCH_REGISTRY = "src/lib/settingsSearch/registry.ts"
# The rows Settings hides while Premium cannot be bought (premium_purchase_blocked,
# settings.tsx); its search has no such condition and would still list them. The
# index is generated from the tabs when a build starts (settings-search-plugin),
# so the rows are dropped where the index is read, as upstream drops the wallet's.
SETTINGS_SEARCH_SALE_ROWS = ("Premium.Boarding.Title", "TelegramBusiness", "MenuTelegramStars",
                             "MenuTelegramStarsTon", "Chat.Menu.SendGift")


def help_section(tree):
    tree.replace(SETTINGS, "import askQuestion, {openTelegramFaq} from '@components/askQuestion';\n", "")
    tree.replace_block(SETTINGS, "      {/* help, the way tdesktop ends its main settings */}\n", "      </Section>\n",
                       "      {/* pluma: no help section: the FAQ and the volunteers' support are Telegram's. */}\n",
                       must_contain=("openTelegramFaq", "askQuestion(", "'AskAQuestion'"))
    for key in ("AskAQuestion", "TelegramFaq"):
        tree.replace(SETTINGS_SEARCH,
                     f"    {{id: 'AppSettingsTab:{key}', sectionId: 'AppSettingsTab', kind: 'row', titleLangKey: '{key}'}},\n",
                     "")
    sale_rows = "".join(f"  'AppSettingsTab:{key}',\n" for key in SETTINGS_SEARCH_SALE_ROWS)
    wallet_entries = "export const WALLET_ENTRIES = new Set([\n  'AppSettingsTab:WalletAttachMoney'\n]);\n"
    tree.replace(SETTINGS_SEARCH_OPENERS, wallet_entries,
                 wallet_entries + "\n"
                 "// pluma: rows Settings hides while Premium cannot be bought; the index lists them.\n"
                 f"export const SALE_ENTRIES = new Set([\n{sale_rows}]);\n")
    tree.replace(SETTINGS_SEARCH_REGISTRY, "NON_NAVIGABLE_SECTIONS, WALLET_ENTRIES} from './openers';",
                 "NON_NAVIGABLE_SECTIONS, SALE_ENTRIES, WALLET_ENTRIES} from './openers';")
    tree.replace(SETTINGS_SEARCH_REGISTRY, "    (isWalletReleased() || !WALLET_ENTRIES.has(entry.id)));\n",
                 "    (isWalletReleased() || !WALLET_ENTRIES.has(entry.id)) &&\n"
                 "    !SALE_ENTRIES.has(entry.id)); // pluma\n")


def verify_help_section(sources):
    for rel in (SETTINGS, SETTINGS_SEARCH):
        for s in ("openTelegramFaq", "askQuestion(", "AskAQuestion", "TelegramFaq"):
            if s in sources[rel]:
                raise PatchError(f"{rel}: {s!r} is still there; Settings has no help section")
    for key in SETTINGS_SEARCH_SALE_ROWS:
        if f"  'AppSettingsTab:{key}',\n" not in sources[SETTINGS_SEARCH_OPENERS]:
            raise PatchError(f"{SETTINGS_SEARCH_OPENERS}: the search still lists {key!r}, which Settings hides")
    if "!SALE_ENTRIES.has(entry.id)" not in sources[SETTINGS_SEARCH_REGISTRY]:
        raise PatchError(f"{SETTINGS_SEARCH_REGISTRY}: the search does not drop the rows of the sale")


def premium_for_everyone(tree):
    for rel, old, new in PREMIUM_FOR_EVERYONE_EDITS:
        tree.replace(rel, old, new)


def verify_premium_for_everyone(tree):
    for rel, old, new in PREMIUM_FOR_EVERYONE_EDITS:
        text = tree.read(rel)
        if text.count(new) != 1 or old in text.replace(new, ""):
            raise PatchError(f"{rel}: the edit of task 071 is not there")


# --- No AI message editor (task 079) ------------------------------------------
# The AI editor rewrites, proofreads, restyles and translates a typed message
# (aiEditorPopup, createWithAiPopup: messages.composeMessageWithAI,
# messages.composeRichMessageWithAI and the aicompose.* tones); Pluma runs no
# language model to answer them (the owner's decision, 2026-11-11). Its
# button exists only where a field is given the chat's AI editor context:
# the chat's message field (RichMessageInput, whose toolbar AI button clicks
# that button) and the caption of the media popup (InputFieldMessage). Neither
# is given it now, so no button is made; the AI button of the formatting
# tooltip, which clicks the same button, is hidden.
AI_CHAT_INPUT = "src/components/chat/input.ts"
AI_NEW_MEDIA = "src/components/popups/newMedia.tsx"
AI_MARKUP_TOOLTIP = "src/components/chat/markupTooltip.ts"
NO_AI_EDITOR_EDITS = (
    (AI_CHAT_INPUT,
     "      ai: this.getAiEditorContext(),\n",
     "      // pluma: no AI editor, Pluma runs no language model (task 079).\n"),
    (AI_NEW_MEDIA,
     "        sendOnShortcut: true,\n        ai: chat.input.getAiEditorContext()\n      });\n",
     "        sendOnShortcut: true\n        // pluma: no AI editor, Pluma runs no language model (task 079).\n      });\n"),
    (AI_MARKUP_TOOLTIP,
     "    const aiAvailable = this.input.classList.contains('input-message-input');\n",
     "    const aiAvailable = false; // pluma: no AI editor, Pluma runs no language model (task 079)\n"),
)
# The editor's context is made by createAiEditorContext() for
# getAiEditorContext() alone, which nothing calls now; its button is made
# only by useAiEditorButton, for the two fields that get no context. Upstream
# adding a caller of either stops the patch until it is read.
_AI_CONTEXT_CALL = re.compile(r"\.getAiEditorContext\(|\bcreateAiEditorContext\(")
_AI_BUTTON_USE = re.compile(r"\buseAiEditorButton\(|<AiEditorButton\b")
AI_CONTEXT_CALLS = {AI_CHAT_INPUT: 1, "src/components/chat/inputState/createAiEditorContext.ts": 1}
AI_BUTTON_USES = {"src/components/richMessageInput/ai.tsx": 1, "src/components/richMessageInput/index.tsx": 1,
                  "src/components/richMessageInput/aiButton.tsx": 1, "src/components/inputFieldMessage.tsx": 1}


def no_ai_editor(tree):
    for rel, old, new in NO_AI_EDITOR_EDITS:
        tree.replace(rel, old, new)


def verify_no_ai_editor(sources):
    for rel, old, new in NO_AI_EDITOR_EDITS:
        text = sources[rel]
        if text.count(new) != 1 or old in text.replace(new, ""):
            raise PatchError(f"{rel}: the AI editor is offered again")
    for rel, text in sources.items():
        code = _COMMENT.sub("", text)
        found = len(_AI_CONTEXT_CALL.findall(code))
        if found != AI_CONTEXT_CALLS.get(rel, 0):
            raise PatchError(f"{rel}: {found} uses of the AI editor's context, expected {AI_CONTEXT_CALLS.get(rel, 0)}; "
                             "another way into the AI editor")
        found = len(_AI_BUTTON_USE.findall(code))
        if found != AI_BUTTON_USES.get(rel, 0):
            raise PatchError(f"{rel}: {found} AI editor buttons, expected {AI_BUTTON_USES.get(rel, 0)}; "
                             "another way into the AI editor")


# --- the service account (task 080) --------------------------------------------
# Pluma's support account (user.support, sent with no online status) is no
# volunteer of Telegram's support: where a user's last seen goes it reads
# "service account" (the owner's decision, 2026-11-11). Every such line of the
# client comes from getUserStatusString, which gives a support account the
# string SupportStatus: the chat's top bar and the profile through
# appImManager.getUserStatus, and the lists of contacts, of members, of search
# and of the popups. The string keeps its key and gets a new text: lang.ts has
# the English one, and the server's language pack the same key in every other
# language (pkg/langpack/override.json of the server), so that a downloaded
# language does not bring Telegram's "support" back. The account of service
# notifications (777000) has a string of its own, Peer.ServiceNotifications.
USER_STATUS = "src/components/wrappers/getUserStatusString.ts"
SERVICE_ACCOUNT_STRING = ("src/lang.ts", "  'SupportStatus': 'support',\n", "  'SupportStatus': 'service account',\n")
# What the text relies on: the status of a support account is this string,
# here alone.
SERVICE_ACCOUNT_STATUS = "      if(user.pFlags.support) {\n        key = 'SupportStatus';\n        break;\n      }\n"
_SUPPORT_STATUS_USE = re.compile(r"""['"`]SupportStatus['"`]""")
SUPPORT_STATUS_USES = {"src/lang.ts": 1, USER_STATUS: 1}


def service_account(tree):
    tree.expect(USER_STATUS, SERVICE_ACCOUNT_STATUS)
    tree.replace(*SERVICE_ACCOUNT_STRING)


def verify_service_account(sources):
    rel, old, new = SERVICE_ACCOUNT_STRING
    if sources[rel].count(new) != 1 or old in sources[rel]:
        raise PatchError(f"{rel}: a support account is not a service account")
    if sources[USER_STATUS].count(SERVICE_ACCOUNT_STATUS) != 1:
        raise PatchError(f"{USER_STATUS}: the status of a support account is not the string SupportStatus")
    for rel, text in sources.items():
        found = len(_SUPPORT_STATUS_USE.findall(_COMMENT.sub("", text)))
        if found != SUPPORT_STATUS_USES.get(rel, 0):
            raise PatchError(f"{rel}: {found} uses of 'SupportStatus', expected {SUPPORT_STATUS_USES.get(rel, 0)}; "
                             "is it still the status of a support account, and of nothing else?")


# --- voice and round messages to text -------------------------------------------
# Every user has Premium (ADR 0041) and the server transcribes voice and round
# messages for everybody (messages.transcribeAudio), so the chat offers their
# button as upstream does: wrapDocument gives a voice row its button
# (canTranscribeVoice), and wrapRoundVideoBubble a round video its own.
# A view-once voice or round message is never transcribed (the owner's
# decision, 2026-11-12), and Web K offers it no button as it is: a media with
# ttl_seconds is one canSeeMessageMedia hides, so the chat draws the message as
# a service line (isDrawnAsService) and returns before it wraps the document or
# the round video. The check fails when upstream changes any of that.
TRANSCRIBE_VOICE = "              canTranscribeVoice: true,\n              translatableParams,\n"
TRANSCRIBE_ROUND = "    if(isRound) {\n      wrapRoundVideoBubble({\n"
CAN_SEE_MEDIA = "src/lib/appManagers/utils/messages/canSeeMessageMedia.ts"
VIEW_ONCE_HIDDEN = ("  if((media as MessageMedia.messageMediaPhoto).ttl_seconds) {\n"
                    "    // const {document} = (media as MessageMedia.messageMediaDocument);\n"
                    "    // if(!document || (document as Document.document).type !== 'voice') {\n"
                    "    //   return false;\n"
                    "    // }\n"
                    "    return false;\n"
                    "  }\n")
VIEW_ONCE_MEDIA = ("const isSelfDestructingMediaMessage = (message: Message.message) => "
                   "!!(message.media as MessageMedia.messageMediaPhoto)?.ttl_seconds;\n")
VIEW_ONCE_AS_SERVICE = ("  return isStoryMentionMessage(message) || "
                        "(isSelfDestructingMediaMessage(message) && !canSeeMessageMedia(message));\n")
# renderMessage: the branch of a service line sets returnService, and the
# chat returns with it before it wraps a voice row or a round video.
VIEW_ONCE_SERVICE_LINE = "    if(isDrawnAsService(message)) {\n"
VIEW_ONCE_SERVICE_SET = "      returnService = true;\n"
VIEW_ONCE_RETURN = "    if(returnService) {\n"
VIEW_ONCE_ORDER = (VIEW_ONCE_SERVICE_LINE, VIEW_ONCE_SERVICE_SET, VIEW_ONCE_RETURN)


def transcription(tree):
    for text in (TRANSCRIBE_VOICE, TRANSCRIBE_ROUND, VIEW_ONCE_MEDIA, VIEW_ONCE_AS_SERVICE, *VIEW_ONCE_ORDER):
        tree.expect(BUBBLES, text)
    tree.expect(CAN_SEE_MEDIA, VIEW_ONCE_HIDDEN)


def verify_transcription(sources):
    bubbles = sources[BUBBLES]
    for text in (TRANSCRIBE_VOICE, TRANSCRIBE_ROUND):
        if bubbles.count(text) != 1:
            raise PatchError(f"{BUBBLES}: a voice or round message has no button of its text")
    if sources[CAN_SEE_MEDIA].count(VIEW_ONCE_HIDDEN) != 1:
        raise PatchError(f"{CAN_SEE_MEDIA}: a view-once media is not hidden, so it may offer its transcription")
    if bubbles.count(VIEW_ONCE_MEDIA) != 1 or bubbles.count(VIEW_ONCE_AS_SERVICE) != 1:
        raise PatchError(f"{BUBBLES}: a view-once message is not drawn as a service line, "
                         "which offers no transcription")
    if any(bubbles.count(text) != 1 for text in VIEW_ONCE_ORDER):
        raise PatchError(f"{BUBBLES}: a service line is not returned with as it was, "
                         "so a view-once message may be wrapped as a voice or round one")
    order = [bubbles.find(text) for text in VIEW_ONCE_ORDER]
    if order != sorted(order) or order[-1] > min(bubbles.find(TRANSCRIBE_VOICE), bubbles.find(TRANSCRIBE_ROUND)):
        raise PatchError(f"{BUBBLES}: a service line is wrapped as a voice or round message, "
                         "so a view-once one would offer its transcription")


# --- end-to-end group calls (task 094) ---------------------------------------------
#
# ADR 0060 of the server (the owner's decisions of 2026-11-12): every group call is end-to-end, a chat's and a
# channel's video chat too, not only a conference; nobody joins one as a channel; there are no RTMP streams;
# a browser that cannot encrypt frames does not open a group call; the client reports the state of its
# encryption to the SFU.
#
# Web K has the whole end-to-end path of a conference (lib/calls/e2e, a port of tde2e): a key born in the
# encryption worker, the chain's last block, a block that adds us (phone.joinGroupCall with public_key and
# block), the chain's polling and pushes, the emoji, the only_left removal of members who left, and the frame
# transforms (RTCRtpScriptTransform). Which path a call takes was decided by how it was joined, not by the
# server: a chat's video chat went the legacy way (GroupCallsController.joinGroupCall ->
# joinGroupCallInternal, no key), a conference the end-to-end one (joinConference -> joinConferenceCommon ->
# GroupCallInstance.attachE2e). Now a chat's call goes the end-to-end way, by its inputGroupCall(id,
# access_hash) and with its chat, and keeps the interface of a chat's call: GroupCallInstance.isConference,
# which the interface and the simulcast asked, is split into isE2e (the crypto: transport recovery, the
# conference's blackhole probe, joining as someone else) and isConference (an end-to-end call without a chat:
# no admins, its own link, no speaker invites). The places that asked `instance.e2e` for the interface of a
# conference (invites, the link, the settings, removing a participant, the question on leaving it for another
# call) ask isConference; the emoji badge and the members with access keep asking `e2e`, so a chat's call shows
# them as a conference does.
#
# Joining as a channel is gone: a chain member is a user (a block adds a user_id), so the account is who
# joins. chooseGroupCallJoinAs asks nobody and the call's settings offer no "Display me as..."; the server
# answers phone.getGroupCallJoinAs with the user alone and refuses another join_as anyway.
#
# A browser without RTCRtpScriptTransform (environment/conferenceCallSupport.ts) cannot encrypt frames: the
# ways into a chat's call (AppImManager.joinGroupCall, joinCallFromLink) tell it so with the string a
# conference has for it (ConferenceCall.Unsupported) and join or start nothing. A transform that cannot be
# attached already ends the call (GroupCallInstance.failE2eTransform).
#
# RTMP streams: their parts come from the server unencrypted. IS_LIVE_STREAM_SUPPORTED, upstream's own switch
# for a browser that cannot play them, is off: no "Stream With..." in the chat's menu (topbar.ts), no live
# plate (topbarPlates.ts), no stream action in a profile (peerProfile.tsx), no RTMP player set up
# (appDialogsManager.ts). What could still lead to one, a link and the list of active calls, finds
# joinLiveStream refusing, and the player is opened by nothing. Web K has no live stories: stories.startLive
# and messageMediaVideoStream are in its schema only.
#
# Recording: the server does not serve phone.toggleGroupCallRecord (ADR 0060 §4). A chat's call in Web K has no
# recording entry; the RTMP player's menu had the only ones ("Start Recording", "Stop Recording"), and they go.
#
# The status report, PlumaE2EStatus v1 of ADR 0060 §5, the same for every Pluma client: every 5 s, by its own
# timer and the first 5 s after the join, the main connection sends it over its data channel while that is open,
# exactly these fields: colibriClass, v (1), seq (from 1 for each join), height and lastBlock (the hash prefix of
# the block at that height; tde2e's block hash is over the local form, which is how the server keeps a block),
# offset0 and offset1 (the cursors the sub-chains are polled from), error (the tde2e code of a sticky failure),
# sendEpochs, decryptEpochs, unknownEpochs, encrypted, encryptFailed and the senders (user, ok, unknownEpoch,
# tooOld, duplicate, failed, lastOkMs) by user. The frame counters and the two epoch lists are what happened
# since the last report: the worker, where the frames are, starts them again when a report takes them. The
# lists are bounded (15, 15, 8, 100 senders) and the JSON to 16 KiB, past which the senders decrypted longest
# ago go. No key, nonce, emoji or frame goes in.
#
# Self-healing, ADR 0060 §5: a joined call rejoins with a new key when (1) tde2e fails for good (upstream left the
# call, groupCallInstance.ts callFailed), (2) its sub-chain 0 stays behind the server's next_offset with no block
# applied for more than 12 s, (3) a request meets GROUPCALL_FORBIDDEN (upstream already rejoins), (4) for 15 s
# frames came from senders and none decrypted while its chain is current. Those rejoins wait 0, 2 and 5 s and up
# to 1 s more at random, and the fourth within 5 minutes leaves the call with PlumaCall.EncryptionFailed
# (GroupCallsController.recoverConference). The rejoins of a failed transport stay as upstream has them and count
# for nothing; so do the retries of a join that met CONF_WRITE_CHAIN_INVALID, which are part of that join.
#
# Those retries, ADR 0060 §5 (as of 2026-11-13): upstream reads the last block again and joins on it, 5 attempts
# at most (groupCallConnectionInstance.ts:385, 408), which drops members of a herd that joins again at once after
# a restart of the SFU, each a block on the same height and one a round through. A refusal counts toward 10 in a
# row only when the last block read after it is the one the refused block was built on; while the chain moves
# the join goes on, for 100 attempts at most.

GROUP_CALLS = "src/lib/calls/groupCallsController.ts"
GROUP_CALL = "src/lib/calls/groupCallInstance.ts"
GROUP_CALL_CONNECTION = "src/lib/calls/groupCallConnectionInstance.ts"
E2E_CALL = "src/lib/calls/e2e/call.ts"
E2E_BLOCKCHAIN = "src/lib/calls/e2e/blockchain.ts"
E2E_WORKER = "src/lib/calls/e2e/encrypt.worker.ts"
E2E_PROTOCOL = "src/lib/calls/e2e/encryptWorkerProtocol.ts"
E2E_HOST = "src/lib/calls/e2e/encryptWorkerHost.ts"
IM_MANAGER = "src/lib/appImManager.ts"
JOIN_AS = "src/components/groupCall/joinAs.ts"
CALL_SETTINGS = "src/components/call/settingsPopup.tsx"
GROUP_CALL_POPUP = "src/components/groupCall/index.tsx"
GROUP_CALL_PARTICIPANTS = "src/components/groupCall/participants.ts"
SHARE_INVITE = "src/components/call/shareInviteLink.ts"
LIVE_STREAM_SUPPORT = "src/environment/liveStreamSupport.ts"
CONFERENCE_SUPPORT = "src/environment/conferenceCallSupport.ts"
RTMP_VIEWER = "src/components/mediaViewer/rtmp.ts"

_ADR = "(ADR 0060 of the server)"

E2E_GROUP_CALL_EDITS = (
    # A chat's call takes the end-to-end path, by its id and access hash, with its chat and its speaker invite.
    (GROUP_CALLS,
     "import {\n  findGroupCallChainUpdate\n} from '@lib/calls/helpers/groupCallUpdates';\n",
     "import {\n  findGroupCallChainUpdate,\n  groupCallToInput\n} from '@lib/calls/helpers/groupCallUpdates';\n"),
    (GROUP_CALLS,
     "  account?: CallAccount;\n};\ntype ConferenceStartOptions = {\n",
     "  account?: CallAccount;\n"
     "  /** pluma: the speaker invite of a chat's call it is joined by (phone.joinGroupCall `invite_hash`). */\n"
     "  inviteHash?: string;\n"
     "};\ntype ConferenceStartOptions = {\n"),
    (GROUP_CALLS,
     "    const streamManager = await createMainStreamManager(muted, joinVideo);\n"
     "    return this.joinGroupCallInternal(chatId, groupCallId, streamManager, muted, joinVideo, account, joinAs, inviteHash)\n"
     "    .then(() => {\n"
     "      // have to refresh participants because of the new connection\n"
     "      const {currentGroupCall} = this;\n"
     "      if(!currentGroupCall) return;\n"
     "      // The transport join is already accepted. Initial roster hydration is\n"
     "      // best-effort and will be refreshed by later participant updates, but\n"
     "      // the worker-proxy rejection still needs an observer.\n"
     "      this.replayCachedParticipants(currentGroupCall, 'initial group call participant hydration failed');\n"
     "    });\n"
     "  }\n",
     f"    // pluma: every group call is end-to-end {_ADR}. A chat's video chat is joined the way a\n"
     "    // conference is: a key of its own, born in the encryption worker, a block that adds us to the call's\n"
     "    // chain (`public_key` and `block` of phone.joinGroupCall), every frame encrypted; it keeps the interface\n"
     "    // of a chat's call (GroupCallInstance.isConference). A chain member is a user, so the account joins:\n"
     "    // `joinAs` is the account (chooseGroupCallJoinAs) and is not sent.\n"
     "    const groupCall = await account.managers.appGroupCallsManager.getGroupCallFull(groupCallId);\n"
     "    if(groupCall?._ !== 'groupCall') {\n"
     "      throw new Error('The group call is over');\n"
     "    }\n"
     "\n"
     "    await this.joinConference({\n"
     "      input: groupCallToInput(groupCall),\n"
     "      selfUserId: BigInt(account.myId),\n"
     "      chatId,\n"
     "      muted,\n"
     "      joinVideo,\n"
     "      account,\n"
     "      inviteHash\n"
     "    });\n"
     "  }\n"),
    (GROUP_CALLS,
     "    return instance.isConference ?\n      this.recoverConference(instance, reason) :\n",
     f"    // pluma: an end-to-end call, a chat's too, is joined again with a new key {_ADR}\n"
     "    return instance.isE2e ?\n      this.recoverConference(instance, reason) :\n"),
    (GROUP_CALLS,
     "    if(instance.isConference) {\n      throw new Error('A conference is joined as the account only');\n    }\n",
     f"    // pluma: a chain member is a user: every group call is joined as the account {_ADR}\n"
     "    if(instance.isE2e) {\n      throw new Error('An end-to-end call is joined as the account only');\n    }\n"),
    (GROUP_CALLS,
     "    instance.inviteHash = inviteHash;\n"
     "    // * only a rejoin under way now that goes out with it does instead\n"
     "    const isRejoining = this.groupCallRejoins.has(instance);\n"
     "    await this.rejoinUnlessJoined(instance, (options) => isRejoining && options.inviteHash === inviteHash, 'invite-hash');\n",
     "    instance.inviteHash = inviteHash;\n"
     f"    // pluma: a chat's call is end-to-end {_ADR}: it is joined again the way a conference is\n"
     "    // rebuilt, with a new key, and the invite goes with that join (recoverConference).\n"
     "    await this.recoverConference(instance, 'invite-hash');\n"),
    (GROUP_CALLS,
     "    if(!call || !this.currentGroupCall.e2e) {\n",
     "    if(!call || !this.currentGroupCall.isConference) {\n"),
    (GROUP_CALLS,
     "        outboundMediaRecoveryUsed: opts.outboundMediaRecoveryUsed,\n        account: opts.account\n      });\n",
     "        outboundMediaRecoveryUsed: opts.outboundMediaRecoveryUsed,\n        account: opts.account,\n"
     "        inviteHash: opts.inviteHash\n      });\n"),
    (GROUP_CALLS,
     "    commitRebuiltBlock?: () => Promise<void>;\n    account: CallAccount;\n  }): Promise<GroupCallInstance> {\n",
     "    commitRebuiltBlock?: () => Promise<void>;\n    account: CallAccount;\n"
     "    // pluma: the speaker invite of a chat's call (phone.joinGroupCall `invite_hash`)\n"
     "    inviteHash?: string;\n  }): Promise<GroupCallInstance> {\n"),
    (GROUP_CALLS,
     "      instance = createdInstance;\n",
     "      instance = createdInstance;\n      createdInstance.inviteHash = opts.inviteHash;\n"),
    (GROUP_CALLS,
     "          isMuted: opts.muted ?? true,\n          joinVideo: opts.joinVideo,\n          rejoin: false,\n",
     "          isMuted: opts.muted ?? true,\n          joinVideo: opts.joinVideo,\n          rejoin: false,\n"
     "          inviteHash: opts.inviteHash,\n"),
    (GROUP_CALLS,
     "        if(this.currentGroupCall === instance && state === GROUP_CALL_STATE.CLOSED) {\n"
     "          this.setCurrentGroupCall(null);\n"
     "          this.stopConnectingSound();\n"
     "          if(joinedSuccessfully && !this.recoveringConferences.has(instance)) {\n",
     "        if(this.currentGroupCall === instance && state === GROUP_CALL_STATE.CLOSED) {\n"
     "          this.setCurrentGroupCall(null);\n"
     "          this.stopConnectingSound();\n"
     "          // pluma: a chat's call, as its legacy join did: the chat's call buttons see it gone\n"
     "          if(instance.chatId) rootScope.dispatchEvent('chat_update', instance.chatId);\n"
     "          if(joinedSuccessfully && !this.recoveringConferences.has(instance)) {\n"),
    (GROUP_CALLS,
     "    const isConference = instance.isConference;\n    let stopped = false;\n",
     f"    // pluma: the transport of an end-to-end call, a chat's too {_ADR}\n"
     "    const isE2e = instance.isE2e;\n    let stopped = false;\n"),
    (GROUP_CALLS,
     "    if(IS_CHROMIUM && isConference) {\n",
     "    if(IS_CHROMIUM && isE2e) {\n"),
    (GROUP_CALLS,
     "          account: getCallAccountOf(instance)\n        });\n",
     "          account: getCallAccountOf(instance),\n          inviteHash: instance.inviteHash\n        });\n"),
    # The crypto and the interface asked one getter; now each asks its own.
    (GROUP_CALL,
     "  public get isConference(): boolean {\n    return !!this.e2e || this.selfUserId !== undefined;\n  }\n",
     f"  // pluma: end-to-end, the crypto of a conference: every group call, a chat's video chat too\n"
     f"  // {_ADR}. The transport, its recovery and joining as someone else ask this.\n"
     "  public get isE2e(): boolean {\n    return !!this.e2e || this.selfUserId !== undefined;\n  }\n"
     "\n"
     "  // pluma: a conference, the end-to-end call no chat stands behind (its creator runs it, it has its own\n"
     "  // link and no speaker invites): what the interface asks. A chat's video chat keeps a chat call's.\n"
     "  public get isConference(): boolean {\n"
     "    return this.isE2e && (!this.chatId || this.chatId === NULL_PEER_ID);\n"
     "  }\n"
     "\n"
     "  // pluma: the state of the call's encryption for the SFU (PlumaE2EStatus v1, ADR 0060 §5 of the server) once\n"
     "  // the chain is open: the worker's part, which it starts again once taken, and the cursors this instance\n"
     "  // polls the two sub-chains from.\n"
     "  public async takeE2eStatusReport(): Promise<E2eStatusReportFields | undefined> {\n"
     "    if(!this.e2e || !this.e2eActive || this.e2eActivating) return;\n"
     "    const report = await this.e2e.takeE2eReport();\n"
     "    return {...report, offset0: this.e2eChainOffsets[0], offset1: this.e2eChainOffsets[1]};\n"
     "  }\n"
     "\n"
     "  // pluma: rules 2 and 4 of the self-healing (ADR 0060 §5 of the server); rule 1 is the worker's callFailed,\n"
     "  // rule 3 GROUPCALL_FORBIDDEN (requestConferenceRecoveryForForbidden), and the controller bounds the rejoins\n"
     "  // they ask for. Rule 2: the server's sub-chain 0 is ahead of what this client applied and no block applies,\n"
     "  // for E2E_CHAIN_BEHIND_MS. Rule 4: for as long as the worker's E2E_DECRYPT_STALL_MS, frames came from\n"
     "  // senders and not one of them decrypted, while this client's chain is current: the fault is this client's.\n"
     "  // One sender that fails while others decrypt is that sender's, caught by its own rules.\n"
     "  private async checkE2eSelfHealing(): Promise<void> {\n"
     "    if(!this.e2e || !this.e2eActive || this.e2eActivating || this.conferenceRecoveryDispatched ||\n"
     "       this.checkingE2eSelfHealing) {\n"
     "      return;\n"
     "    }\n"
     "\n"
     "    const now = performance.now();\n"
     "    if(this.e2eServerChainOffset0 > this.e2eChainOffsets[0]) {\n"
     "      this.e2eChainBehindSince ??= now;\n"
     "      if(now - this.e2eChainBehindSince > E2E_CHAIN_BEHIND_MS) {\n"
     "        this.requestConferenceRecovery('chain-behind');\n"
     "      }\n"
     "      return;\n"
     "    }\n"
     "\n"
     "    this.e2eChainBehindSince = undefined;\n"
     "    this.checkingE2eSelfHealing = true;\n"
     "    try {\n"
     "      const stalled = await this.e2e.isDecryptStalled();\n"
     "      if(stalled && this.e2eActive && !this.conferenceRecoveryDispatched &&\n"
     "         this.e2eServerChainOffset0 <= this.e2eChainOffsets[0]) {\n"
     "        this.requestConferenceRecovery('decrypt-stalled');\n"
     "      }\n"
     "    } catch(err) {\n"
     "      this.log.warn('e2e self-healing check failed', err);\n"
     "    } finally {\n"
     "      this.checkingE2eSelfHealing = false;\n"
     "    }\n"
     "  }\n"),
    (GROUP_CALL,
     "import type {CallStatusSnapshot} from '@lib/calls/e2e/encryptWorkerProtocol';\n",
     "import type {CallStatusSnapshot, E2eStatusReportFields} from '@lib/calls/e2e/encryptWorkerProtocol';\n"),
    # Self-healing: a failure of the encryption rejoins instead of leaving, and the instance watches its chain and
    # its decryption.
    (GROUP_CALL,
     "const E2E_CHAIN_POLL_INTERVAL_MS = 1500;\n",
     "const E2E_CHAIN_POLL_INTERVAL_MS = 1500;\n"
     "// pluma: the self-healing of an end-to-end call (ADR 0060 §5 of the server): how often rules 2 and 4 are\n"
     "// checked, and how long this client's sub-chain 0 may stay behind the server's while no block applies (the\n"
     "// 10 s an old epoch stays usable, tde2e FORGET_EPOCH_DELAY of Call.h, and a margin)\n"
     "const E2E_SELF_HEALING_CHECK_MS = 1000;\n"
     "const E2E_CHAIN_BEHIND_MS = 12000;\n"),
    (GROUP_CALL,
     "  private e2eChainOffsets: {0: number; 1: number} = {0: 0, 1: 0};\n",
     "  private e2eChainOffsets: {0: number; 1: number} = {0: 0, 1: 0};\n"
     "  // pluma: the farthest next_offset of sub-chain 0 the server announced, since when this client has been behind\n"
     "  // it with no block applied, and the timer of rules 2 and 4 of the self-healing (checkE2eSelfHealing)\n"
     "  private e2eServerChainOffset0 = 0;\n"
     "  private e2eChainBehindSince: number | undefined;\n"
     "  private e2eSelfHealingInterval: ReturnType<typeof setInterval> | undefined;\n"
     "  private checkingE2eSelfHealing = false;\n"),
    (GROUP_CALL,
     "    if(!this.isValidE2eChainBatch(subChainId, blocks, nextOffset, requestedOffset)) {\n"
     "      return Promise.resolve(false);\n"
     "    }\n"
     "\n"
     "    const firstOffset = nextOffset - blocks.length;\n"
     "    if(subChainId === 1 && requestedOffset === 0 && this.e2eChainOffsets[1] === 0 && firstOffset > 0) {\n",
     "    if(!this.isValidE2eChainBatch(subChainId, blocks, nextOffset, requestedOffset)) {\n"
     "      return Promise.resolve(false);\n"
     "    }\n"
     "\n"
     "    // pluma: how far the server's sub-chain 0 goes, for rule 2 of the self-healing (checkE2eSelfHealing)\n"
     "    if(subChainId === 0 && nextOffset > this.e2eServerChainOffset0) {\n"
     "      this.e2eServerChainOffset0 = nextOffset;\n"
     "    }\n"
     "\n"
     "    const firstOffset = nextOffset - blocks.length;\n"
     "    if(subChainId === 1 && requestedOffset === 0 && this.e2eChainOffsets[1] === 0 && firstOffset > 0) {\n"),
    (GROUP_CALL,
     "      pending.delete(offset);\n      this.e2eChainOffsets[subChainId] = offset + 1;\n    }\n  }\n",
     "      pending.delete(offset);\n      this.e2eChainOffsets[subChainId] = offset + 1;\n"
     "      // pluma: a block applied, so this client is not stuck behind the server (rule 2 of the self-healing)\n"
     "      if(subChainId === 0) this.e2eChainBehindSince = undefined;\n"
     "    }\n  }\n"),
    (GROUP_CALL,
     "    // Watchdog: detect + self-heal a silent poller stall (see field comment).\n"
     "    if(!this.e2eWatchdogInterval) {\n"
     "      this.e2eWatchdogInterval = setInterval(() => {\n"
     "        this.e2eWatchdogTick();\n"
     "      }, E2E_WATCHDOG_INTERVAL_MS);\n"
     "    }\n"
     "  }\n",
     "    // Watchdog: detect + self-heal a silent poller stall (see field comment).\n"
     "    if(!this.e2eWatchdogInterval) {\n"
     "      this.e2eWatchdogInterval = setInterval(() => {\n"
     "        this.e2eWatchdogTick();\n"
     "      }, E2E_WATCHDOG_INTERVAL_MS);\n"
     "    }\n"
     "\n"
     f"    // pluma: rules 2 and 4 of the self-healing {_ADR}\n"
     "    if(!this.e2eSelfHealingInterval) {\n"
     "      this.e2eChainBehindSince = undefined;\n"
     "      this.e2eSelfHealingInterval = setInterval(() => {\n"
     "        void this.checkE2eSelfHealing();\n"
     "      }, E2E_SELF_HEALING_CHECK_MS);\n"
     "    }\n"
     "  }\n"),
    (GROUP_CALL,
     "    if(this.e2eWatchdogInterval) {\n"
     "      clearInterval(this.e2eWatchdogInterval);\n"
     "      this.e2eWatchdogInterval = undefined;\n"
     "    }\n"
     "  }\n",
     "    if(this.e2eWatchdogInterval) {\n"
     "      clearInterval(this.e2eWatchdogInterval);\n"
     "      this.e2eWatchdogInterval = undefined;\n"
     "    }\n"
     "    if(this.e2eSelfHealingInterval) {\n"
     "      clearInterval(this.e2eSelfHealingInterval);\n"
     "      this.e2eSelfHealingInterval = undefined;\n"
     "    }\n"
     "  }\n"),
    (GROUP_CALL,
     "      this.log.error('e2e: callFailed — leaving; reason:', message);\n"
     "      this.e2eFatalError ??= new Error(message);\n"
     "      // Leave, do NOT discard. `hangUp(true)` routes to phone.discardGroupCall,\n"
     "      // which ends the conference for EVERY participant — so one client failing\n"
     "      // to apply a block used to tear down everyone else's call. Our e2e state\n"
     "      // being unusable is a statement about this client only; the others may be\n"
     "      // perfectly healthy, and if they are not, they will each decide that for\n"
     "      // themselves.\n"
     "      // Before/during activation the join transaction owns rollback. Let\n"
     "      // activateE2e reject into it instead of racing it with a second leave.\n"
     "      if(this.e2eActive && !this.e2eActivating) this.hangUpAfterFatalFailure();\n"
     "    });\n",
     "      // pluma: any other sticky tde2e failure of a joined call is rule 1 of the self-healing (ADR 0060 §5 of\n"
     "      // the server): a full rejoin with a new key, as tdesktop answers every tde2e failure (\"TdE2E: Got\n"
     "      // failure, scheduling rejoin!\", calls_group_call.cpp:787-790), never discarding the call for everyone.\n"
     "      // The controller bounds the rejoins and leaves with a message past them.\n"
     "      if(this.e2eActive && !this.e2eActivating) {\n"
     "        this.log.warn('e2e: callFailed — requesting full rejoin', message);\n"
     "        this.requestConferenceRecovery('e2e-failure');\n"
     "        return;\n"
     "      }\n"
     "\n"
     "      // Before/during activation the join transaction owns rollback. Let\n"
     "      // activateE2e reject into it instead of racing it with a leave.\n"
     "      this.log.error('e2e: callFailed before activation; reason:', message);\n"
     "      this.e2eFatalError ??= new Error(message);\n"
     "    });\n"),
    # The controller bounds the rejoins the encryption asks for.
    (GROUP_CALLS,
     "const OUTBOUND_MEDIA_BLACKHOLE_REASON = 'outbound-media-blackhole';\n",
     "const OUTBOUND_MEDIA_BLACKHOLE_REASON = 'outbound-media-blackhole';\n"
     "// pluma: the rejoins of the self-healing of an end-to-end call (ADR 0060 §5 of the server): at most\n"
     "// E2E_REJOINS_LIMIT in a rolling E2E_REJOINS_PERIOD_MS, then the call is left with a message; before each, the\n"
     "// delay of its place in that window and a random part. Every rejoin changes the key for everyone, and\n"
     "// members rejoining at once collide in CONF_WRITE_CHAIN_INVALID. Only the encryption's reasons count: a\n"
     "// failed transport, an SSRC clash or a speaker link rejoin as they did, and the retries of a join that met\n"
     "// CONF_WRITE_CHAIN_INVALID are part of that join (GroupCallConnectionInstance).\n"
     "const E2E_REJOINS_LIMIT = 3;\n"
     "const E2E_REJOINS_PERIOD_MS = 5 * 60 * 1000;\n"
     "const E2E_REJOIN_DELAYS_MS = [0, 2000, 5000];\n"
     "const E2E_REJOIN_JITTER_MS = 1000;\n"
     "// What GroupCallInstance asks a rejoin for when its encryption fails: a sticky tde2e error (`e2e-failure`,\n"
     "// `membership-lost`), its chain behind the server's (`chain-behind`), GROUPCALL_FORBIDDEN on any of its\n"
     "// requests (`*-forbidden`), nothing decrypted from anybody (`decrypt-stalled`).\n"
     "const isE2eRejoinReason = (reason: string) => reason === 'e2e-failure' || reason === 'membership-lost' ||\n"
     "  reason === 'chain-behind' || reason === 'decrypt-stalled' || reason.endsWith('-forbidden');\n"),
    (GROUP_CALLS,
     "  private recoveringConferences = new WeakSet<GroupCallInstance>();\n",
     "  private recoveringConferences = new WeakSet<GroupCallInstance>();\n"
     "  // pluma: when the encryption of each call last asked a rejoin, within E2E_REJOINS_PERIOD_MS\n"
     "  private e2eRejoins = new Map<GroupCallId, number[]>();\n"),
    (GROUP_CALLS,
     "    this.log.warn('rejoining conference', {reason, id: instance.id});\n"
     "    const promise = (async() => {\n"
     "      try {\n"
     "        await instance.hangUp(false, false, true);\n",
     "    this.log.warn('rejoining conference', {reason, id: instance.id});\n"
     "    // pluma: a rejoin the encryption asks for waits its delay, and past the limit the call is left\n"
     "    const e2eRejoinDelay = isE2eRejoinReason(reason) ? this.takeE2eRejoinDelay(instance.id) : 0;\n"
     "    const promise = (async() => {\n"
     "      try {\n"
     "        if(e2eRejoinDelay === undefined) {\n"
     "          this.log.error('the encryption keeps failing — leaving the call', {reason, id: instance.id});\n"
     "          await instance.hangUp();\n"
     "          toastNew({langPackKey: 'PlumaCall.EncryptionFailed'});\n"
     "          return;\n"
     "        }\n"
     "        if(e2eRejoinDelay) {\n"
     "          await pause(e2eRejoinDelay);\n"
     "          this.assertConferenceTransition(generation);\n"
     "          if(this.currentGroupCall !== instance || instance.isClosing) return;\n"
     "        }\n"
     "        await instance.hangUp(false, false, true);\n"),
    (GROUP_CALLS,
     "  private assertConferenceTransition(generation?: number): void {\n",
     "  // pluma: the delay before the rejoin the encryption of call `id` asks for now, or undefined when it asked\n"
     "  // E2E_REJOINS_LIMIT times in the last E2E_REJOINS_PERIOD_MS already (ADR 0060 §5 of the server)\n"
     "  private takeE2eRejoinDelay(id: GroupCallId): number | undefined {\n"
     "    const now = performance.now();\n"
     "    const recent = (this.e2eRejoins.get(id) || []).filter((at) => now - at < E2E_REJOINS_PERIOD_MS);\n"
     "    if(recent.length >= E2E_REJOINS_LIMIT) {\n"
     "      this.e2eRejoins.delete(id);\n"
     "      return;\n"
     "    }\n"
     "\n"
     "    recent.push(now);\n"
     "    this.e2eRejoins.set(id, recent);\n"
     "    return E2E_REJOIN_DELAYS_MS[recent.length - 1] + Math.floor(Math.random() * E2E_REJOIN_JITTER_MS);\n"
     "  }\n"
     "\n"
     "  private assertConferenceTransition(generation?: number): void {\n"),
    ("src/lang.ts",
     "  'Error.AnError': 'An error occurred. Please try again later.',\n",
     "  'Error.AnError': 'An error occurred. Please try again later.',\n"
     "  'PlumaCall.EncryptionFailed': 'The encryption of this call keeps failing, so you left it. Join it again.',\n"),
    # The report goes over the main connection's data channel.
    (GROUP_CALL_CONNECTION,
     "const REMOTE_VIDEO_CONSTRAINTS_REFRESH_MS = 5000;\n",
     "const REMOTE_VIDEO_CONSTRAINTS_REFRESH_MS = 5000;\n"
     "// pluma: the status report of the call's encryption (PlumaE2EStatus v1, ADR 0060 §5 of the server): every 5 s\n"
     "// by its own timer, the first 5 s after the join, at most 16 KiB of JSON\n"
     "const E2E_STATUS_REPORT_INTERVAL_MS = 5000;\n"
     "const E2E_STATUS_REPORT_MAX_LENGTH = 16384;\n"
     "\n"
     "// pluma: the report as the SFU takes it: these fields and no other, `seq` counting the reports of this join\n"
     "// from 1. Past the size limit the senders decrypted longest ago go first. Every value is a number, a hex\n"
     "// string or a name, so the length of the JSON is its size in bytes.\n"
     "function serializeE2eStatusReport(seq: number, report: E2eStatusReportFields): string {\n"
     "  const senders = report.senders.map(({user, ok, unknownEpoch, tooOld, duplicate, failed, lastOkMs}) => {\n"
     "    return {user, ok, unknownEpoch, tooOld, duplicate, failed, lastOkMs};\n"
     "  });\n"
     "  for(;;) {\n"
     "    const json = JSON.stringify({\n"
     "      colibriClass: 'PlumaE2EStatus',\n"
     "      v: 1,\n"
     "      seq,\n"
     "      height: report.height,\n"
     "      lastBlock: report.lastBlock,\n"
     "      offset0: report.offset0,\n"
     "      offset1: report.offset1,\n"
     "      error: report.error,\n"
     "      sendEpochs: report.sendEpochs,\n"
     "      decryptEpochs: report.decryptEpochs,\n"
     "      unknownEpochs: report.unknownEpochs,\n"
     "      encrypted: report.encrypted,\n"
     "      encryptFailed: report.encryptFailed,\n"
     "      senders\n"
     "    });\n"
     "    if(json.length <= E2E_STATUS_REPORT_MAX_LENGTH || !senders.length) return json;\n"
     "    let oldest = 0;\n"
     "    for(let i = 1; i < senders.length; ++i) {\n"
     "      if(senders[i].lastOkMs > senders[oldest].lastOkMs) oldest = i;\n"
     "    }\n"
     "    senders.splice(oldest, 1);\n"
     "  }\n"
     "}\n"),
    (GROUP_CALL_CONNECTION,
     "import {InputGroupCall} from '@layer';\n",
     "import {InputGroupCall} from '@layer';\n"
     "import type {E2eStatusReportFields} from '@lib/calls/e2e/encryptWorkerProtocol';\n"),
    (GROUP_CALL_CONNECTION,
     "  private updateConstraintsTimeout: number;\n",
     "  private updateConstraintsTimeout: number;\n"
     "  private e2eStatusReportInterval: number;\n"
     "  private e2eStatusReportSeq = 0;\n"),
    (GROUP_CALL_CONNECTION,
     "    dataChannel.addEventListener('open', () => {\n"
     "      this.maybeUpdateRemoteVideoConstraints();\n"
     "    });\n"
     "\n"
     "    dataChannel.addEventListener('close', () => {\n"
     "      this.clearUpdateConstraintsInterval();\n"
     "    });\n",
     "    dataChannel.addEventListener('open', () => {\n"
     "      this.maybeUpdateRemoteVideoConstraints();\n"
     "      this.startE2eStatusReports();\n"
     "    });\n"
     "\n"
     "    dataChannel.addEventListener('close', () => {\n"
     "      this.clearUpdateConstraintsInterval();\n"
     "      this.stopE2eStatusReports();\n"
     "    });\n"),
    (GROUP_CALL_CONNECTION,
     "    this.clearUpdateConstraintsInterval();\n    this.senderVideoConstraint.dispose();\n    super.closeConnection();\n",
     "    this.clearUpdateConstraintsInterval();\n    this.stopE2eStatusReports();\n"
     "    this.senderVideoConstraint.dispose();\n    super.closeConnection();\n"),
    (GROUP_CALL_CONNECTION,
     "  protected onDataChannelMessage(message: Record<string, unknown>) {\n",
     "  // pluma: the state of the call's end-to-end encryption for the SFU, over the main connection's data channel\n"
     "  // while it is open (colibriClass \"PlumaE2EStatus\" v1, ADR 0060 §5 of the server): heights, cursors, epochs\n"
     "  // and counters, never a key, a nonce, the emoji or a frame. The server sees from it whose keys went out of\n"
     "  // step. A report is taken from the worker only while the channel is open: what is not taken goes in the\n"
     "  // next one.\n"
     "  private startE2eStatusReports() {\n"
     "    if(this.type !== 'main' || !this.groupCall?.e2e || this.e2eStatusReportInterval) {\n"
     "      return;\n"
     "    }\n"
     "\n"
     "    this.e2eStatusReportInterval = window.setInterval(() => {\n"
     "      if(this.dataChannel?.readyState !== 'open') return;\n"
     "      this.groupCall.takeE2eStatusReport().then((report) => {\n"
     "        if(!report || this.dataChannel?.readyState !== 'open') return;\n"
     "        this.dataChannel.send(serializeE2eStatusReport(++this.e2eStatusReportSeq, report));\n"
     "      }).catch((err) => {\n"
     "        this.log.warn('e2e status report failed', err);\n"
     "      });\n"
     "    }, E2E_STATUS_REPORT_INTERVAL_MS);\n"
     "  }\n"
     "\n"
     "  private stopE2eStatusReports() {\n"
     "    if(this.e2eStatusReportInterval) {\n"
     "      clearInterval(this.e2eStatusReportInterval);\n"
     "      this.e2eStatusReportInterval = undefined;\n"
     "    }\n"
     "  }\n"
     "\n"
     "  protected onDataChannelMessage(message: Record<string, unknown>) {\n"),
    # The report's requests, its shape, and what the worker counts for it.
    (E2E_PROTOCOL,
     "  | {kind: 'getStatus'; id: number}\n",
     "  | {kind: 'getStatus'; id: number}\n"
     f"  // pluma: the status report of the encryption and rule 4 of the self-healing {_ADR}\n"
     "  | {kind: 'takeE2eReport'; id: number}\n"
     "  | {kind: 'isDecryptStalled'; id: number}\n"),
    (E2E_PROTOCOL,
     "export interface OutboundBroadcast {\n",
     "// pluma: what the client tells the SFU of the call's encryption, over the data channel every 5 s\n"
     "// (PlumaE2EStatus v1, ADR 0060 §5 of the server; the same for every Pluma client). The frame counters and the\n"
     "// epoch lists are what happened since the last report; the other fields are current values. Epochs and blocks\n"
     "// go as the first 8 bytes of their hash in hex, which the server can compute anyway; no key, nonce, emoji or\n"
     "// frame goes in.\n"
     "export interface E2eSenderReport {\n"
     "  // the sender's user_id\n"
     "  user: number;\n"
     "  // their frames decrypted, and the ones that were not: the frame names no active epoch of ours (tde2e\n"
     "  // Decrypt_UnknownEpoch), it is older than the replay window (\"Message is too old\"), it came already\n"
     "  // (\"Message is already processed\"), anything else\n"
     "  ok: number;\n"
     "  unknownEpoch: number;\n"
     "  tooOld: number;\n"
     "  duplicate: number;\n"
     "  failed: number;\n"
     "  // milliseconds from their last frame decrypted to the report, -1 when none was\n"
     "  lastOkMs: number;\n"
     "}\n"
     "\n"
     "// The worker's part of the report.\n"
     "export interface E2eStatusReport {\n"
     "  // the height of sub-chain 0 applied, -1 without a state (a failed call)\n"
     "  height: number;\n"
     "  // the hash of the block at that height, the block as the server keeps it (the local form, its hash is\n"
     "  // tde2e's own), '' without a state\n"
     "  lastBlock: string;\n"
     "  // the tde2e code (e2e_errors.h) of the sticky failure, 0 while the call works\n"
     "  error: number;\n"
     "  // the epochs the last frame encrypted names: what this client encrypts with now (at most 15)\n"
     "  sendEpochs: string[];\n"
     "  // the epochs named by frames decrypted (at most 15), and by frames failed with Decrypt_UnknownEpoch (the\n"
     "  // first 8)\n"
     "  decryptEpochs: string[];\n"
     "  unknownEpochs: string[];\n"
     "  // frames of this client's streams encrypted, and not\n"
     "  encrypted: number;\n"
     "  encryptFailed: number;\n"
     "  // the senders a frame came from, by user (at most 100)\n"
     "  senders: E2eSenderReport[];\n"
     "}\n"
     "\n"
     "// The whole report but its framing: the worker's part and the cursors the two sub-chains are polled from\n"
     "// (offset1 is the broadcasts' cursor).\n"
     "export type E2eStatusReportFields = E2eStatusReport & {offset0: number; offset1: number};\n"
     "\n"
     "export interface OutboundBroadcast {\n"),
    (E2E_PROTOCOL,
     "  getStatus: CallStatusSnapshot;\n",
     "  getStatus: CallStatusSnapshot;\n  takeE2eReport: E2eStatusReport;\n  isDecryptStalled: boolean;\n"),
    (E2E_HOST,
     "  public getStatus(): Promise<RequestResultMap['getStatus']> {\n    return this.invoke('getStatus');\n  }\n",
     "  public getStatus(): Promise<RequestResultMap['getStatus']> {\n    return this.invoke('getStatus');\n  }\n"
     "\n"
     f"  // pluma: the status report of the encryption, which starts its counters again {_ADR}\n"
     "  public takeE2eReport(): Promise<RequestResultMap['takeE2eReport']> {\n"
     "    return this.invoke('takeE2eReport');\n"
     "  }\n"
     "\n"
     f"  // pluma: rule 4 of the self-healing {_ADR}\n"
     "  public isDecryptStalled(): Promise<RequestResultMap['isDecryptStalled']> {\n"
     "    return this.invoke('isDecryptStalled');\n"
     "  }\n"),
    (E2E_HOST,
     "    args?: K extends 'createKey' | 'pullOutbound' | 'getStatus' | 'commitRejoinBlock' | 'destroy' ?\n",
     "    args?: K extends 'createKey' | 'pullOutbound' | 'getStatus' | 'takeE2eReport' | 'isDecryptStalled' |\n"
     "      'commitRejoinBlock' | 'destroy' ?\n"),
    (E2E_CALL,
     "  public getLastBlockHash(): Uint8Array {\n    this.checkStatus();\n    return new Uint8Array(this.state.lastBlockHash);\n  }\n",
     "  public getLastBlockHash(): Uint8Array {\n    this.checkStatus();\n    return new Uint8Array(this.state.lastBlockHash);\n  }\n"
     "\n"
     "  // pluma: the hashes of the active epochs, which tell the status report of the encryption a frame that names\n"
     f"  // none of ours from one whose key of ours failed {_ADR}\n"
     "  public getEpochHashes(): Uint8Array[] {\n"
     "    this.checkStatus();\n"
     "    return this.epochs.map((epoch) => new Uint8Array(epoch.epochHash));\n"
     "  }\n"),
    (E2E_WORKER,
     "import {ensureCryptoReady, randomBytes} from './crypto';\n"
     "import type {CallStatusSnapshot, HostRequest, HostResponse, WorkerEvent} from './encryptWorkerProtocol';\n",
     "import {bytesToHex, ensureCryptoReady, randomBytes} from './crypto';\n"
     "import type {\n"
     "  CallStatusSnapshot,\n"
     "  E2eSenderReport,\n"
     "  E2eStatusReport,\n"
     "  HostRequest,\n"
     "  HostResponse,\n"
     "  WorkerEvent\n"
     "} from './encryptWorkerProtocol';\n"),
    (E2E_WORKER,
     "    case 'getStatus':\n      return snapshot();\n",
     "    case 'getStatus':\n      return snapshot();\n"
     "\n"
     "    case 'takeE2eReport':\n"
     "      if(!call) throw new Error('takeE2eReport: not initialized');\n"
     "      return takeE2eReport();\n"
     "\n"
     "    case 'isDecryptStalled':\n"
     "      return isDecryptStalled();\n"),
    (E2E_WORKER,
     "      pendingRejoinBlock = undefined;\n      ssrcToUser.clear();\n      return undefined;\n",
     "      pendingRejoinBlock = undefined;\n      ssrcToUser.clear();\n      resetE2eReport();\n      return undefined;\n"),
    (E2E_WORKER,
     "const decryptErrFrames = new Map<number, number>();\n",
     "const decryptErrFrames = new Map<number, number>();\n"
     "\n"
     "// pluma: the counters of the status report (E2eStatusReport, ADR 0060 §5 of the server) of the call this\n"
     "// worker holds, and what rule 4 of the self-healing reads (isDecryptStalled). The frame counters and the epoch\n"
     "// lists are since the last report, which takes them; per sender also when a frame of theirs last came, last\n"
     "// decrypted, and since when theirs fail. Times are performance.now(), as the epochs' own.\n"
     "const E2E_REPORT_MAX_EPOCHS = 15;\n"
     "const E2E_REPORT_MAX_UNKNOWN_EPOCHS = 8;\n"
     "const E2E_REPORT_MAX_SENDERS = 100;\n"
     "// rule 4 of the self-healing: frames came for this long and none decrypted (Web K's own sync watchdog waits\n"
     "// as long, E2E_SYNC_STALL_MS of groupCallInstance.ts)\n"
     "const E2E_DECRYPT_STALL_MS = 15000;\n"
     "// The tde2e codes (tde2e/td/e2e/e2e_errors.h) of the errors this port fails a call with, by the code its\n"
     "// BlockchainError (blockchain.ts) and CallError (call.ts) carry; any other is UnknownError.\n"
     "const TDE2E_ERROR_CODES: {[code: string]: number} = {\n"
     "  NO_CHANGES: 201,\n"
     "  INVALID_SIGNATURE: 202,\n"
     "  PREVIOUS_BLOCK_HASH_MISMATCH: 203,\n"
     "  HEIGHT_MISMATCH: 204,\n"
     "  INVALID_STATE_PROOF: 205,\n"
     "  NO_PERMISSIONS: 207,\n"
     "  INVALID_GROUP_STATE: 208,\n"
     "  INVALID_SHARED_KEY: 209,\n"
     "  NOT_PARTICIPANT: 300,\n"
     "  WRONG_USER_ID: 301,\n"
     "  CALL_FAILED: 601\n"
     "};\n"
     "const TDE2E_UNKNOWN_ERROR = 100;\n"
     "type SenderCounters = Omit<E2eSenderReport, 'user' | 'lastOkMs'> & {\n"
     "  lastFrameAt?: number;\n"
     "  lastOkAt?: number;\n"
     "  failingSince?: number;\n"
     "};\n"
     "const senderCounters = new Map<bigint, SenderCounters>();\n"
     "const decryptEpochs = new Set<string>();\n"
     "const unknownEpochs = new Set<string>();\n"
     "let sendEpochs: string[] = [];\n"
     "let encryptedFrames = 0;\n"
     "let encryptFailedFrames = 0;\n"
     "\n"
     "function senderCountersOf(userId: bigint): SenderCounters {\n"
     "  let counters = senderCounters.get(userId);\n"
     "  if(!counters) {\n"
     "    counters = {ok: 0, unknownEpoch: 0, tooOld: 0, duplicate: 0, failed: 0};\n"
     "    senderCounters.set(userId, counters);\n"
     "  }\n"
     "  return counters;\n"
     "}\n"
     "\n"
     "// The first 8 bytes of the epoch hashes a frame names in its header_a, read the way decryptPacket (call.ts)\n"
     "// reads them: the length of the unencrypted prefix in the last 4 bytes, after the prefix the head with the\n"
     "// number of epochs in its low byte, then a 32-byte hash per epoch.\n"
     "function frameEpochHashPrefixes(packet: Uint8Array): string[] {\n"
     "  if(packet.length < 8) return [];\n"
     "  const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength);\n"
     "  const bodyEnd = packet.length - 4;\n"
     "  const prefixLength = view.getUint32(bodyEnd, true);\n"
     "  if(prefixLength > bodyEnd - 4) return [];\n"
     "  const epochsN = view.getUint32(prefixLength, true) & 0xff;\n"
     "  const prefixes: string[] = [];\n"
     "  for(let i = 0, offset = prefixLength + 4; i < epochsN && offset + 32 <= bodyEnd; ++i, offset += 32) {\n"
     "    prefixes.push(view.getUint32(offset).toString(16).padStart(8, '0') +\n"
     "      view.getUint32(offset + 4).toString(16).padStart(8, '0'));\n"
     "  }\n"
     "  return prefixes;\n"
     "}\n"
     "\n"
     "function addEpochs(epochs: Set<string>, prefixes: string[], limit: number): void {\n"
     "  for(const prefix of prefixes) {\n"
     "    if(epochs.size >= limit) return;\n"
     "    epochs.add(prefix);\n"
     "  }\n"
     "}\n"
     "\n"
     "// The hash prefixes of our active epochs; none once the call is gone or failed.\n"
     "function ownEpochHashPrefixes(): Set<string> {\n"
     "  try {\n"
     "    return new Set((call?.getEpochHashes() ?? []).map((hash) => bytesToHex(hash.subarray(0, 8))));\n"
     "  } catch{\n"
     "    return new Set();\n"
     "  }\n"
     "}\n"
     "\n"
     "function countEncrypted(encrypted: Uint8Array | undefined): void {\n"
     "  if(!encrypted) {\n"
     "    ++encryptFailedFrames;\n"
     "    return;\n"
     "  }\n"
     "\n"
     "  ++encryptedFrames;\n"
     "  const prefixes = frameEpochHashPrefixes(encrypted);\n"
     "  if(prefixes.length !== sendEpochs.length || prefixes.some((prefix, i) => prefix !== sendEpochs[i])) {\n"
     "    sendEpochs = prefixes.slice(0, E2E_REPORT_MAX_EPOCHS);\n"
     "  }\n"
     "}\n"
     "\n"
     "function countDecrypted(fromUserId: bigint, packet: Uint8Array): void {\n"
     "  const counters = senderCountersOf(fromUserId);\n"
     "  ++counters.ok;\n"
     "  counters.lastFrameAt = counters.lastOkAt = performance.now();\n"
     "  counters.failingSince = undefined;\n"
     "  addEpochs(decryptEpochs, frameEpochHashPrefixes(packet), E2E_REPORT_MAX_EPOCHS);\n"
     "}\n"
     "\n"
     "// By the words of decryptPacket and ReplayState.checkAndMark (call.ts). decryptPacket says \"no matching active\n"
     "// epoch\" also when a frame names an epoch of ours whose key does not open its header; tde2e fails that one on\n"
     "// the key (Call::decrypt, Decrypt_UnknownEpoch only when no epoch matched), and so does the report.\n"
     "function countDecryptError(fromUserId: bigint, err: unknown, packet: Uint8Array): void {\n"
     "  const counters = senderCountersOf(fromUserId);\n"
     "  const now = counters.lastFrameAt = performance.now();\n"
     "  const message = (err as Error)?.message || '';\n"
     "  if(/^replay: seqno \\d+ older than window /.test(message)) {\n"
     "    ++counters.tooOld;\n"
     "    return;\n"
     "  }\n"
     "  if(/^replay: seqno \\d+ already seen$/.test(message)) {\n"
     "    ++counters.duplicate;\n"
     "    return;\n"
     "  }\n"
     "\n"
     "  counters.failingSince ??= now;\n"
     "  if(message === 'decryptPacket: no matching active epoch') {\n"
     "    const named = frameEpochHashPrefixes(packet);\n"
     "    const own = ownEpochHashPrefixes();\n"
     "    if(!named.some((prefix) => own.has(prefix))) {\n"
     "      ++counters.unknownEpoch;\n"
     "      addEpochs(unknownEpochs, named, E2E_REPORT_MAX_UNKNOWN_EPOCHS);\n"
     "      return;\n"
     "    }\n"
     "  }\n"
     "  ++counters.failed;\n"
     "}\n"
     "\n"
     "function tde2eErrorCode(error: Error): number {\n"
     "  const code = /^([A-Z_]+): /.exec(error.message)?.[1];\n"
     "  return (code && TDE2E_ERROR_CODES[code]) || TDE2E_UNKNOWN_ERROR;\n"
     "}\n"
     "\n"
     "// The report, which starts the counters and the epoch lists again.\n"
     "function takeE2eReport(): E2eStatusReport {\n"
     "  const failure = call.getStatus();\n"
     "  const now = performance.now();\n"
     "  const senders: E2eSenderReport[] = [];\n"
     "  for(const [userId, counters] of senderCounters) {\n"
     "    const {ok, unknownEpoch, tooOld, duplicate, failed, lastOkAt} = counters;\n"
     "    if(!(ok + unknownEpoch + tooOld + duplicate + failed)) continue;\n"
     "    senders.push({\n"
     "      user: Number(userId),\n"
     "      ok,\n"
     "      unknownEpoch,\n"
     "      tooOld,\n"
     "      duplicate,\n"
     "      failed,\n"
     "      lastOkMs: lastOkAt === undefined ? -1 : Math.round(now - lastOkAt)\n"
     "    });\n"
     "    counters.ok = counters.unknownEpoch = counters.tooOld = counters.duplicate = counters.failed = 0;\n"
     "  }\n"
     "  senders.sort((a, b) => a.user - b.user);\n"
     "  senders.splice(E2E_REPORT_MAX_SENDERS);\n"
     "\n"
     "  const report: E2eStatusReport = {\n"
     "    height: failure ? -1 : call.getHeight(),\n"
     "    lastBlock: failure ? '' : bytesToHex(call.getLastBlockHash().subarray(0, 8)),\n"
     "    error: failure ? tde2eErrorCode(failure) : 0,\n"
     "    sendEpochs: sendEpochs.slice(),\n"
     "    decryptEpochs: [...decryptEpochs],\n"
     "    unknownEpochs: [...unknownEpochs],\n"
     "    encrypted: encryptedFrames,\n"
     "    encryptFailed: encryptFailedFrames,\n"
     "    senders\n"
     "  };\n"
     "  decryptEpochs.clear();\n"
     "  unknownEpochs.clear();\n"
     "  encryptedFrames = encryptFailedFrames = 0;\n"
     "  return report;\n"
     "}\n"
     "\n"
     "// Rule 4 of the self-healing (ADR 0060 §5 of the server): frames came from senders in the last\n"
     "// E2E_DECRYPT_STALL_MS, and every one of them has failed for that long without a frame decrypted.\n"
     "function isDecryptStalled(): boolean {\n"
     "  if(!call || call.getStatus()) return false;\n"
     "  const now = performance.now();\n"
     "  let sending = false;\n"
     "  for(const {lastFrameAt, failingSince} of senderCounters.values()) {\n"
     "    if(lastFrameAt === undefined || now - lastFrameAt > E2E_DECRYPT_STALL_MS) continue;\n"
     "    if(failingSince === undefined || now - failingSince < E2E_DECRYPT_STALL_MS) return false;\n"
     "    sending = true;\n"
     "  }\n"
     "  return sending;\n"
     "}\n"
     "\n"
     "function resetE2eReport(): void {\n"
     "  senderCounters.clear();\n"
     "  decryptEpochs.clear();\n"
     "  unknownEpochs.clear();\n"
     "  sendEpochs = [];\n"
     "  encryptedFrames = encryptFailedFrames = 0;\n"
     "}\n"),
    (E2E_WORKER,
     "    frame.data = toFrameData(encrypted);\n    return frame;\n  } catch{\n    return undefined;\n  }\n}\n",
     "    countEncrypted(encrypted); // pluma: for the status report, before the frame takes the bytes\n"
     "    frame.data = toFrameData(encrypted);\n    return frame;\n  } catch{\n"
     "    countEncrypted(undefined); // pluma: for the status report\n"
     "    return undefined;\n  }\n}\n"),
    (E2E_WORKER,
     "    frame.data = toFrameData(decrypted);\n    // Recovered — let a later error on this SSRC report afresh.\n",
     "    countDecrypted(fromUserId, encrypted); // pluma: for the status report\n"
     "    frame.data = toFrameData(decrypted);\n"
     "    // Recovered — let a later error on this SSRC report afresh.\n"),
    (E2E_WORKER,
     "  } catch(err) {\n    const message = (err as Error)?.message?.slice(0, 80) || '';\n",
     "  } catch(err) {\n"
     "    countDecryptError(fromUserId, err, new Uint8Array(frame.data)); // pluma: for the status report\n"
     "    const message = (err as Error)?.message?.slice(0, 80) || '';\n"),
    # Into a chat's call: not without RTCRtpScriptTransform, and not as a channel.
    (IM_MANAGER,
     "    return this.callTransitions.run(async() => {\n"
     "      const chatId = peerId.toChatId();\n"
     "      const hasRights = await managers.appChatsManager.hasRights(chatId, 'manage_call');\n",
     "    return this.callTransitions.run(async() => {\n"
     f"      // pluma: every group call is end-to-end {_ADR}; a browser that cannot encrypt frames\n"
     "      // (no RTCRtpScriptTransform) is told so, as for a conference, and starts or joins nothing.\n"
     "      if(!IS_CONFERENCE_CALL_SUPPORTED) {\n"
     "        toastNew({langPackKey: 'ConferenceCall.Unsupported'});\n"
     "        return;\n"
     "      }\n"
     "\n"
     "      const chatId = peerId.toChatId();\n"
     "      const hasRights = await managers.appChatsManager.hasRights(chatId, 'manage_call');\n"),
    (IM_MANAGER,
     "      const isLive = !!call.pFlags.rtmp_stream;\n"
     "      if(!isLive && !IS_GROUP_CALL_SUPPORTED) {\n"
     "        return;\n"
     "      }\n",
     f"      // pluma: no RTMP streams {_ADR}: a link to one leads nowhere (joinLiveStream). Every\n"
     "      // other call is end-to-end, which a browser without RTCRtpScriptTransform cannot join: it says so.\n"
     "      if(call.pFlags.rtmp_stream) {\n"
     "        toastNew({langPackKey: 'Error.AnError'});\n"
     "        return;\n"
     "      }\n"
     "\n"
     "      if(!IS_GROUP_CALL_SUPPORTED) {\n"
     "        return;\n"
     "      }\n"
     "\n"
     "      if(!IS_CONFERENCE_CALL_SUPPORTED) {\n"
     "        toastNew({langPackKey: 'ConferenceCall.Unsupported'});\n"
     "        return;\n"
     "      }\n"),
    (IM_MANAGER,
     "        leaveCurrentCall = await this.confirmLeavingCurrentCall(peerId, isLive ? 'Live' : 'Voice');\n",
     "        leaveCurrentCall = await this.confirmLeavingCurrentCall(peerId, 'Voice');\n"),
    (IM_MANAGER,
     "      const confirm = !leaveCurrentCall;\n"
     "      if(isLive) {\n"
     "        if(confirm && !(await confirmGroupCallJoin(account, peerId, call.title))) {\n"
     "          return;\n"
     "        }\n"
     "\n"
     "        await leaveCurrentCall?.();\n"
     "        await this.watchLiveStream(peerId, account, call.id);\n"
     "        return;\n"
     "      }\n",
     "      const confirm = !leaveCurrentCall;\n"),
    (IM_MANAGER,
     "  public joinLiveStream(peerId: PeerId): Promise<void> {\n"
     "    // * the account the stream is watched on: the tab can switch to another while this waits its turn\n"
     "    const account = captureCallAccount(this.managers);\n"
     "    return this.callTransitions.run(async() => {\n"
     "      await this.discardCurrentCall(peerId, 'Live');\n"
     "      await this.watchLiveStream(peerId, account);\n"
     "    });\n"
     "  }\n"
     "\n"
     "  // * `callId`: the stream asked for, when only that one will do (see rtmpCallsController.joinCall)\n"
     "  private async watchLiveStream(peerId: PeerId, account: CallAccount, callId?: GroupCallId) {\n"
     "    try {\n"
     "      await rtmpCallsController.joinCall(peerId.toChatId(), account, callId);\n"
     "    } catch(err) {\n"
     "      console.error(err);\n"
     "      toastNew({\n"
     "        langPackKey: 'Error.AnError'\n"
     "      });\n"
     "      return;\n"
     "    }\n"
     "\n"
     "    try {\n"
     "      await openRtmpCallViewer(peerId);\n"
     "    } catch(err) {\n"
     "      this.log.error('opening RTMP viewer failed', err);\n"
     "      toastNew({langPackKey: 'Error.AnError'});\n"
     "    }\n"
     "  }\n",
     f"  // pluma: no RTMP streams {_ADR}: a stream's parts come from the server unencrypted, so\n"
     "  // none is watched and the call the user is in is not left for one. The server starts none and marks no\n"
     "  // call as one; the ways in went with IS_LIVE_STREAM_SUPPORTED.\n"
     "  public joinLiveStream(peerId: PeerId): Promise<void> {\n"
     "    toastNew({langPackKey: 'Error.AnError'});\n"
     "    return Promise.resolve();\n"
     "  }\n"),
    (IM_MANAGER,
     "import openRtmpCallViewer from '@lib/calls/openRtmpCallViewer';\n",
     ""),
    (JOIN_AS,
     "  const {account, peerId, hasCall} = options;\n"
     "  const {accountNumber, managers, myId} = account;\n",
     "  const {account, peerId} = options;\n"
     "  const {myId} = account;\n"),
    (JOIN_AS,
     "  let joinAs: GroupCallJoinAsOptions;\n"
     "  try {\n"
     "    joinAs = await managers.appGroupCallsManager.getGroupCallJoinAs(peerId);\n"
     "  } catch(err) {\n"
     "    // tdesktop requestList: a failed request joins as the account\n"
     "    console.error('group call join-as list failed', err);\n"
     "    return confirmed(myId);\n"
     "  }\n"
     "\n"
     "  if(!shouldAskGroupCallJoinAs(joinAs, myId, hasCall)) {\n"
     "    return confirmed(joinAs.peerIds.length ? joinAs.defaultPeerId : myId);\n"
     "  }\n"
     "\n"
     "  const isBroadcast = await managers.appChatsManager.isBroadcast(peerId.toChatId());\n"
     "  // * the peers to pick are the joining account's, whichever the tab went to while the list loaded\n"
     "  await showCallAccount(accountNumber);\n"
     "  const chosen = await pickGroupCallJoinAs({\n"
     "    joinAs,\n"
     "    selected: joinAs.defaultPeerId,\n"
     "    context: hasCall ? 'join' : 'create',\n"
     "    isBroadcast,\n"
     "    myId\n"
     "  });\n"
     "\n"
     "  if(chosen !== undefined) {\n"
     "    saveGroupCallJoinAs(managers, peerId, chosen, joinAs);\n"
     "  }\n"
     "\n"
     "  return chosen;\n"
     "}\n",
     f"  // pluma: every group call is end-to-end {_ADR}, and a member of its chain is a user: the\n"
     "  // account joins, nobody is asked who to be and no choice is saved for the chat.\n"
     "  return confirmed(myId);\n"
     "}\n"),
    (CALL_SETTINGS,
     "    const isVideoChat = !!groupCallInstance && !groupCallInstance.e2e;\n",
     "    const isVideoChat = !!groupCallInstance && !groupCallInstance.isConference;\n"),
    (CALL_SETTINGS,
     "      managers.appGroupCallsManager.getGroupCallJoinAs(chatId.toPeerId(true)).then(setJoinAsOptions, (err) => {\n"
     "        console.error('group call join-as list failed', err);\n"
     "      });\n",
     f"      // pluma: no \"Display me as...\": a group call is joined as the account {_ADR}.\n"),
    # The interface of a conference, which a chat's end-to-end call does not take.
    (GROUP_CALL_POPUP,
     "    if(!instance.e2e) {\n      updateCanInviteMembers();\n",
     "    if(!instance.isConference) {\n      updateCanInviteMembers();\n"),
    (GROUP_CALL_POPUP,
     "      if(instance.e2e) return {\n        addPeople: () => void onInviteClick('conference'),\n",
     "      if(instance.isConference) return {\n        addPeople: () => void onInviteClick('conference'),\n"),
    (GROUP_CALL_POPUP,
     "        const canManage = instance.e2e ? false :\n",
     "        const canManage = instance.isConference ? false :\n"),
    (GROUP_CALL_POPUP,
     "        const canManage = !instance.e2e &&\n",
     "        const canManage = !instance.isConference &&\n"),
    (GROUP_CALL_PARTICIPANTS,
     "  private async canManage() {\n    if(this.instance.e2e) {\n",
     "  private async canManage() {\n    if(this.instance.isConference) {\n"),
    (GROUP_CALL_PARTICIPANTS,
     "  private async canRemoveParticipant(peerId: PeerId) {\n    if(this.instance.e2e) {\n",
     "  private async canRemoveParticipant(peerId: PeerId) {\n    if(this.instance.isConference) {\n"),
    (GROUP_CALL_PARTICIPANTS,
     "    const isConference = !!instance.e2e;\n",
     "    const isConference = instance.isConference;\n"),
    (SHARE_INVITE,
     "    if(instance.e2e) {\n      // A conference link is handed over in the Call Link box",
     "    if(instance.isConference) {\n      // A conference link is handed over in the Call Link box"),
    # Leaving a chat's call for another asks about the chat's video chat, not about a conference.
    (IM_MANAGER,
     "    const fromType = currentCall.e2e ? 'Conference' : 'Voice';\n",
     f"    // pluma: a chat's video chat is end-to-end too {_ADR} and keeps its chat: only a conference\n"
     "    // is left as one\n"
     "    const fromType = currentCall.isConference ? 'Conference' : 'Voice';\n"),
    # No RTMP streams.
    (LIVE_STREAM_SUPPORT,
     "import Modes from '@config/modes';\n\nconst IS_LIVE_STREAM_SUPPORTED = 'serviceWorker' in navigator && !Modes.noServiceWorker;\n",
     f"// pluma: no RTMP streams {_ADR}: their parts come from the server unencrypted. Off, the\n"
     "// client offers to start none (\"Stream With...\" of the chat's menu), shows none to watch (the live plate, a\n"
     "// profile's action) and sets up no RTMP player (appDialogsManager).\n"
     "const IS_LIVE_STREAM_SUPPORTED = false;\n"),
    # No recording: the server does not serve phone.toggleGroupCallRecord. A chat's call has no recording entry in
    # Web K; the RTMP player's menu had the only ones.
    (RTMP_VIEWER,
     "          }, {\n"
     "            icon: 'radioon',\n"
     "            text: 'Rtmp.MediaViewer.Menu.StartRecording',\n"
     "            verify: () => getCall()?.admin && !getCall().call.pFlags.record_video_active,\n"
     "            onClick: () => showRtmpRecordPopup()\n"
     "          }, {\n"
     "            icon: 'radiooff',\n"
     "            text: 'Rtmp.MediaViewer.Menu.StopRecording',\n"
     "            verify: () => getCall()?.admin && getCall().call.pFlags.record_video_active,\n"
     "            onClick: () => {\n"
     "              const call = getCall();\n"
     "              if(!call) return;\n"
     "              this.managers.appGroupCallsManager.stopRecording(call.inputCall).catch(() => {\n"
     "                toastNew({\n"
     "                  langPackKey: 'Error.AnError'\n"
     "                });\n"
     "              });\n"
     "            }\n"
     "          }, {\n"
     "            icon: 'settings',\n",
     "          }, {\n"
     f"            // pluma: no recording, phone.toggleGroupCallRecord is not served {_ADR}\n"
     "            icon: 'settings',\n"),
    (RTMP_VIEWER, "import {showRtmpRecordPopup} from '@components/rtmp/recordPopup';\n", ""),
    # A join CONF_WRITE_CHAIN_INVALID refuses goes again on the last block: 10 refusals in a row count only when
    # the last block stayed the same, and while it moves the join goes on, for 100 attempts at most. The join
    # remembers the last block its own was built on (joinConferenceAttempt), the connection compares.
    (GROUP_CALLS,
     "    const initialOffsets: Partial<{0: number; 1: number}> = {};\n",
     "    const initialOffsets: Partial<{0: number; 1: number}> = {};\n"
     "    // pluma: the chain's last block the join's own block was built on, none on an empty chain: the\n"
     "    // connection tells by it a refusal of a chain that moves from one of a chain that stands (ADR 0060 §5\n"
     "    // of the server)\n"
     "    let joinChainHead: Uint8Array | undefined;\n"),
    (GROUP_CALLS,
     "      initialOffsets[0] = head.nextOffset;\n      return head.block ?\n",
     "      initialOffsets[0] = head.nextOffset;\n      joinChainHead = head.block;\n      return head.block ?\n"),
    (GROUP_CALLS,
     "      initialOffsets[0] = head.nextOffset;\n      if(!head.block) {\n",
     "      initialOffsets[0] = head.nextOffset;\n      joinChainHead = head.block;\n      if(!head.block) {\n"),
    (GROUP_CALLS,
     "        rebuildBlock: rebuildJoinBlock,\n",
     "        rebuildBlock: rebuildJoinBlock,\n        chainHead: () => joinChainHead,\n"),
    (GROUP_CALLS,
     "    rebuildBlock?: () => Promise<Uint8Array>;\n",
     "    rebuildBlock?: () => Promise<Uint8Array>;\n"
     "    // pluma: the chain's last block the join's block was built on, the one rebuildBlock read last\n"
     "    chainHead?: () => Uint8Array | undefined;\n"),
    (GROUP_CALLS,
     "          e2eRebuildBlock: opts.rebuildBlock,\n",
     "          e2eRebuildBlock: opts.rebuildBlock,\n          e2eChainHead: opts.chainHead,\n"),
    (GROUP_CALL_CONNECTION,
     "import forEachReverse from '@helpers/array/forEachReverse';\n",
     "import forEachReverse from '@helpers/array/forEachReverse';\nimport bytesCmp from '@helpers/bytes/bytesCmp';\n"),
    (GROUP_CALL_CONNECTION,
     "    e2eRebuildBlock?: () => Promise<Uint8Array>,\n",
     "    e2eRebuildBlock?: () => Promise<Uint8Array>,\n"
     "    // pluma: the chain's last block the join's block was built on, read again by e2eRebuildBlock; none on an\n"
     "    // empty chain. Whether it changed after a refusal decides whether the refusal counts (ADR 0060 §5 of the\n"
     "    // server).\n"
     "    e2eChainHead?: () => Uint8Array | undefined,\n"),
    (GROUP_CALL_CONNECTION,
     "        e2eRebuildBlock: undefined,\n        e2eCommitRebuiltBlock: undefined,\n",
     "        e2eRebuildBlock: undefined,\n        e2eChainHead: undefined,\n        e2eCommitRebuiltBlock: undefined,\n"),
    (GROUP_CALL_CONNECTION,
     "    this.options.e2eRebuildBlock = undefined;\n",
     "    this.options.e2eRebuildBlock = undefined;\n    this.options.e2eChainHead = undefined;\n"),
    (GROUP_CALL_CONNECTION,
     "    // only the `block` field changes per attempt. Caps at 5 retries to bound\n"
     "    // pathological loops; tdlib doesn't cap but we're conservative.\n",
     "    // only the `block` field changes per attempt; how many attempts, the rule\n"
     "    // below says (pluma).\n"),
    (GROUP_CALL_CONNECTION,
     "    const maxRetries = 5;\n",
     "    // pluma: CONF_WRITE_CHAIN_INVALID repeats the join on the last block (ADR 0060 §5 of the server). A refusal\n"
     "    // counts toward 10 in a row only when the last block read after it is the one the refused block was built\n"
     "    // on: the chain stands, so the refusal is no race. While the chain moves, as when every member joins again\n"
     "    // at once after a restart of the SFU and one join a round goes through, the join goes on, for 100 attempts\n"
     "    // at most. Then it is the join's error. A join without e2eChainHead cannot see the chain move, and each\n"
     "    // of its refusals counts.\n"
     "    const maxStillRefusals = 10;\n"
     "    const maxAttempts = 100;\n"
     "    const chainHead = options.type === 'main' ? options.e2eChainHead : undefined;\n"
     "    let stillRefusals = 0;\n"),
    (GROUP_CALL_CONNECTION,
     "        if(!isChainRace || attempt >= maxRetries - 1) throw err;\n"
     "        if(!rebuildBlock) throw err;\n"
     "        const newBlock = await rebuildBlock();\n",
     "        if(!isChainRace || attempt >= maxAttempts - 1) throw err;\n"
     "        if(!rebuildBlock) throw err;\n"
     "        const refusedOn = chainHead?.();\n"
     "        const newBlock = await rebuildBlock();\n"
     "        const builtOn = chainHead?.();\n"
     "        const chainMoved = builtOn !== undefined && (refusedOn === undefined || !bytesCmp(refusedOn, builtOn));\n"
     "        stillRefusals = chainMoved ? 0 : stillRefusals + 1;\n"
     "        if(stillRefusals >= maxStillRefusals) throw err;\n"),
)

# What the edits rely on and do not change: the end-to-end join of a conference by an inputGroupCall with a chat,
# the browser check, the string it shows, the words the report sorts decryption errors by and the frame format it
# reads epoch hashes from, the errors' codes, and the switch's users that hide the ways into a stream.
E2E_GROUP_CALL_RELIES_ON = (
    (GROUP_CALLS, "        chatId: opts.chatId,\n        muted: opts.muted,\n        joinVideo: opts.joinVideo,\n"
                  "        transitionGeneration: opts.transitionGeneration,\n", 1),
    (GROUP_CALLS, "        chatId: opts.chatId ?? NULL_PEER_ID,\n", 1),
    (GROUP_CALLS, "      instance.attachE2e(opts.worker, opts.selfUserId, opts.initialOffsets);\n", 1),
    (GROUP_CALLS, "      const placeholderId = (opts.input && opts.input._ === 'inputGroupCall') ?\n", 1),
    (CONFERENCE_SUPPORT, "const IS_CONFERENCE_CALL_SUPPORTED = IS_CONFERENCE_CALL_ENABLED && IS_RTC_SCRIPT_TRANSFORM_SUPPORTED;\n", 1),
    ("src/lang.ts", "  'ConferenceCall.Unsupported': 'Encrypted group calls are not supported in this browser. "
                    "Open this call in a supported Telegram app.',\n", 1),
    (IM_MANAGER, "import IS_CONFERENCE_CALL_SUPPORTED from '@environment/conferenceCallSupport';\n", 1),
    (E2E_CALL, "    throw new Error('decryptPacket: no matching active epoch');\n", 1),
    (E2E_CALL, "    if(seqno <= oldest) throw new Error(`replay: seqno ${seqno} older than window (max ${window.max})`);\n", 1),
    (E2E_CALL, "    if(window.seen.has(seqno)) throw new Error(`replay: seqno ${seqno} already seen`);\n", 1),
    (E2E_CALL, "  const unencryptedPrefixLength = trailerReader.uint32();\n", 1),
    (E2E_CALL, "  const epochsN = head & 0xff;\n", 1),
    (E2E_CALL, "    super(`${code}: ${message}`);\n", 1),
    (E2E_BLOCKCHAIN, "    super(`${code}: ${message}`);\n", 1),
    ("src/components/chat/topbar.ts", "        text: 'Rtmp.Topbar.StreamWith',\n", 1),
    ("src/components/chat/topbar.ts", "        verify: () => IS_LIVE_STREAM_SUPPORTED\n", 1),
    ("src/components/chat/topbarPlates.ts",
     "  const live = IS_LIVE_STREAM_SUPPORTED ? createChatLivePlate(topbar, chat, managers) : undefined;\n", 1),
    ("src/components/peerProfile.tsx", "    return !isRtmp() || IS_LIVE_STREAM_SUPPORTED;\n", 1),
    ("src/lib/appDialogsManager.ts", "    if(IS_LIVE_STREAM_SUPPORTED) rtmpCallsController.construct(managers);\n", 1),
    # The self-healing: an instance's reasons reach the controller's rejoin, which pauses and toasts with these.
    (GROUP_CALL, "  private requestConferenceRecovery(reason: string): void {\n", 1),
    (GROUP_CALL, "    this.dispatchEvent('conferenceRecoveryRequired', reason);\n", 1),
    (GROUP_CALLS, "      createdInstance.addEventListener('conferenceRecoveryRequired', (reason) => {\n"
                  "        void this.recoverConference(createdInstance, reason);\n", 1),
    (GROUP_CALLS, "import pause from '@helpers/schedulers/pause';\n", 1),
    (GROUP_CALLS, "import {toastNew} from '@components/toast';\n", 1),
    (GROUP_CALLS, "import {GroupCallId, GroupCallConnectionType} from '@appManagers/appGroupCallsManager';\n", 1),
    # What the report reads: the bytes of a frame, before the frame takes them, on both sides.
    (E2E_WORKER, "    const encrypted = new Uint8Array(frame.data);\n    let decrypted = await call.decrypt(", 1),
)

# The rejoins an instance asks for (requestConferenceRecovery, requestConferenceRecoveryForForbidden), sorted:
# the ones the encryption asks for, which the controller bounds (isE2eRejoinReason), and Web K's own watchdog of
# its pollers, which is a transport's matter. An upstream reason of its own is one to sort.
_REJOIN_REASON = re.compile(r"\brequestConferenceRecovery(?:ForForbidden)?\('([\w-]+)'")
E2E_REJOIN_REASONS = {"e2e-failure", "membership-lost", "chain-behind", "decrypt-stalled", "roster-forbidden",
                      "member-prune-forbidden", "chain-forbidden", "sync-refresh-forbidden", "broadcast-forbidden",
                      "source-resolution-forbidden"}
TRANSPORT_REJOIN_REASONS = {"sync-unrecoverable-locally"}

# Who reads which kind of call. A call's `.e2e` (its encryption worker; the instance's own `this.e2e` is its
# crypto) outside the worker's port: the emoji badge and the panel's class for it ask it (a chat's call shows
# them), the title asks it together with the chat (a chat's call is named by its chat), the status report's
# connection asks it, the sandbox's stories set it. `isConference` is the interface of a conference, `isE2e`
# the crypto's path. An upstream change to any of these counts is a new reader to sort.
_E2E_READ = re.compile(r"(?<![\w$])(?!this\??\.)[\w$]+\??\.e2e\b")
E2E_READS = {GROUP_CALL_POPUP: 2, "src/components/groupCall/title.ts": 1, GROUP_CALL_CONNECTION: 1,
             "src/components/popupSandbox/stories/calls.ts": 1}
_IS_CONFERENCE_READ = re.compile(r"\.isConference\b")
IS_CONFERENCE_READS = {GROUP_CALLS: 2, GROUP_CALL_CONNECTION: 1, GROUP_CALL_POPUP: 4, GROUP_CALL_PARTICIPANTS: 3,
                       SHARE_INVITE: 1, CALL_SETTINGS: 1, IM_MANAGER: 1}
_IS_E2E_READ = re.compile(r"\.isE2e\b")
IS_E2E_READS = {GROUP_CALLS: 3, GROUP_CALL: 1}
# The join-as list is asked by nothing; its maker stays for the manager's own sake.
_JOIN_AS_LIST = re.compile(r"\bgetGroupCallJoinAs\(")
JOIN_AS_LISTS = {"src/lib/appManagers/appGroupCallsManager.ts": 1}
# The RTMP player: made by openRtmpCallViewer only, which nothing calls, and the stream joined by that player
# only.
_RTMP_PLAYER = re.compile(r"\bopenRtmpCallViewer\(|\bnew AppMediaViewerRtmp\(|\brtmpCallsController\.joinCall\(")
RTMP_PLAYERS = {"src/lib/calls/openRtmpCallViewer.ts": 2, "src/components/mediaViewer/rtmp.ts": 1}
# Starting a stream: the chat's menu item, which IS_LIVE_STREAM_SUPPORTED hides, the player nothing opens, the
# sandbox's story, and the popup itself.
_RTMP_START = re.compile(r"\bshowRtmpStartStreamPopup\(")
RTMP_STARTS = {"src/components/chat/topbar.ts": 1, "src/components/mediaViewer/rtmp.ts": 1,
               "src/components/popupSandbox/stories/misc.ts": 1, "src/components/rtmp/adminPopup.tsx": 1}
# Starting or stopping a recording: the recording popup (made by showRtmpRecordPopup, which nothing calls) and its
# request; the manager's own methods are no calls.
_RECORDING = re.compile(r"\bshowRtmpRecordPopup\(|\.startRecording\(|\.stopRecording\(")
RECORDINGS = {"src/components/rtmp/recordPopup.tsx": 2}
# The recording entries' strings are in the strings alone.
_RECORDING_ENTRY = re.compile(r"""['"`]Rtmp\.MediaViewer\.Menu\.(?:Start|Stop)Recording['"`]""")
RECORDING_ENTRIES = {"src/lang.ts": 2}


def e2e_group_calls(tree):
    for rel, text, count in E2E_GROUP_CALL_RELIES_ON:
        tree.expect(rel, text, count)
    for rel, old, new in E2E_GROUP_CALL_EDITS:
        tree.replace(rel, old, new)


def verify_e2e_group_calls(sources):
    for rel, old, new in E2E_GROUP_CALL_EDITS:
        text = sources[rel]
        if (new and text.count(new) != 1) or old in (text.replace(new, "") if new else text):
            raise PatchError(f"{rel}: the edit of task 094 is not there")
    if "joinGroupCallInternal(" in _COMMENT.sub("", sources[GROUP_CALLS]).replace("private async joinGroupCallInternal(", ""):
        raise PatchError(f"{GROUP_CALLS}: a group call is joined without end-to-end encryption")
    reasons = set(_REJOIN_REASON.findall(_COMMENT.sub("", sources[GROUP_CALL])))
    if reasons != E2E_REJOIN_REASONS | TRANSPORT_REJOIN_REASONS:
        raise PatchError(f"{GROUP_CALL}: rejoins for {sorted(reasons ^ (E2E_REJOIN_REASONS | TRANSPORT_REJOIN_REASONS))}"
                         ", which the self-healing has not sorted")
    for reason in sorted(reasons):
        counted = reason in ("e2e-failure", "membership-lost", "chain-behind", "decrypt-stalled") or \
            reason.endswith("-forbidden")
        if counted != (reason in E2E_REJOIN_REASONS):
            raise PatchError(f"{GROUP_CALLS}: isE2eRejoinReason sorts the rejoin for {reason!r} wrongly")
    for pattern, expected, what in (
        (_E2E_READ, E2E_READS, "reads of a call's e2e worker"),
        (_IS_CONFERENCE_READ, IS_CONFERENCE_READS, "reads of isConference"),
        (_IS_E2E_READ, IS_E2E_READS, "reads of isE2e"),
        (_JOIN_AS_LIST, JOIN_AS_LISTS, "asks for the join-as list"),
        (_RTMP_PLAYER, RTMP_PLAYERS, "ways into the RTMP player"),
        (_RTMP_START, RTMP_STARTS, "ways to start an RTMP stream"),
        (_RECORDING, RECORDINGS, "ways to record a call"),
        (_RECORDING_ENTRY, RECORDING_ENTRIES, "recording entries"),
    ):
        for rel, text in sources.items():
            if pattern is _E2E_READ and rel.startswith("src/lib/calls/e2e/"):
                continue
            found = len(pattern.findall(_COMMENT.sub("", text)))
            if found != expected.get(rel, 0):
                raise PatchError(f"{rel}: {found} {what}, expected {expected.get(rel, 0)}; is every group call "
                                 "still end-to-end, joined as the account, with no RTMP stream and no recording?")


# --- the colours of calls ---------------------------------------------------------
#
# The owner's decision of 2026-11-12 (variant A, "Шалфей"): calls are drawn in the sage palette of the rebranding
# (task 017 of the server), not in Telegram's colours. Telegram iOS draws a call's background as three
# four-point gradients (CallBackgroundLayer.swift:108-124 at the pinned iOS), which Web K's call screen copies
# (components/call/index.tsx GRADIENT_COLORS): connecting 568FD6 626ED5 A667D5 7664DA, connected ACBD65 459F8D
# 53A4D1 3E917A, weak signal C0508D F09536 CE5081 FC7C4C. Pluma's, the points in the same order:
CALL_BACKGROUNDS = {
    "connecting": ("3a4a3c", "4f6e52", "2c3a2d", "5b7a5e"),
    "active": ("5b7a5e", "6f8f72", "4f6e52", "7fa082"),
    "weak": ("8a5a44", "a86b4c", "7a4e3b", "b97a55"),
}
# The other colours of calls are mapped by meaning onto those sets: Telegram's blue and purple (muted, waiting,
# a raised hand, connecting) onto the connecting one, green (speaking, unmuted) onto the connected one, red and
# orange (muted by an admin) onto the weak one, and the text of a state onto the palette's accents on a dark
# ground (#9DBB9F the accent, #7FA082 the soft one). The group call's screen is always dark; the call's plate
# over a chat keeps white text on its gradient. The buttons that end, decline or leave a call stay red and the
# one that answers it green, as in Telegram's other clients (the owner's decision of 2026-11-13; CALL_BUTTONS
# below). Web K defines them in:
#   - components/call/index.tsx: the 1:1 call's backgrounds;
#   - scss/base.scss: the group call's --gc-* colours, which its stylesheets, the participants' and the
#     microphone's lottie colours (groupCall/index.tsx getColorByMutedState), the avatars' waves (avatarBlobs.ts)
#     and the microphone's gradients and waves (microphoneBlobs.ts) all read;
#   - scss/partials/popups/_groupCall.scss and _call.scss: the call's screens, the only places that take the
#     state texts in the sage palette (CALL_TEXT_SCOPES below);
#   - scss/partials/_chatPinned.scss: the call's plate over a chat (.pinned-call), its gradients per state and its
#     microphone button;
#   - components/topbarWeave.ts: the plate's former canvas gradients, unused but kept in step;
#   - components/popupSandbox/stories/calls.ts: the fake camera of the development sandbox's call stories.
CALL_COLORS = "src/components/call/index.tsx"
CALL_POPUP = "src/scss/partials/popups/_call.scss"
CALL_PLATE = "src/scss/partials/_chatPinned.scss"
CALL_WEAVE = "src/components/topbarWeave.ts"
CALL_SANDBOX = "src/components/popupSandbox/stories/calls.ts"
_SAGE = "(task 017 of the server)"
# The group call's state texts (--gc-green/blue/red-text-color) are also read outside calls: by polls, a right
# and a wrong answer (chat/bubbleParts/pollMessageContent/styles.module.scss 280-349), and by the markup's diff
# (scss/partials/_markup.scss 110, 115). The root keeps Telegram's (base.scss 300-302); the sage ones are
# --gc-call-*-text-color, which the screens of the group call (.popup-group-call, groupCall/index.tsx 845) and
# of a 1:1 call (.popup-call, call/index.tsx 829) take as their --gc-*-text-color.
CALL_TEXT_OUTSIDE = ("  --gc-green-text-color: #5CC85E;\n"
                     "  --gc-blue-text-color: #3390ec;\n"
                     "  --gc-red-text-color: #ff595a;\n")
_CALL_TEXT_SCOPE = ("  // pluma: the call's state texts are the sage ones (base.scss --gc-call-*) inside its screen only;\n"
                    "  // polls and the markup's diff read the root's, which keep Telegram's\n"
                    "  --gc-green-text-color: var(--gc-call-green-text-color);\n"
                    "  --gc-blue-text-color: var(--gc-call-blue-text-color);\n"
                    "  --gc-red-text-color: var(--gc-call-red-text-color);\n")
CALL_TEXT_SCOPES = tuple((rel, head + "\n" + tail, head + "\n" + _CALL_TEXT_SCOPE + "\n" + tail)
                         for rel, head, tail in (
    ("src/scss/partials/popups/_groupCall.scss", '.popup-group-call {\n  $parent: ".popup";\n',
     "  // A panel, not a sheet:"),
    (CALL_POPUP, '.popup-call {\n  $parent: ".popup";\n', "  #{$parent} {\n"),
))
_CALL_TEXT_SET = re.compile(r"--gc-(?:green|blue|red)-text-color\s*:")

CALL_COLOR_EDITS = (
    (CALL_COLORS,
     "const GRADIENT_COLORS = {\n"
     "  connecting: '568fd6,626ed5,a667d5,7664da',\n"
     "  active:     'acbd65,459f8d,53a4d1,3e917a',\n"
     "  weak:       'c0508d,f09536,ce5081,fc7c4c'\n"
     "};\n",
     "// pluma: the same gradients in the sage palette, the points in the same order (task 017 of the server; the\n"
     "// owner's decision of 2026-11-12).\n"
     "const GRADIENT_COLORS = {\n"
     + "".join(f"  {state}:{' ' * (11 - len(state))}'{','.join(colors)}'{',' if state != 'weak' else ''}\n"
               for state, colors in CALL_BACKGROUNDS.items())
     + "};\n"),
    ("src/scss/base.scss",
     "  --gc-button-leave-color: rgba(100, 50, 50, .92);\n"
     "  --gc-button-unmuted-color: rgba(27, 66, 42, .92);\n"
     "  --gc-button-muted-color: rgba(38, 53, 76, .92);\n"
     "  --gc-button-hand-color: rgba(71, 40, 63, .92);\n"
     "  --gc-button-unmuted-fill-color: #195530;\n"
     "  --gc-button-muted-fill-color: #3C87F7;\n"
     "  --gc-green-color: #195530;\n"
     "  --gc-blue-color: #3C87F7;\n"
     "  --gc-red-color: #643333;\n"
     "\n"
     "  --gc-primary-text-color: #fff;\n"
     "  --gc-secondary-text-color: #aaaaaa;\n"
     "  --gc-green-text-color: #5CC85E;\n"
     "  --gc-blue-text-color: #3390ec;\n"
     "  --gc-red-text-color: #ff595a;\n",
     f"  // pluma: the call's colours in the sage palette {_SAGE}: red the\n"
     "  // weak signal's, unmuted and green the connected call's, muted, a raised hand and blue the connecting\n"
     "  // call's; Leave keeps Telegram's red\n"
     "  --gc-button-leave-color: rgba(100, 50, 50, .92);\n"
     "  --gc-button-unmuted-color: rgba(79, 110, 82, .92);\n"
     "  --gc-button-muted-color: rgba(44, 58, 45, .92);\n"
     "  --gc-button-hand-color: rgba(58, 74, 60, .92);\n"
     "  --gc-button-unmuted-fill-color: #4F6E52;\n"
     "  --gc-button-muted-fill-color: #5B7A5E;\n"
     "  --gc-green-color: #4F6E52;\n"
     "  --gc-blue-color: #5B7A5E;\n"
     "  --gc-red-color: #7A4E3B;\n"
     "\n"
     "  --gc-primary-text-color: #fff;\n"
     "  --gc-secondary-text-color: #aaaaaa;\n"
     "  // pluma: polls and the markup's diff read these too, so they keep Telegram's; the call's screens take\n"
     "  // the sage ones below instead (CALL_TEXT_SCOPES)\n"
     + CALL_TEXT_OUTSIDE +
     "  // pluma: the call's state texts in the sage palette: speaking the accent, waiting the soft accent of the\n"
     "  // dark theme, muted by an admin the weak signal's\n"
     "  --gc-call-green-text-color: #9DBB9F;\n"
     "  --gc-call-blue-text-color: #7FA082;\n"
     "  --gc-call-red-text-color: #B97A55;\n"),
    *CALL_TEXT_SCOPES,
    # The participants' and the microphone's lottie colours read the root's custom properties
    # (helpers/dom/customProperties.ts reads getComputedStyle(document.documentElement)), not the call's screen.
    (GROUP_CALL_POPUP,
     "  const propertyValue = customProperties.getProperty('gc-' + colorStr + '-text-color');\n",
     "  // pluma: the state colours of the call are the sage ones (base.scss --gc-call-*); the root's\n"
     "  // --gc-*-text-color keep Telegram's for polls and the markup's diff\n"
     "  const prefix = colorStr === 'secondary' ? 'gc-' : 'gc-call-';\n"
     "  const propertyValue = customProperties.getProperty(prefix + colorStr + '-text-color');\n"),
    ("src/scss/base.scss",
     "  --gc-microphone-unmuted-from: #00A3B4;\n"
     "  --gc-microphone-unmuted-to: #00CB47;\n"
     "  --gc-microphone-muted-from: #4EABF8;\n"
     "  --gc-microphone-muted-to: #3478F6;\n"
     "  --gc-microphone-hand-from: #DF44B8;\n"
     "  --gc-microphone-hand-to: #3851EB;\n",
     "  // pluma: unmuted the connected call's sage, muted and a raised hand the connecting call's (task 017 of the\n"
     "  // server)\n"
     "  --gc-microphone-unmuted-from: #5B7A5E;\n"
     "  --gc-microphone-unmuted-to: #7FA082;\n"
     "  --gc-microphone-muted-from: #4F6E52;\n"
     "  --gc-microphone-muted-to: #3A4A3C;\n"
     "  --gc-microphone-hand-from: #5B7A5E;\n"
     "  --gc-microphone-hand-to: #2C3A2D;\n"),
    (CALL_PLATE,
     "  initial-value: #0976E3;\n}\n\n@property --pc-c2 {\n  syntax: '<color>';\n  inherits: false;\n"
     "  initial-value: #2BCEFF;\n}\n\n@property --pc-c3 {\n  syntax: '<color>';\n  inherits: false;\n"
     "  initial-value: #2BCEFF;\n}\n",
     "  initial-value: #2C3A2D; // pluma: the muted plate's sage\n}\n\n@property --pc-c2 {\n  syntax: '<color>';\n"
     "  inherits: false;\n  initial-value: #4F6E52;\n}\n\n@property --pc-c3 {\n  syntax: '<color>';\n  inherits: false;\n"
     "  initial-value: #4F6E52;\n}\n"),
    (CALL_PLATE,
     "      // Default (no state class yet) — blue, same as `.is-muted`.\n"
     "      --pc-c1: #0976E3;\n      --pc-c2: #2BCEFF;\n      --pc-c3: #2BCEFF;\n",
     "      // Default (no state class yet) — same as `.is-muted`.\n"
     "      --pc-c1: #2C3A2D;\n      --pc-c2: #4F6E52;\n      --pc-c3: #4F6E52;\n"),
    (CALL_PLATE,
     "  &.is-unmuted .topbar-call-center {\n    --pc-c1: #52CE5D;\n    --pc-c2: #00B1C0;\n    --pc-c3: #00B1C0;\n  }\n"
     "\n"
     "  &.is-muted .topbar-call-center {\n    --pc-c1: #0976E3;\n    --pc-c2: #2BCEFF;\n    --pc-c3: #2BCEFF;\n  }\n"
     "\n"
     "  &.is-muted-by-admin .topbar-call-center {\n    --pc-c1: #F05459;\n    --pc-c2: #766EE9;\n    --pc-c3: #57A4FE;\n"
     "  }\n"
     "\n"
     "  &.is-rtmp .topbar-call-center {\n    --pc-c1: #4588E3;\n    --pc-c2: #976FFF;\n    --pc-c3: #E46ACE;\n  }\n"
     "\n"
     "  &.is-connecting .topbar-call-center {\n    --pc-c1: #8599aa;\n    --pc-c2: #8599aa;\n    --pc-c3: #8599aa;\n"
     "  }\n"
     "\n"
     "  // Mic button color: green when actively unmuted, primary otherwise.\n"
     "  &.is-unmuted .topbar-call-mic-btn {\n    background-color: #54B655;\n\n    @include hover() {\n"
     "      background-color: #4D9F4C !important;\n    }\n  }\n",
     f"  // pluma: the plate's states in the sage palette {_SAGE}: unmuted the\n"
     "  // connected call's, muted, a stream and connecting the connecting call's, muted by an admin the weak signal's\n"
     "  &.is-unmuted .topbar-call-center {\n    --pc-c1: #5B7A5E;\n    --pc-c2: #6F8F72;\n    --pc-c3: #6F8F72;\n  }\n"
     "\n"
     "  &.is-muted .topbar-call-center {\n    --pc-c1: #2C3A2D;\n    --pc-c2: #4F6E52;\n    --pc-c3: #4F6E52;\n  }\n"
     "\n"
     "  &.is-muted-by-admin .topbar-call-center {\n    --pc-c1: #8A5A44;\n    --pc-c2: #A86B4C;\n    --pc-c3: #7A4E3B;\n"
     "  }\n"
     "\n"
     "  &.is-rtmp .topbar-call-center {\n    --pc-c1: #3A4A3C;\n    --pc-c2: #5B7A5E;\n    --pc-c3: #4F6E52;\n  }\n"
     "\n"
     "  &.is-connecting .topbar-call-center {\n    --pc-c1: #3A4A3C;\n    --pc-c2: #3A4A3C;\n    --pc-c3: #3A4A3C;\n"
     "  }\n"
     "\n"
     "  // Mic button color: the connected call's sage when actively unmuted, primary otherwise.\n"
     "  &.is-unmuted .topbar-call-mic-btn {\n    background-color: #6F8F72;\n\n    @include hover() {\n"
     "      background-color: #5B7A5E !important;\n    }\n  }\n"),
    (CALL_WEAVE,
     "    const MUTED_BY_ADMIN_STOPS: ColorStops = [[0, '#F05459'], [.4, '#766EE9'], [1, '#57A4FE']];\n"
     "    const UNMUTED_STOPS: ColorStops = [[0, '#52CE5D'], [1, '#00B1C0']];\n"
     "    const MUTED_STOPS: ColorStops = [[0, '#0976E3'], [1, '#2BCEFF']];\n"
     "    const CONNECTING_STOPS: ColorStops = [[0, '#8599aa'], [1, '#8599aa']];\n"
     "    const RTMP_STOPS: ColorStops = [[0, '#4588E3'], [.5, '#976FFF'], [1, '#E46ACE']];\n",
     f"    // pluma: the plate's colours in the sage palette {_SAGE}, as\n"
     "    // .pinned-call has them\n"
     "    const MUTED_BY_ADMIN_STOPS: ColorStops = [[0, '#8A5A44'], [.4, '#A86B4C'], [1, '#7A4E3B']];\n"
     "    const UNMUTED_STOPS: ColorStops = [[0, '#5B7A5E'], [1, '#6F8F72']];\n"
     "    const MUTED_STOPS: ColorStops = [[0, '#2C3A2D'], [1, '#4F6E52']];\n"
     "    const CONNECTING_STOPS: ColorStops = [[0, '#3A4A3C'], [1, '#3A4A3C']];\n"
     "    const RTMP_STOPS: ColorStops = [[0, '#3A4A3C'], [.5, '#5B7A5E'], [1, '#4F6E52']];\n"),
    # Accept of a 1:1 call (call/index.tsx 569-573, CallButton color="green"; _call.scss 348-350) read the
    # group call's speaking green, which is sage now; it keeps Telegram's. Decline and End take the theme's
    # danger colour (_call.scss 344-346) and stay as they are.
    (CALL_POPUP,
     "    &-green {\n"
     "      background-color: var(--gc-green-text-color) !important;\n"
     "    }\n",
     "    // pluma: Accept keeps Telegram's green; --gc-green-text-color, speaking, is the palette's\n"
     "    &-green {\n"
     "      background-color: #5CC85E !important;\n"
     "    }\n"),
    (CALL_SANDBOX,
     "    gradient.addColorStop(0, '#3e917a');\n"
     "    gradient.addColorStop(0.5, '#53a4d1');\n"
     "    gradient.addColorStop(1, '#a667d5');\n",
     f"    // pluma: the call's colours in the sage palette {_SAGE}\n"
     "    gradient.addColorStop(0, '#4f6e52');\n"
     "    gradient.addColorStop(0.5, '#7fa082');\n"
     "    gradient.addColorStop(1, '#3a4a3c');\n"),
)

# Telegram's colours of calls, as the places above had them. Most are found nowhere else in the client and must
# be gone from every source; a few are also colours of something else (the accent, the danger and green of a
# theme, Premium's gradient, a sticker's outline) and must be gone from the call's own files, from the --gc-*
# colours and from the call's plate.
TELEGRAM_CALL_COLORS = (
    "568fd6", "626ed5", "a667d5", "7664da", "acbd65", "459f8d", "53a4d1", "3e917a", "c0508d", "f09536", "ce5081",
    "fc7c4c", "195530", "3c87f7", "643333", "00a3b4", "00cb47", "4eabf8", "3478f6", "df44b8", "3851eb", "0976e3",
    "2bceff", "52ce5d", "00b1c0", "f05459", "766ee9", "57a4fe", "8599aa", "54b655", "4d9f4c",
)
TELEGRAM_CALL_COLORS_SHARED = ("5cc85e", "3390ec", "ff595a", "4588e3", "976fff", "e46ace")
TELEGRAM_CALL_TINTS = ("100, 50, 50", "27, 66, 42", "38, 53, 76", "71, 40, 63")
# The buttons that keep Telegram's colours, each exactly as the edits above leave it and only there: Leave of a
# group call (groupCall/index.tsx 664-668 makes it .group-call-button-red, _groupCall.scss 139-141 paints it
# with --gc-button-leave-color) and Accept of a 1:1 call.
CALL_BUTTONS = (
    ("src/scss/base.scss", "  --gc-button-leave-color: rgba(100, 50, 50, .92);\n"),
    (CALL_POPUP, "    &-green {\n      background-color: #5CC85E !important;\n    }\n"),
)
_TELEGRAM_CALL_COLOR = re.compile(r"(?<![0-9A-Fa-f])(?:" + "|".join(TELEGRAM_CALL_COLORS) + r")(?![0-9A-Fa-f])"
                                  r"|rgba?\((?:" + "|".join(TELEGRAM_CALL_TINTS) + r"),", re.IGNORECASE)
_TELEGRAM_CALL_COLOR_SHARED = re.compile(r"(?<![0-9A-Fa-f])(?:" + "|".join(TELEGRAM_CALL_COLORS_SHARED) +
                                         r")(?![0-9A-Fa-f])", re.IGNORECASE)
# The call's own files: the screens of 1:1 and group calls, conferences, the plate and its parts.
_CALL_UI = re.compile(r"^src/(?:components/(?:call|groupCall|conferenceCall)/|components/(?:topbarCall\.tsx|"
                      r"topbarWeave\.ts|groupCallActiveIcon\.ts)$|components/popupSandbox/stories/calls\.ts$|"
                      r"scss/partials/popups/_(?:call|groupCall|conferenceCall)\.scss$|scss/partials/_chatPinned\.scss$)")


def call_colors(tree):
    for rel, old, new in CALL_COLOR_EDITS:
        tree.replace(rel, old, new)


def verify_call_colors(sources):
    for rel, button in CALL_BUTTONS:
        if sources[rel].count(button) != 1:
            raise PatchError(f"{rel}: a call's button does not keep Telegram's colour")
    if sources["src/scss/base.scss"].count(CALL_TEXT_OUTSIDE) != 1:
        raise PatchError("src/scss/base.scss: the root's --gc-*-text-color, which polls and the markup read, do not "
                         "keep Telegram's colours")
    for rel, old, new in CALL_COLOR_EDITS:
        if sources[rel].count(new) != 1 or old in sources[rel]:
            raise PatchError(f"{rel}: the call is not in the sage palette")
    for rel, text in sources.items():
        for r, kept in CALL_BUTTONS + (("src/scss/base.scss", CALL_TEXT_OUTSIDE),):
            if r == rel:
                text = text.replace(kept, "")
        for r, _, scope in CALL_TEXT_SCOPES:
            if r == rel:
                text = text.replace(scope, "")
        if _CALL_TEXT_SET.search(text) or ("gc-call-" in text and not _CALL_UI.match(rel)
                                           and rel != "src/scss/base.scss"):
            raise PatchError(f"{rel}: the call's state texts are set or read outside a call's screen; polls and "
                             "the markup keep Telegram's colours")
        m = _TELEGRAM_CALL_COLOR.search(text)
        if not m and _CALL_UI.match(rel):
            m = _TELEGRAM_CALL_COLOR_SHARED.search(text)
        if not m and rel == "src/scss/base.scss":
            m = _TELEGRAM_CALL_COLOR_SHARED.search("".join(re.findall(r"^\s*--gc-[^\n]*\n", text, re.MULTILINE)))
        if m:
            raise PatchError(f"{rel}: Telegram's call colour {m.group()!r} is still there; a call is drawn in the "
                             "sage palette")


# --- the screens of the login code ----------------------------------------------
#
# Task 076 (ADR 0044): the server sends the code to the person's other Pluma
# session (auth.sentCodeTypeApp) or to their own Telegram, in a message from
# Pluma's account there (auth.sentCodeTypeFragmentSms, its url the chat with
# that account); a code that did not reach Telegram comes as
# auth.sentCodeTypeSms, and the administrator issues it. Pluma sends no SMS: a
# next_type of SMS is "Didn't get the code?" (App, FragmentSms) and "Send
# again" after a countdown (Sms), both auth.resendCode on the same card, which
# applies the new sentCode in place (AuthCodeCard.tsx applyNewSentCode). The
# Fragment and SMS screens get Pluma's texts and the card's filled button
# (wordSubmit) under the code: "Open Telegram" opens the chat, "Open Telegram
# settings" the privacy setting that lets the account find the person by their
# number (tg://settings/phone_privacy: Android LaunchActivity.java:2654, iOS
# OpenUrl.swift:1025, tdesktop deep_links/deep_links_settings.cpp). A browser
# cannot tell whether an app takes tg://, so the buttons always show (the first
# one only with a chat to open). Fragment's sticker (jolly_roger) gives way to
# the tracking monkey of the other codes; the screen of a code that did not
# reach Telegram has Utya searching (UtyanSearch). With no next_type the row
# is hidden, as upstream has it (updateResend).
#
# auth.resendCode can also fail in ways upstream's card takes for "An error
# occurred" with the link offered again at once. PHONE_CODE_EXPIRED goes back
# to the number, as the pencil does; SEND_CODE_UNAVAILABLE (no further try
# through Telegram) is the administrator's code: an alert says so and the row
# goes, as with no next_type; a flood wait is the card's own "Too many
# attempts" line, and the countdown runs to its end before the link is back.
# A resend answer that comes after the card has gone is dropped, as its error
# already was: applied, it would store the code card's state again and start
# a countdown nothing stops.

AUTH_CODE = "src/pages/cards/AuthCodeCard.tsx"
SENT_CODE = "src/pages/sentCode.ts"
LANG_SIGN = "src/langSign.ts"

# The English strings, as langSign.ts has them; other languages come from the
# server's language pack. "Telegram" in them is the real Telegram: they are
# added after the rename (rebrand), and verify knows them.
LOGIN_CODE_STRINGS = (
    ("Pluma.Code.SentTelegram",
     "**Check Telegram**\\nWe\\'ve sent the code for **%s** to your Telegram, in a message from the Pluma account."),
    ("Pluma.Code.OpenTelegram", "Open Telegram"),
    ("Pluma.Code.NotReceived", "[Didn\\'t get the code?]()"),
    ("Pluma.Code.NotDelivered",
     "**Code didn\\'t reach Telegram**\\nThe code for **%s** didn\\'t reach your Telegram. Let Telegram find you by "
     "your number: **Settings → Privacy and Security → Phone Number → Who can find me by my number? → Everybody**."
     "\\n\\nNo Telegram? Ask the administrator for the code and enter it here."),
    ("Pluma.Code.OpenTelegramSettings", "Open Telegram settings"),
    ("Pluma.Code.SendAgainIn", "Send again in %s"),
    ("Pluma.Code.SendAgain", "[Send again]()"),
    ("Pluma.Code.Sending", "Sending…"),
    ("Pluma.Code.AskAdministrator", "Ask the administrator"),
    ("Pluma.Code.AskAdministratorText", "Ask the Pluma administrator for your code and enter it here."),
)
LOGIN_CODE_STRING_LINES = tuple(f"  '{key}': '{value}'," for key, value in LOGIN_CODE_STRINGS)

# The links of the real Telegram app that the card gives to the system: the
# only tg: links of the client (verify), each once.
TELEGRAM_APP_LINKS = (
    (AUTH_CODE, "/^tg:\\/\\/resolve\\?domain=\\w+$/"),
    (AUTH_CODE, "'tg://settings/phone_privacy'"),
)

_RESENDING = "  'Login.Code.Resending': 'Requesting a new code...',\n"

LOGIN_CODE_EDITS = (
    (LANG_SIGN, _RESENDING, _RESENDING + "".join(line + "\n" for line in LOGIN_CODE_STRING_LINES)),
    (SENT_CODE,
     "  if(sentCode.next_type?._ === 'auth.codeTypeFragmentSms') return 0;\n"
     "  return sentCode.timeout || 0;\n"
     "}\n",
     "  if(sentCode.next_type?._ === 'auth.codeTypeFragmentSms') return 0;\n"
     "  return sentCode.timeout || 0;\n"
     "}\n"
     "\n"
     "/**\n"
     " * pluma: the resend row of the screens of a code sent through Telegram. Pluma sends no SMS: from a\n"
     " * code in the app or in Telegram a next type of SMS is \"Didn't get the code?\", which leads to the\n"
     " * screen of a code that did not reach Telegram (`auth.sentCodeTypeSms`), and there it is \"Send\n"
     " * again\", another try through Telegram. Undefined where upstream's labels stay.\n"
     " */\n"
     "export function getPlumaResendLangKeys(sentCode: SentCode): PlumaResendLangKeys | undefined {\n"
     "  if(sentCode.next_type?._ !== 'auth.codeTypeSms') return undefined;\n"
     "  switch(sentCode.type._) {\n"
     "    case 'auth.sentCodeTypeApp':\n"
     "    case 'auth.sentCodeTypeFragmentSms':\n"
     "      return {link: 'Pluma.Code.NotReceived', pending: 'Pluma.Code.SendAgainIn', sending: 'Pluma.Code.Sending'};\n"
     "    case 'auth.sentCodeTypeSms':\n"
     "      return {link: 'Pluma.Code.SendAgain', pending: 'Pluma.Code.SendAgainIn', sending: 'Pluma.Code.Sending'};\n"
     "    default:\n"
     "      return undefined;\n"
     "  }\n"
     "}\n"
     "\n"
     "/** pluma: the link once the countdown is over, the countdown, and the line while the request runs. */\n"
     "export type PlumaResendLangKeys = {link: LangPackKey, pending: LangPackKey, sending: LangPackKey};\n"),
    ("src/global.d.ts",
     "    | 'PHONE_CODE_INVALID'\n    | 'WIDGET_RESPONSE_TIMEOUT'\n",
     "    | 'PHONE_CODE_INVALID'\n"
     "    // pluma: auth.resendCode when no other way to send the code is left\n"
     "    | 'SEND_CODE_UNAVAILABLE'\n"
     "    | 'WIDGET_RESPONSE_TIMEOUT'\n"),
    (AUTH_CODE, "import simpleConfirmation from '@components/popups/simpleConfirmation';\n",
     "import simpleConfirmation, {showSimpleConfirmationPopup} from '@components/popups/simpleConfirmation';\n"),
    (AUTH_CODE, "  getCodeLength,\n  getResendLangKey,\n",
     "  getCodeLength,\n  getPlumaResendLangKeys,\n  getResendLangKey,\n"),
    (AUTH_CODE, "type Spec = Extract<CardSpec, {name: 'authCode'}>;\n",
     "type Spec = Extract<CardSpec, {name: 'authCode'}>;\n"
     "\n"
     "// pluma: links of the real Telegram app, not Pluma's (plm://), that the screens of a code sent\n"
     "// through Telegram give to the system: the chat with the account that wrote the code\n"
     "// (`auth.sentCodeTypeFragmentSms.url`), and the privacy setting that lets the account find the person\n"
     "// by their number (Android LaunchActivity, iOS OpenUrl, tdesktop deep_links_settings)\n"
     f"const TELEGRAM_CHAT_LINK = {TELEGRAM_APP_LINKS[0][1]};\n"
     f"const TELEGRAM_PHONE_PRIVACY_LINK = {TELEGRAM_APP_LINKS[1][1]};\n"
     "\n"
     "/**\n"
     " * pluma: gives a link of the real Telegram app to the system, as tweb gives it a tg:// link it cannot\n"
     " * open itself (confirmOpenUrl). A browser cannot tell whether an app takes the scheme, so the buttons\n"
     " * are always there, and the text says where to go without them.\n"
     " */\n"
     "function openTelegramLink(url: string) {\n"
     "  const a = document.createElement('a');\n"
     "  a.href = url;\n"
     "  a.click();\n"
     "}\n"),
    (AUTH_CODE, "  const [errorContent, setErrorContent] = createSignal<JSX.Element>();\n",
     "  const [errorContent, setErrorContent] = createSignal<JSX.Element>();\n"
     "  // pluma: the filled button of the screens of a code sent through Telegram\n"
     "  const [telegramButton, setTelegramButton] = createSignal<{url: string, text: LangPackKey}>();\n"),
    (AUTH_CODE,
     "    if(sentCode.type._ === 'auth.sentCodeTypeFragmentSms') {\n",
     "    // pluma: Utya searching on the screen of a code that did not reach Telegram; a code in\n"
     "    // Telegram (Fragment's type) has the monkey of the other codes, not Fragment's sticker\n"
     "    if(sentCode.type._ === 'auth.sentCodeTypeSms') {\n"),
    (AUTH_CODE, "      }, 'jolly_roger').then((animation) => {\n", "      }, 'UtyanSearch').then((animation) => {\n"),
    (AUTH_CODE,
     "    const key = getResendLangKey(sentCode.next_type);\n",
     "    // pluma: the labels of the screens of a code sent through Telegram\n"
     "    const pluma = getPlumaResendLangKeys(sentCode);\n"
     "    const key = pluma?.link ?? getResendLangKey(sentCode.next_type);\n"),
    (AUTH_CODE,
     "      setResendContent(i18n(getResendPendingLangKey(sentCode.next_type), [toHHMMSS(diff)]));\n",
     "      setResendContent(i18n(pluma?.pending ?? getResendPendingLangKey(sentCode.next_type), [toHHMMSS(diff)]));\n"),
    (AUTH_CODE,
     "  function resendCode() {\n    if(resending) return;\n",
     "  /**\n"
     "   * pluma: the errors of a resend that are not a failure to report. An expired code goes back to the\n"
     "   * number, as the pencil does; with no further try through Telegram the code is the administrator's,\n"
     "   * and the row goes, as with no next type; a flood wait is the card's line for it, and the countdown\n"
     "   * runs to its end before the link is offered again. Returns whether the error was one of them.\n"
     "   */\n"
     "  function handlePlumaResendError(err: ApiError) {\n"
     "    if(err.type === 'PHONE_CODE_EXPIRED') {\n"
     "      toastNew({langPackKey: 'PHONE_CODE_EXPIRED'});\n"
     "      navigate({name: 'signIn'});\n"
     "      return true;\n"
     "    }\n"
     "\n"
     "    if(err.type === 'SEND_CODE_UNAVAILABLE') {\n"
     "      sentCode = {...sentCode, next_type: undefined};\n"
     "      persistSentCode();\n"
     "      updateResend();\n"
     "      showSimpleConfirmationPopup({\n"
     "        titleLangKey: 'Pluma.Code.AskAdministrator',\n"
     "        descriptionLangKey: 'Pluma.Code.AskAdministratorText',\n"
     "        buttons: [{langKey: 'OK'}]\n"
     "      });\n"
     "      return true;\n"
     "    }\n"
     "\n"
     "    const floodWait = getFloodWaitTime(err);\n"
     "    if(floodWait.hasWaitTime) {\n"
     "      sentCode.resend_deadline = tsNow(true) + floodWait.waitTime;\n"
     "      persistSentCode();\n"
     "      setErrorContent(i18n('Login.Code.TooManyAttempts', [wrapFormattedDuration(formatDuration(floodWait.waitTime))]));\n"
     "      updateResend();\n"
     "      return true;\n"
     "    }\n"
     "\n"
     "    return false;\n"
     "  }\n"
     "\n"
     "  function resendCode() {\n    if(resending) return;\n"),
    (AUTH_CODE,
     "      resending = false;\n\n      return continueLogin(code, {\n",
     "      resending = false;\n"
     "      // pluma: an answer that comes after the card has gone is dropped, as its error is: applied, it\n"
     "      // would store the code card's state again and start a countdown that nothing stops\n"
     "      if(isGone()) {\n"
     "        return;\n"
     "      }\n"
     "\n"
     "      return continueLogin(code, {\n"),
    (AUTH_CODE,
     "      console.error('auth.resendCode error:', err);\n",
     "      if(handlePlumaResendError(err)) {\n"
     "        return;\n"
     "      }\n"
     "\n"
     "      console.error('auth.resendCode error:', err);\n"),
    (AUTH_CODE,
     "    setResendContent(i18n('Login.Code.Resending'));\n",
     "    setResendContent(i18n(getPlumaResendLangKeys(sentCode)?.sending ?? 'Login.Code.Resending')); // pluma\n"),
    (AUTH_CODE, "    let args: any[] | undefined;\n",
     "    let args: any[] | undefined;\n"
     "    let button: {url: string, text: LangPackKey} | undefined; // pluma\n"),
    (AUTH_CODE,
     "      case 'auth.sentCodeTypeSms':\n"
     "      // the web client cannot attest with Play Integrity / SafetyNet, so a\n",
     "      // pluma: Pluma sends no SMS: a code that did not reach the person's Telegram, which the\n"
     "      // administrator issues, and the way to let Telegram find them by their number\n"
     "      case 'auth.sentCodeTypeSms':\n"
     "        key = 'Pluma.Code.NotDelivered';\n"
     "        args = [wrapLeftToRight(sentCode.phone_number)];\n"
     "        button = {url: TELEGRAM_PHONE_PRIVACY_LINK, text: 'Pluma.Code.OpenTelegramSettings'};\n"
     "        break;\n"
     "      // the web client cannot attest with Play Integrity / SafetyNet, so a\n"),
    (AUTH_CODE,
     "      case 'auth.sentCodeTypeFragmentSms': {\n"
     "        key = 'PhoneNumber.Code.Fragment.Info';\n"
     "        const a = document.createElement('a');\n"
     "        setBlankToAnchor(a);\n"
     "        a.href = type.url;\n"
     "        args = [a];\n"
     "        break;\n"
     "      }\n",
     "      // pluma: Pluma has no Fragment numbers: a code sent to the person's Telegram, in a message from\n"
     "      // the account whose chat url opens (none when the server does not know it)\n"
     "      case 'auth.sentCodeTypeFragmentSms':\n"
     "        key = 'Pluma.Code.SentTelegram';\n"
     "        args = [wrapLeftToRight(sentCode.phone_number)];\n"
     "        if(TELEGRAM_CHAT_LINK.test(type.url)) {\n"
     "          button = {url: type.url, text: 'Pluma.Code.OpenTelegram'};\n"
     "        }\n"
     "        break;\n"),
    (AUTH_CODE, "    setSentTypeContent(i18n(key, args));\n",
     "    setSentTypeContent(i18n(key, args));\n"
     "    setTelegramButton(button); // pluma\n"),
    (AUTH_CODE,
     "          text=\"Login.Next\"\n"
     "        />\n"
     "      </Show>\n",
     "          text=\"Login.Next\"\n"
     "        />\n"
     "      </Show>\n"
     "      {/* pluma: the filled button of the screens of a code sent through Telegram */}\n"
     "      <Show when={telegramButton()} keyed>\n"
     "        {(button) => (\n"
     "          <Button\n"
     "            class={classNames('btn-primary btn-color-primary', styles.wordSubmit)}\n"
     "            onClick={() => openTelegramLink(button.url)}\n"
     "            text={button.text}\n"
     "          />\n"
     "        )}\n"
     "      </Show>\n"),
)


def login_code_screens(tree):
    # What the edits rely on: the sticker of the screen of a code that did
    # not reach Telegram, and the one use of setBlankToAnchor (and its
    # import, which goes with it).
    tree.expect("src/lib/lottie/lottieLoader.ts", "  | 'UtyanSearch'\n")
    tree.expect(AUTH_CODE, "setBlankToAnchor", 3)
    for rel, old, new in LOGIN_CODE_EDITS:
        tree.replace(rel, old, new)
    tree.replace(AUTH_CODE, "import setBlankToAnchor from '@lib/richTextProcessor/setBlankToAnchor';\n", "")


def verify_login_code_screens(sources):
    for rel, old, new in LOGIN_CODE_EDITS:
        text = sources[rel]
        if text.count(new) != 1 or old in text.replace(new, ""):
            raise PatchError(f"{rel}: the edit of task 076 is not there")
    for line in LOGIN_CODE_STRING_LINES:
        if sources[LANG_SIGN].split("\n").count(line) != 1:
            raise PatchError(f"{LANG_SIGN}: {line.strip()[:60]!r} is not there once")
    for s in ("'jolly_roger'", "'PhoneNumber.Code.Fragment.Info'", "setBlankToAnchor"):
        if s in sources[AUTH_CODE]:
            raise PatchError(f"{AUTH_CODE}: {s} is still there; a code in Telegram is no Fragment code")


# --- updates of an open tab -----------------------------------------------------
#
# A release of the site reaches a tab that stays open within the hour, and the
# operator can make one mandatory (the owner's decision of 2026-11-13). Upstream
# asks the site's `version` every 30 minutes and shows its Update button when it
# differs from the running one (sidebarLeft/index.ts, CHECK_UPDATE_INTERVAL), but
# every Pluma build of one upstream commit is the same "2.3 (686)": the build is
# this repository's commit instead, in the site as pluma-version, a name without
# an extension the service worker caches (requestCache of serviceWorker/index.service.ts
# takes .js, .json and the like). A build of a higher PLUMA_REQUIRED_EPOCH
# (config/app.env) than the tab's is a mandatory release: the tab goes under the
# screen of a tab that cannot go on (pages/deactivatedScreen.ts, upstream's for a
# newer version in another tab), which reloads it however it is closed.

RELEASE_FILE = "public/pluma-version"
UPDATE_SIDEBAR = "src/components/sidebarLeft/index.ts"
SERVICE_WORKER = "src/lib/serviceWorker/index.service.ts"
# The files of the site the service worker answers from its cache.
SERVICE_WORKER_CACHED = r"/\.(js|css|jpe?g|json|wasm|png|mp3|svg|tgs|ico|woff2?|ttf)(?:\?.*)?$/"
UPDATE_APP = "src/config/app.ts"
UPDATE_STRINGS = (
    ("Pluma.Update.Required.Title", "Update required"),
    ("Pluma.Update.Required.Subtitle", "This version can no longer be used.\\nClick anywhere to reload this tab."),
)
UPDATE_STRING_LINES = tuple(f"  '{key}': '{value}'," for key, value in UPDATE_STRINGS)
UPDATE_CHECK = (
    "    {\n"
    "      const CHECK_UPDATE_INTERVAL = 1800e3;\n"
    "      const checkUpdateInterval = setInterval(() => {\n"
    "        fetch('version', {cache: 'no-cache'})\n"
    "        .then((res) => (res.status === 200 && res.ok && res.text()) || Promise.reject())\n"
    "        .then((text) => {\n"
    "          if(text !== App.versionFull) {\n"
    "            this.hasUpdate = true;\n"
    "            clearInterval(checkUpdateInterval);\n"
    "\n"
    "            if(!this.newBtnMenu.classList.contains('is-hidden')) {\n"
    "              this.updateBtn.classList.remove('is-hidden');\n"
    "            }\n"
    "          }\n"
    "        })\n"
    "        .catch(noop);\n"
    "      }, CHECK_UPDATE_INTERVAL);\n"
    "    }\n",
    "    {\n"
    "      // pluma: a release of the site is a build of Pluma's, while every build of one Web K is the same `version`:\n"
    "      // the page compares its build with the site's pluma-version (no extension, which the service worker would\n"
    "      // cache), every 15 minutes and when it is shown again, a minute at least after the last time, so a release\n"
    "      // reaches an open tab within the hour. Another build shows the Update button; one of a higher required epoch\n"
    "      // (a mandatory release, ci/patch.py) leaves the tab under the screen of an updated version, closed by a reload\n"
    "      const CHECK_UPDATE_INTERVAL = 900e3;\n"
    "      const CHECK_UPDATE_AGAIN_AFTER = 60e3;\n"
    "      let checkedAt = 0;\n"
    "      let updateRequired = false;\n"
    "      const checkUpdate = () => {\n"
    "        if(updateRequired) {\n"
    "          return;\n"
    "        }\n"
    "\n"
    "        checkedAt = Date.now();\n"
    "        fetch('pluma-version', {cache: 'no-cache'})\n"
    "        .then((res) => (res.status === 200 && res.ok && res.json()) || Promise.reject())\n"
    "        .then((deployed: {build?: unknown, epoch?: unknown}) => {\n"
    "          if(updateRequired || typeof(deployed?.build) !== 'string' || deployed.build === App.plumaBuild) {\n"
    "            return;\n"
    "          }\n"
    "\n"
    "          if(typeof(deployed.epoch) === 'number' && deployed.epoch > App.plumaRequiredEpoch) {\n"
    "            updateRequired = true;\n"
    "            clearInterval(checkUpdateInterval);\n"
    "            showDeactivatedScreen({\n"
    "              title: 'Pluma.Update.Required.Title',\n"
    "              subtitle: 'Pluma.Update.Required.Subtitle',\n"
    "              onClick: () => appNavigationController.reload()\n"
    "            });\n"
    "            return;\n"
    "          }\n"
    "\n"
    "          this.hasUpdate = true;\n"
    "          if(!this.newBtnMenu.classList.contains('is-hidden')) {\n"
    "            this.updateBtn.classList.remove('is-hidden');\n"
    "          }\n"
    "        })\n"
    "        .catch(noop);\n"
    "      };\n"
    "      const checkUpdateInterval = setInterval(checkUpdate, CHECK_UPDATE_INTERVAL);\n"
    "      const onShown = () => {\n"
    "        if(document.visibilityState === 'visible' && Date.now() - checkedAt >= CHECK_UPDATE_AGAIN_AFTER) {\n"
    "          checkUpdate();\n"
    "        }\n"
    "      };\n"
    "      document.addEventListener('visibilitychange', onShown);\n"
    "      window.addEventListener('focus', onShown);\n"
    "    }\n",
)
UPDATE_IMPORT = (
    "import App, {getAppVersionText} from '@config/app';\n",
    "import App, {getAppVersionText} from '@config/app';\n"
    "import {showDeactivatedScreen} from '@/pages/deactivatedScreen';\n",
)
UPDATE_LANG_ANCHOR = ("  'Deactivated.LoadFailed.Subtitle': 'Part of the app could not be downloaded. Check your connection."
                      "\\nClick anywhere to reload this tab.',\n")


def update_app_edit(c):
    return ("  build: +import.meta.env.VITE_BUILD,\n",
            "  build: +import.meta.env.VITE_BUILD,\n"
            "  // pluma: the release of the site this page is (ci/patch.py, update_prompts)\n"
            f"  plumaBuild: '{c.build_id}',\n"
            f"  plumaRequiredEpoch: {c.required_epoch},\n")


def release_file(c):
    return json.dumps({"build": c.build_id, "epoch": c.required_epoch}) + "\n"


def update_prompts(tree, c):
    # What the edits rely on: the screen and the reload they call, and the
    # button they show.
    tree.expect("src/pages/deactivatedScreen.ts", "export function showDeactivatedScreen({title, subtitle, onClick}: DeactivatedScreen) {\n")
    tree.expect("src/pages/deactivatedScreen.ts", "    closable: true,\n    onClose: onClick,\n")
    tree.expect(UPDATE_SIDEBAR, "import appNavigationController, {NavigationItem} from '@components/appNavigationController';\n")
    tree.expect(UPDATE_SIDEBAR, "      appNavigationController.reload();\n    });\n\n    sidebarHeader.nextElementSibling.append(this.updateBtn);\n")
    # The site's file: one the build keeps (ci/build.sh publishes what
    # keepAsset.js names) and the service worker does not cache.
    tree.expect("keepAsset.js", "    || asset.includes('version')\n")
    tree.expect(SERVICE_WORKER, f"    event.request.url.match({SERVICE_WORKER_CACHED})\n")
    if (tree.root / RELEASE_FILE).exists():
        raise PatchError(f"{RELEASE_FILE}: upstream ships one now; review what it is")
    for rel, old, new in (UPDATE_SIDEBAR, *UPDATE_CHECK), (UPDATE_SIDEBAR, *UPDATE_IMPORT), (UPDATE_APP, *update_app_edit(c)):
        tree.replace(rel, old, new)
    tree.replace("src/lang.ts", UPDATE_LANG_ANCHOR,
                 UPDATE_LANG_ANCHOR + "".join(line + "\n" for line in UPDATE_STRING_LINES))
    tree.write(RELEASE_FILE, release_file(c))


def verify_update_prompts(tree, c, sources):
    for rel, old, new in (UPDATE_SIDEBAR, *UPDATE_CHECK), (UPDATE_SIDEBAR, *UPDATE_IMPORT), (UPDATE_APP, *update_app_edit(c)):
        text = sources[rel]
        if text.count(new) != 1 or old in text.replace(new, ""):
            raise PatchError(f"{rel}: the edit of the update prompts is not there")
    lines = sources["src/lang.ts"].split("\n")
    for line in UPDATE_STRING_LINES:
        if lines.count(line) != 1:
            raise PatchError(f"src/lang.ts: {line.strip()[:60]!r} is not there once")
    # Nothing else asks the site for its build: upstream's own check, moved,
    # would compare a version that never changes here.
    for rel, text in sources.items():
        if re.search(r"fetch\(\s*['\"`](?:\./)?version['\"`]", text):
            raise PatchError(f"{rel}: asks the site's version, which the update prompts replace")
        if len(re.findall(r"['\"`](?:\./)?pluma-version['\"`]", text)) != (rel == UPDATE_SIDEBAR):
            raise PatchError(f"{rel}: asks pluma-version, which only the update prompts may")
    release = tree.root / RELEASE_FILE
    if not release.is_file() or release.read_text(encoding="utf-8") != release_file(c):
        raise PatchError(f"{RELEASE_FILE}: not the release of this build")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--source", required=True, help="the tweb checkout")
    ap.add_argument("--upstream", required=True, help="upstream.env")
    ap.add_argument("--app", required=True, help="config/app.env")
    ap.add_argument("--server-url", required=True, help="the WebSocket URL of the server, wss://<host>/apiws")
    ap.add_argument("--rsa-public-key", required=True, help="PKCS#1 PEM of the server key")
    ap.add_argument("--target", required=True, help="server or dev (recorded for ci/build.sh)")
    ap.add_argument("--build-id", required=True, help="the commit of this repository the build is made from")
    a = ap.parse_args(argv)
    try:
        c = Config(load_env(a.upstream), load_env(a.app), a.server_url,
                   pathlib.Path(a.rsa_public_key).read_text(), a.target, a.build_id)
        tree = Tree(a.source)
        patch(tree, c)
        verify(tree, c)
        tree.write(RECORD, json.dumps(c.record(), indent=2) + "\n")
    except PatchError as e:
        print(f"patch: {e}", file=sys.stderr)
        return 1
    print(f"patch: \"{c.app_name}\", api_id {c.api_id}, layer {c.layer}, server {c.server_url}, "
          f"server key {c.fingerprint:#018x} ({c.fingerprint})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
