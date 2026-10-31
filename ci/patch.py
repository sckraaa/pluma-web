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
    def __init__(self, upstream, app, server_url, rsa_pem, target):
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

# The built-in English strings. The word Telegram in a value becomes the
# app's name ("Pluma Premium", "Sign in to Pluma"); in a key, a comment or a
# URL (t.me/TelegramTips) it stays: (file, words renamed, words left).
STRINGS = (
    ("src/lang.ts", 210, 30),
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
)
_TG_LINK = re.compile(r"['\"`]tg:|\^tg:")
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
        ("link-color", "#00488f", "#4f6e52"),
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
        ("link-color", "#8774E1", "#b2ceb4"),
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
    ("src/scss/partials/_button.scss",
     "      background-color: var(--primary-color);\n" "      color: #fff;\n" "      padding: .125rem .3125rem;\n"),
    ("src/scss/partials/_row.scss",
     "      background-color: var(--primary-color);\n" "      color: #fff;\n" "      padding: .1875rem .3125rem;\n"),
    ("src/scss/partials/_chat.scss",
     "\t.btn-send {\n" "    color: #fff !important;\n" "    background-color: var(--primary-color) !important;\n"),
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
    ("src/scss/partials/_replyKeyboard.scss",
     "        background-color: var(--primary-color);\n" "        color: #fff !important;\n"),
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
     "  background: var(--primary-color);\n" "  color: #fff;\n"),
    ("src/components/popups/webAppLocationAccess.module.scss",
     "  background: var(--primary-color);\n" "  color: var(--white);\n"),
)
_WHITE_ON_PRIMARY = re.compile(r"(?<![\w-])((?:color|stroke): )(?:#fff|white|var\(--white\)|var\(--badge-text-color\))")


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


def rebrand(tree, c):
    name = c.app_name

    # Icons and logos.
    for rel, sha256 in ICONS:
        tree.replace_file("public/" + rel, sha256, (BRAND / "web" / rel).read_bytes())
    tree.replace_file("public/" + SCREENSHOT[0], SCREENSHOT[1], None)
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
    tree.replace(side, "  t.textContent = `Telegram Web${App.suffix} ${App.version} (${App.build})`;\n",
                 f"  t.textContent = `{name} Web ${{App.version}} (${{App.build}})`;\n")
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
    tree.replace(theme, "'link-color': '#b2ceb4', // SCSS resolves to var(--primary-color)\n",
                 "'link-color': '#b2ceb4', // pluma: lighter than the accent\n")
    tree.replace(theme,
                 "import {changeColorAccent, ColorRgb, getAccentColor, getAverageColor, getRgbColorFromTelegramColor, "
                 "hexToRgb, hslaStringToHex, hslaStringToRgba, hslaToRgba, hsvToRgb, mixColors, rgbaToHexa, "
                 "rgbaToHsla, rgbToHsv} from '@helpers/color';\n",
                 "import {changeColorAccent, ColorRgb, computePerceivedBrightness, getAccentColor, getAverageColor, "
                 "getRgbColorFromTelegramColor, hexToRgb, hslaStringToHex, hslaStringToRgba, hslaToRgba, hsvToRgb, "
                 "mixColors, rgbaToHexa, rgbaToHsla, rgbToHsv} from '@helpers/color';\n")
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
                 "      hex: isNight ? '#ffffff' : rgbaToHexa(accentColor2 ? hsvToRgb(...accentColor2) : myMessagesAccent),\n",
                 "      // pluma: the outbox accent colours the time and checks of a dark theme too.\n"
                 "      hex: accentColor2 ? rgbaToHexa(hsvToRgb(...accentColor2)) : "
                 "(isNight ? '#ffffff' : rgbaToHexa(myMessagesAccent)),\n")
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

    base = "src/scss/base.scss"
    tree.replace(base, "  --badge-text-color: #fff;\n  --original-ripple-color: rgba(0, 0, 0, #{$hover-alpha});\n",
                 "  --badge-text-color: #fff;\n"
                 "  // pluma: what sits on an accent fill; themeController sets it per theme.\n"
                 "  --on-primary-color: #fff;\n"
                 "  --original-ripple-color: rgba(0, 0, 0, #{$hover-alpha});\n")
    tree.replace(base, '  @include avatar-color("blue", #5CAFFA, #408ACF);\n',
                 '  @include avatar-color("blue", #7FA082, #6F8F72); // pluma: sage, not blue\n')
    tree.replace(base, "  --avatar-color-story-unread-from: #34c76f;\n  --avatar-color-story-unread-to: #3da1fd;\n",
                 "  // pluma: sage, not green and blue.\n"
                 "  --avatar-color-story-unread-from: #9DBB9F;\n  --avatar-color-story-unread-to: #5B7A5E;\n")
    tree.replace(base, "  --message-checkbox-color: #61c642;\n", "  --message-checkbox-color: var(--primary-color); // pluma\n")
    tree.replace(base,
                 "  --message-out-link-color: #fff;\n"
                 "  --message-out-status-color: #fff;\n"
                 "  --message-out-time-color: rgba(255, 255, 255, .6);\n",
                 "  // pluma: the outbox accent (white unless a theme has one), as in the day theme.\n"
                 "  --message-out-link-color: var(--message-out-primary-color);\n"
                 "  --message-out-status-color: var(--message-out-primary-color);\n"
                 "  --message-out-time-color: var(--message-out-status-color);\n")
    for rel, rule in ON_PRIMARY:
        new, n = _WHITE_ON_PRIMARY.subn(r"\1var(--on-primary-color)", rule)
        if n != 1:
            raise PatchError(f"ON_PRIMARY: {rule!r} has {n} colours, expected 1")
        tree.replace(rel, rule, new)
    tree.replace("src/scss/partials/_badge.scss",
                 "  &-primary {\n    background-color: var(--primary-color);\n  }\n",
                 "  &-primary {\n    background-color: var(--primary-color);\n    color: var(--on-primary-color); // pluma\n  }\n")
    tree.replace("src/scss/partials/_slider.scss",
                 "        .badge {\n          background-color: var(--primary-color);\n        }\n",
                 "        .badge {\n          background-color: var(--primary-color);\n"
                 "          color: var(--on-primary-color); // pluma\n        }\n")
    chatlist = "src/scss/partials/_chatlist.scss"
    tree.replace(chatlist,
                 "  .is-muted.backwards .dialog-subtitle-badge-pollvote {\n"
                 "    background-color: var(--chatlist-status-color);\n  }\n",
                 "  .is-muted.backwards .dialog-subtitle-badge-pollvote {\n"
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
                            ("#fff", "var(--on-primary-color)", 9),
                            ("color: white;", "color: var(--on-primary-color);", 1),
                            ("rgba(255, 255, 255, .7)", "color-mix(in srgb, var(--on-primary-color) 70%, transparent)", 1),
                            ("rgba(255, 255, 255, .2)", "color-mix(in srgb, var(--on-primary-color) 20%, transparent)", 1),
                        ))


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
    tree.replace(rel,
                 "// Preview-only: 1 opens the gift popup directly, 2+ opens the recipient picker.\n",
                 "// Preview-only: 1 opens the chat directly, 2+ opens the list of them to pick\n"
                 "// from (pluma: not the gift popup and the recipient picker).\n")

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
                 "  const canLoadBirthdayContacts = () => TEST_BIRTHDAY_CONTACTS || !appConfig.premium_purchase_blocked;\n"
                 "  const canShowBirthdayContacts = () => (\n"
                 "    TEST_BIRTHDAY_CONTACTS || (\n"
                 "      canLoadBirthdayContacts() &&\n"
                 "      promoDataLoaded() &&\n",
                 "  // pluma: whether Premium is for sale does not matter: the banner leads\n"
                 "  // to the chat, not to a gift.\n"
                 "  const canShowBirthdayContacts = () => (\n"
                 "    TEST_BIRTHDAY_CONTACTS || (\n"
                 "      promoDataLoaded() &&\n")
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


def patch(tree, c):
    # The upstream is the one upstream.env describes: the schema layer the
    # server speaks (ADR 0008), the version, and the toolchain the CI installs.
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
    tree.replace(app, "  baseDcId: 2 as TrueDcId,\n",
                 "  // pluma: the Pluma server is datacenter 1.\n"
                 "  baseDcId: 1 as TrueDcId,\n")
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

    # Pluma's name, icons, link scheme and colours.
    rebrand(tree, c)


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
    for s in (f"  id: {c.api_id},\n", f"  hash: '{c.api_hash}',\n", "  baseDcId: 1 as TrueDcId,\n"):
        if s not in app:
            raise PatchError(f"app.ts: no {s.strip()!r}")
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
    for rel, _, _ in STRINGS:
        for line in sources[rel].split("\n"):
            m = _STRING_ENTRY.match(line)
            if m and _TELEGRAM_WORD.search(m.group(2)):
                raise PatchError(f"{rel}: {m.group(2)[:60]!r} still says Telegram")
    for rel, text in sources.items():
        m = _TG_LINK.search(_COMMENT.sub("", text))
        if m:
            raise PatchError(f"{rel}: a tg: link ({m.group()!r}); Pluma's links are plm://")
    if "'plm://login?token='" not in sources["src/pages/cards/SignQRCard.tsx"]:
        raise PatchError("SignQRCard.tsx: the QR code does not sign in with plm://login")
    if '<g id="logo"' not in sources["index.html"]:
        raise PatchError("index.html: not Pluma's logo on the sign-in page")

    # The birthday banner: nothing of the gift flow or the Premium gate left.
    for s in ("premium_purchase_blocked", "showSendGift", "popups/sendGift", "appGiftsManager",
              "Suggestion.BirthdayContacts.Subtitle", "Suggestion.BirthdayContacts.Dismissed"):
        if s in sources[BIRTHDAYS]:
            raise PatchError(f"{BIRTHDAYS}: {s!r} is still there; the birthday banner must open the chat")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--source", required=True, help="the tweb checkout")
    ap.add_argument("--upstream", required=True, help="upstream.env")
    ap.add_argument("--app", required=True, help="config/app.env")
    ap.add_argument("--server-url", required=True, help="the WebSocket URL of the server, wss://<host>/apiws")
    ap.add_argument("--rsa-public-key", required=True, help="PKCS#1 PEM of the server key")
    ap.add_argument("--target", required=True, help="server or dev (recorded for ci/build.sh)")
    a = ap.parse_args(argv)
    try:
        c = Config(load_env(a.upstream), load_env(a.app), a.server_url,
                   pathlib.Path(a.rsa_public_key).read_text(), a.target)
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
