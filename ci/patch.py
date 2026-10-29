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
# Pluma's icons and logos instead of Telegram's (task 017 of the server
# repository).

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

# The accent of the light theme (the dark one's is #9dbb9f): the Windows
# tile and the unread count drawn over the favicon.
ACCENT = "#5b7a5e"


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


def rebrand(tree, c):
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

    # Pluma's icons and logos.
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

    # The brand: Pluma's icons and logos.
    for rel, _ in ICONS:
        if tree.sha256("public/" + rel) != hashlib.sha256((BRAND / "web" / rel).read_bytes()).hexdigest():
            raise PatchError(f"public/{rel}: not Pluma's (brand/web)")
    if (tree.root / "public" / SCREENSHOT[0]).exists():
        raise PatchError(f"public/{SCREENSHOT[0]}: Telegram's screenshot is still there")
    if '<g id="logo"' not in sources["index.html"]:
        raise PatchError("index.html: not Pluma's logo on the sign-in page")


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
