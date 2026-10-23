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
    """The name of the installed app; no claim on t.me and telegram.me links
    and no GCM sender id of Telegram's web push."""
    m = json.loads(tree.read(rel))
    if m.get("name") != "Telegram Web" or m.get("short_name") != "Telegram Web" or "description" not in m:
        raise PatchError(f"{rel}: no name \"Telegram Web\" and description; upstream changed it")
    origins = [s.get("origin") for s in m.get("scope_extensions", [])]
    if origins != ["https://t.me", "https://telegram.me"]:
        raise PatchError(f"{rel}: scope_extensions {origins}, expected t.me and telegram.me; upstream changed it")
    if "gcm_sender_id" not in m:
        raise PatchError(f"{rel}: no gcm_sender_id; upstream changed it")
    m["name"] = m["short_name"] = m["description"] = c.app_name
    del m["scope_extensions"], m["gcm_sender_id"]
    tree.write(rel, json.dumps(m, indent=4, ensure_ascii=False) + "\n")


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
