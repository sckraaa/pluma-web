#!/usr/bin/env python3
import hashlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import check_bundle  # noqa: E402
import patch  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Telegram's production and test server keys (core.telegram.org), and the
# moduli tweb carries for them in rsaKeysManager.ts.
TELEGRAM_PROD = """-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g
5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO
62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/
+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9
t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs
5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB
-----END RSA PUBLIC KEY-----"""

TELEGRAM_TEST = """-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO/vBfqACJLZtS7QMgCGXJ6XIR
yy7mx66W0/sOFa7/1mAZtEoIokDP3ShoqF4fVNb6XeqgQfaUHd8wJpDWHcR2OFwv
plUUI1PLTktZ9uW2WE23b+ixNwJjJGwBDJPQEQFBE+vfmH0JP503wr5INS1poWg/
j25sIWeYPHYeOrFp/eXaqhISP6G+q2IeTaWTXpwZj4LzXq5YOpk4bYEQ6mvRq7D1
aHWfYmlEGepfaYR8Q0YqvvhYtMte3ITnuSJs171+GDqpdKcSwHnd6FudwGO4pcCO
j4WcDuXc2CTHgH8gFTNhp/Y8/SpDOhvn9QIDAQAB
-----END RSA PUBLIC KEY-----"""

TWEB_PROD_MODULUS = (
    "e8bb3305c0b52c6cf2afdf7637313489e63e05268e5badb601af417786472e5f"
    "93b85438968e20e6729a301c0afc121bf7151f834436f7fda680847a66bf64ac"
    "cec78ee21c0b316f0edafe2f41908da7bd1f4a5107638eeb67040ace472a14f9"
    "0d9f7c2b7def99688ba3073adb5750bb02964902a359fe745d8170e36876d4fd"
    "8a5d41b2a76cbff9a13267eb9580b2d06d10357448d20d9da2191cb5d8c93982"
    "961cdfdeda629e37f1fb09a0722027696032fe61ed663db7a37f6f263d370f69"
    "db53a0dc0a1748bdaaff6209d5645485e6e001d1953255757e4b8e42813347b1"
    "1da6ab500fd0ace7e6dfa3736199ccaf9397ed0745a427dcfa6cd67bcb1acff3")

TWEB_TEST_MODULUS = (
    "c8c11d635691fac091dd9489aedced2932aa8a0bcefef05fa800892d9b52ed03"
    "200865c9e97211cb2ee6c7ae96d3fb0e15aeffd66019b44a08a240cfdd2868a8"
    "5e1f54d6fa5deaa041f6941ddf302690d61dc476385c2fa655142353cb4e4b59"
    "f6e5b6584db76fe8b1370263246c010c93d011014113ebdf987d093f9d37c2be"
    "48352d69a1683f8f6e6c2167983c761e3ab169fde5daaa12123fa1beab621e4d"
    "a5935e9c198f82f35eae583a99386d8110ea6bd1abb0f568759f62694419ea5f"
    "69847c43462abef858b4cb5edc84e7b9226cd7bd7e183aa974a712c079dde85b"
    "9dc063b8a5c08e8f859c0ee5dcd824c7807f20153361a7f63cfd2a433a1be7f5")

# A 1024-bit key.
SHORT_KEY = """-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMBvrxwgy0g1WuxFbnjB79af4juEIO3ZXfx30SS/tndZtRAb4XJuUkTj
uONmIsoK45uRKr4M3ALh8hMjCUXWfEOJAcd/CQjW5Iki3JK6DDkh9vZnPdM0vYv9
mYMNNrfzbwRjZeV714GXl0lT5km9M59gELCLwoFVOeKaLC400rX9AgMBAAE=
-----END RSA PUBLIC KEY-----"""

DEV_KEY = (ROOT / "config/dev/server_public.pem").read_text()


def fingerprint(pem):
    return patch.key_fingerprint(*patch.parse_pkcs1_public_key(pem))


class KeyTest(unittest.TestCase):
    def test_telegram_fingerprints(self):
        self.assertEqual(fingerprint(TELEGRAM_PROD), 0xD09D1D85DE64FD85)
        self.assertEqual(fingerprint(TELEGRAM_TEST), 0xB25898DF208D2603)

    def test_hex_as_tweb_carries_it(self):
        # The conversion reproduces tweb's own hex of Telegram's keys, which
        # tweb fingerprints the same way the server does.
        for pem, modulus in ((TELEGRAM_PROD, TWEB_PROD_MODULUS), (TELEGRAM_TEST, TWEB_TEST_MODULUS)):
            n, e = patch.parse_pkcs1_public_key(pem)
            self.assertEqual(n.hex(), modulus)
            self.assertEqual(e.hex(), "010001")

    def test_dev_key_fingerprint(self):
        # The fingerprint the server prints for the development key
        # (tools/genserverkey in the server repository).
        self.assertEqual(fingerprint(DEV_KEY), 14037083214707814241)

    def test_rejects_other_formats(self):
        for pem in (TELEGRAM_PROD.replace("RSA PUBLIC KEY", "PUBLIC KEY"),
                    TELEGRAM_PROD.replace("MIIBCg", "MIIB*g"),
                    "\n".join(TELEGRAM_PROD.splitlines()[:3] + TELEGRAM_PROD.splitlines()[-1:])):
            with self.subTest(pem=pem[:60]), self.assertRaises(patch.PatchError):
                patch.parse_pkcs1_public_key(pem)


class ServerUrlTest(unittest.TestCase):
    def test_valid(self):
        for url, want in (
            ("wss://pluma.chat/apiws", "wss://pluma.chat/apiws"),
            ("wss://Web.Pluma.Chat:8443/apiws", "wss://web.pluma.chat:8443/apiws"),
            ("wss://203.0.113.7/apiws", "wss://203.0.113.7/apiws"),
            ("wss://[2001:db8::1]/apiws", "wss://[2001:db8::1]/apiws"),
            ("ws://localhost:11443/apiws", "ws://localhost:11443/apiws"),
            ("ws://127.0.0.1:11443/apiws", "ws://127.0.0.1:11443/apiws"),
            ("ws://[::1]:11443/apiws", "ws://[::1]:11443/apiws"),
        ):
            with self.subTest(url=url):
                self.assertEqual(patch.parse_server_url(url), want)

    def test_rejects(self):
        for url in (
            "https://pluma.chat/apiws",
            "ws://pluma.chat/apiws",
            "ws://192.168.1.10:11443/apiws",
            "WSS://pluma.chat/apiws",
            "wss://pluma.chat",
            "wss://pluma.chat/apiws?key=1",
            "wss://pluma.chat/apiws#x",
            "wss://user@pluma.chat/apiws",
            "wss://pluma.chat/api'ws",
            "wss://pluma.chat:0/apiws",
            "wss://pluma.chat:65536/apiws",
            "wss://-pluma.chat/apiws",
            "wss://pluma..chat/apiws",
            "wss://300.0.113.7/apiws",
            "wss://[2001:db8::zz]/apiws",
            " wss://pluma.chat/apiws",
        ):
            with self.subTest(url=url), self.assertRaises(patch.PatchError):
                patch.parse_server_url(url)


class NodeEnginesTest(unittest.TestCase):
    def test_upstream_range(self):
        spec = "^22.18.0 || >=24.11.0"
        for version, ok in (("24.22.1", True), ("22.18.0", True), ("22.30.0", True), ("26.0.0", True),
                            ("22.17.9", False), ("23.5.0", False), ("24.10.9", False), ("20.19.0", False)):
            with self.subTest(version=version):
                self.assertEqual(patch.node_satisfies(version, spec), ok)

    def test_other_forms(self):
        self.assertTrue(patch.node_satisfies("22.13.0", ">=22.13"))
        self.assertTrue(patch.node_satisfies("24.11.5", "~24.11.0"))
        self.assertFalse(patch.node_satisfies("24.12.0", "~24.11.0"))
        self.assertTrue(patch.node_satisfies("24.22.1", ">=24 <25"))
        self.assertFalse(patch.node_satisfies("25.0.0", ">=24 <25"))

    def test_rejects_unknown_syntax(self):
        for spec in ("24.x", "lts/*", "", ">=24 ||"):
            with self.subTest(spec=spec), self.assertRaises(patch.PatchError):
                patch.node_satisfies("24.22.1", spec)


def config(**over):
    upstream = patch.load_env(ROOT / "upstream.env")
    app = patch.load_env(ROOT / "config/app.env")
    args = dict(server_url="wss://pluma.chat/apiws", rsa_pem=DEV_KEY, target="server")
    args.update(over.pop("args", {}))
    upstream.update(over.pop("upstream", {}))
    app.update(over.pop("app", {}))
    return patch.Config(upstream, app, **args)


class ConfigTest(unittest.TestCase):
    def test_repository_config(self):
        c = config()
        self.assertEqual((c.app_name, c.api_id, c.layer), ("Pluma", 10004, 233))
        self.assertRegex(c.api_hash, r"\A[0-9a-f]{32}\Z")
        self.assertEqual(c.fingerprint, 14037083214707814241)
        self.assertEqual(len(c.modulus), 512)
        dev = patch.load_env(ROOT / "config/dev/server.env")
        self.assertEqual(patch.parse_server_url(dev["PLUMA_SERVER_URL"]), "ws://localhost:11443/apiws")

    def test_rejects(self):
        for over in (
            {"args": {"server_url": "ws://pluma.chat/apiws"}},
            {"args": {"rsa_pem": SHORT_KEY}},
            {"args": {"target": "release"}},
            {"app": {"PLUMA_API_HASH": "036E9BCFB4175B817EAE73952C7DA3C5"}},
            {"app": {"PLUMA_API_HASH": ""}},
            {"app": {"PLUMA_API_ID": "web"}},
            {"app": {"PLUMA_API_ID": "0"}},
            {"app": {"PLUMA_APP_NAME": "Pluma'"}},
            {"app": {"PLUMA_APP_NAME": "<Pluma>"}},
            {"upstream": {"UPSTREAM_LAYER": ""}},
            {"upstream": {"NODE_VERSION": "lts"}},
        ):
            with self.subTest(over=over), self.assertRaises(patch.PatchError):
                config(**over)


class TraceTest(unittest.TestCase):
    def test_finds(self):
        for text, kind in (
            ("{id: 2, host: '149.154.167.50',  port: 80}", "address"),
            ("connect('91.108.56.130:443')", "address"),
            ("[2001:b28:f23d:f001::a]:443", "address"),
            ("2001:67C:4E8:F002::A", "address"),
            ("`wss://${s}ws${dcId}.web.telegram.org/apiws`", "endpoint"),
            ("'https://' + subdomain + '.Web.Telegram.org/'", "endpoint"),
            ("'//t.me/_websync_?authed=1'", "endpoint"),
            ("modulus: '" + TWEB_TEST_MODULUS.upper() + "'", "server key"),
            (TELEGRAM_PROD, "server key"),
            ("fingerprint 0xD09D1D85DE64FD85", "server key"),
            ('"gcm_sender_id": "122867383838"', "credential"),
        ):
            with self.subTest(text=text[:50]):
                self.assertIn(kind, [k for k, _ in patch.telegram_traces(text)])

    def test_ignores(self):
        for text in (
            "https://web.telegram.org/a/",
            "https://t.me/durov",
            "149.154.176.1 192.0.2.1 91.108.20.1",
            "version 1.149.154.167.50 and 149.154.167.50.1",
            "ws://localhost:11443/apiws",
            TWEB_PROD_MODULUS[:31],
        ):
            with self.subTest(text=text):
                self.assertEqual(patch.telegram_traces(text), [])


class IdentityColorsTest(unittest.TestCase):
    def test_table(self):
        hex_color = r"\A#[0-9A-Fa-f]{6}\Z"
        for identity, table in patch.IDENTITY_COLORS.items():
            with self.subTest(identity=identity):
                self.assertIn(identity, patch.IDENTITIES)
                self.assertEqual(tuple(k for k, _, _ in table), patch._IDENTITY_KEYS)
                for key, old, new in table:
                    self.assertRegex(new, hex_color)
                    # Web K has one name colour for every theme, no dark one.
                    if key == "dark name":
                        self.assertIsNone(old)
                    else:
                        self.assertRegex(old, hex_color)
        for _, identity in patch.IDENTITY_AS_PLAIN:
            self.assertIn(identity, patch.IDENTITY_COLORS)


class TreeTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.dir.name)
        (root / "src/lib/mtproto").mkdir(parents=True)
        (root / "src/lib/mtproto/dcConfigurator.ts").write_text("")
        (root / "a.txt").write_text("one two two\nvoid f() {\n    body;\n}\n")
        self.tree = patch.Tree(root)

    def tearDown(self):
        self.dir.cleanup()

    def test_replace_counts(self):
        with self.assertRaises(patch.PatchError):
            self.tree.replace("a.txt", "two", "2")
        with self.assertRaises(patch.PatchError):
            self.tree.replace("a.txt", "three", "3")
        self.tree.replace("a.txt", "two", "2", count=2)
        self.assertTrue(self.tree.read("a.txt").startswith("one 2 2\n"))

    def test_replace_body(self):
        with self.assertRaises(patch.PatchError):
            self.tree.replace_body("a.txt", "void f() {\n", "\n}\n", "    other;", must_contain=("missing",))
        self.tree.replace_body("a.txt", "void f() {\n", "\n}\n", "    other;", must_contain=("body;",))
        self.assertTrue(self.tree.read("a.txt").endswith("void f() {\n    other;\n}\n"))

    def test_replace_block(self):
        with self.assertRaises(patch.PatchError):
            self.tree.replace_block("a.txt", "void g() {", "\n}\n", "")
        self.tree.replace_block("a.txt", "void f() {", "\n}\n", "int x;\n", must_contain=("body;",))
        self.assertEqual(self.tree.read("a.txt"), "one two two\nint x;\n")

    def test_replace_within(self):
        # The region ends at the first tail: "two" twice before it, once in it.
        self.tree.write("a.txt", "two {\n two two\n}\ntwo\n")
        with self.assertRaises(patch.PatchError):
            self.tree.replace_within("a.txt", "two {\n", "\n}", (("two", "2", 3),))
        with self.assertRaises(patch.PatchError):
            self.tree.replace_within("a.txt", "three {\n", "\n}", (("two", "2", 2),))
        self.tree.replace_within("a.txt", "two {\n", "\n}", (("two", "2", 2),))
        self.assertEqual(self.tree.read("a.txt"), "two {\n 2 2\n}\ntwo\n")

    def test_expect(self):
        self.tree.expect("a.txt", "body;")
        self.tree.expect("a.txt", "two", count=2)
        with self.assertRaises(patch.PatchError):
            self.tree.expect("a.txt", "two")

    def test_replace_file(self):
        sha256 = hashlib.sha256(self.tree.read("a.txt").encode()).hexdigest()
        with self.assertRaises(patch.PatchError):
            self.tree.replace_file("a.txt", "0" * 64, b"new")
        with self.assertRaises(patch.PatchError):
            self.tree.replace_file("b.txt", sha256, b"new")
        self.tree.replace_file("a.txt", sha256, b"new")
        self.assertEqual(self.tree.read("a.txt"), "new")
        self.tree.replace_file("a.txt", hashlib.sha256(b"new").hexdigest(), None)
        self.assertFalse((self.tree.root / "a.txt").exists())

    def test_not_a_checkout(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(patch.PatchError):
            patch.Tree(d)


# --- the patch on the pinned upstream ------------------------------------------

# What the patch reads, from the commit upstream.env pins.
UPSTREAM_PATHS = ("src", "public/version", "public/site.webmanifest", "public/site_apple.webmanifest",
                  "public/browserconfig.xml", "public/assets/img", "public/changelogs", "package.json", "index.html", "vite.config.ts")

THEME = "src/helpers/themeController.ts"
STATE = "src/config/state.ts"
SIDEBAR = "src/components/sidebarLeft/index.ts"
BASE = "src/scss/base.scss"
CHATLIST = "src/scss/partials/_chatlist.scss"
BIRTHDAYS = "src/components/sidebarLeft/birthdaySuggestions.tsx"
PROFILE = "src/components/peerProfile.tsx"
PEER_COLORS = "src/lib/appManagers/utils/peers/getPeerColorById.ts"
DIALOG_COLORS = "src/lib/appManagers/utils/peers/dialogColors.ts"
ARCHIVE = "src/components/archiveDialog.module.scss"
FEATURE_ICON = "src/components/featureDetailsIconSticker.module.scss"
SAVED_TAGS = "src/lib/appManagers/utils/reactions/savedTagsAvailable.ts"
CONTEXT_MENU = "src/components/chat/contextMenu.ts"
BUBBLES = "src/components/chat/bubbles.ts"
TOPBAR_SEARCH = "src/components/chat/topbarSearch.tsx"
REACTIONS_MENU = "src/components/chat/reactionsMenu.ts"
MATCH_HOST = "src/lib/richTextProcessor/matchTelegramUrlHost.ts"

DC = "src/lib/mtproto/dcConfigurator.ts"
RSA = "src/lib/mtproto/rsaKeysManager.ts"
APP = "src/config/app.ts"

# Damage to each place the patch edits or checks, as (file, text in the
# pinned upstream, replacement): every one must stop the patch with an error
# that names the file.
DAMAGE = (
    # Premium stickers: each gate and the import its edit is anchored on.
    *((rel, old, old.replace("(", "( ", 1) if "(" in old else old.replace("= ", "=  ", 1))
      for rel, old, _ in patch.PREMIUM_STICKER_GATES),
    ("src/components/chat/input.ts", patch.EFFECT_THUMB_IMPORT, patch.EFFECT_THUMB_IMPORT.replace("import ", "import type ", 1)),
    ("src/lib/mtproto/schema.ts", '"layer":233', '"layer":234'),
    ("public/version", "2.3 (686)", "2.3 (700)"),
    ("package.json", '"pnpm@11.16.0"', '"pnpm@11.17.0"'),
    ("package.json", '"^22.18.0 || >=24.11.0"', '">=26.0.0"'),
    (DC, "export function constructTelegramWebSocketUrl(_dcId", "export function constructTelegramWebSocketUrl(dcId"),
    (DC, "${suffix}.web.telegram.org/${path}", "${suffix}.web.telegram.org/${route}"),
    (DC, "interpolated unchecked", "interpolated as is"),
    (DC, "host: '149.154.175.50'", "host: '149.154.175.51'"),
    (DC, "private transportHTTP = (", "private transportHttp = ("),
    (DC, "return new HTTP(dcId, chosenServer, logSuffix);", "return new Http(dcId, chosenServer, logSuffix);"),
    ("src/lib/appManagers/apiManager.ts", "import.meta.env.VITE_MTPROTO_HTTP_UPLOAD", "import.meta.env.VITE_MTPROTO_HTTP_UPLOADS"),
    (RSA, "export class RSAKeysManager {", "export class RsaKeysManager {"),
    (RSA, "e8bb3305c0b52c6cf2afdf7637313489", "e8bb3305c0b52c6cf2afdf7637313488"),
    (RSA, "this.publisKeysHex = this.testPublicKeysHex;", "this.publisKeysHex = this.testKeysHex;"),
    (RSA, "import Modes from '@config/modes';", "import Modes from '@/config/modes';"),
    (APP, "'webk.telegram.org']", "'webk.telegram.org', 'webz.telegram.org']"),
    (APP, "id: +import.meta.env.VITE_API_ID,", "id: Number(import.meta.env.VITE_API_ID),"),
    (APP, "hash: import.meta.env.VITE_API_HASH,", "hash: String(import.meta.env.VITE_API_HASH),"),
    (APP, "pushServerKey: import.meta.env.VITE_PUSH_SERVER_KEY,", "pushServerKey: import.meta.env.VITE_PUSH_KEY,"),
    (APP, "baseDcId: BASE_DC_ID as TrueDcId,", "baseDcId: 4 as TrueDcId,"),
    (patch.BASE_DC, "export const BASE_DC_ID = 2;", "export const BASE_DC_ID = 4;"),
    (APP, "App.id = 2496;", "App.id = 2496; App.suffix = 'W';"),
    ("src/pages/cards/SignInCard.tsx", "new Set([1, 2, 3, 4, 5])", "new Set([1, 2, 3, 4, 5, 6])"),
    ("src/lib/telegramMeWebManager.ts", "public setAuthorized(canRedirect: boolean) {", "public setAuthorized(canRedirect: boolean, force?: boolean) {"),
    ("src/lib/telegramMeWebManager.ts", "_websync_?authed=", "_sync_?authed="),
    ("src/lib/webPushApiManager.ts", "public subscribe = (): Promise", "public subscribe = async(): Promise"),
    ("vite.config.ts", "title: 'Telegram Web',", "title: 'Telegram Web K',"),
    ("index.html", '<link rel="canonical" href="{{origin}}">', '<link rel="canonical" href="{{url}}">'),
    ("public/site.webmanifest", '"name": "Telegram Web"', '"name": "Telegram"'),
    ("public/site_apple.webmanifest", '"origin": "https://telegram.me"', '"origin": "https://telegram.dog"'),
    ("public/site.webmanifest", '"gcm_sender_id"', '"gcm_sender"'),
    # Traces of Telegram anywhere else in the client's sources, and a
    # second server.
    ("src/lib/mtproto/networker.ts", " * Originally from:\n", " * Originally from:\n * 149.154.167.51:443\n"),
    ("src/lib/mtproto/networker.ts", " * Originally from:\n", " * Originally from:\n * wss://zws2.web.telegram.org/apiws\n"),
    ("src/lib/mtproto/networker.ts", " * Originally from:\n", " * Originally from:\n * " + TWEB_TEST_MODULUS + "\n"),
    (DC, "export class DcConfigurator {", "const fallback = 'wss://pluma.example/apiws';\nexport class DcConfigurator {"),
    # The brand: icons, logos and tiles.
    ("public/site.webmanifest", '"src": "assets/img/screenshot.jpg"', '"src": "assets/img/screenshot2.jpg"'),
    ("index.html", '<path id="logo" fill-rule="evenodd" d="M80,0 C124', '<path id="logo" d="M80,0 C124'),
    ("index.html", "M114.262551,46.4516129", "M114.26,46.45"),
    ("src/pages/cards/SignInCard.tsx", '<use href="#logo"/>', '<use href="#logo-round"/>'),
    ("src/helpers/qrCode/paintQrCode.ts", "text.replace(/(fill:).+?(;)/,", "text.replace(/(fill:).+?(;)/g,"),
    ("index.html", 'content="#2d89ef"', 'content="#2b5797"'),
    ("public/browserconfig.xml", "<TileColor>#2d89ef</TileColor>", "<TileColor>#2b5797</TileColor>"),
    ("src/lib/uiNotificationsManager.ts", "ctx.fillStyle = '#3390ec';", "ctx.fillStyle = '#3390EC';"),
    # The name: a string that says Telegram anew, one that no longer does,
    # and the places in the code.
    ("src/lang.ts", "  'AppName': 'Telegram',\n", "  'AppName': 'Telegram',\n  'AppNameFull': 'Telegram Messenger',\n"),
    ("src/langSign.ts", "'Sign in to Telegram'", "'Sign in'"),
    ("src/lang.ts", "'TelegramFeaturesUrl': 'https://t.me/TelegramTips'", "'TelegramFeaturesUrl': 'https://t.me/Tips'"),
    (SIDEBAR, "btnMenuFooter.href = 'https://github.com/morethanwords/tweb", "btnMenuFooter.href = 'https://github.com/tweb"),
    (APP, "`Telegram Web${App.suffix} ${App.version}", "`Telegram Web ${App.suffix} ${App.version}"),
    (SIDEBAR, "  t.textContent = getAppVersionText();\n", "  t.textContent = 'Telegram Web';\n"),
    (SIDEBAR, "a.href = 'https://bugs.telegram.org/?tag_ids=40&sort=time';", "a.href = 'https://bugs.telegram.org/';"),
    ("src/lib/appManagers/apiUpdatesManager.ts", "**Telegram Web${App.suffix} ${langStr}", "**Telegram Web ${langStr}"),
    ("src/lib/appManagers/appMessagesManager.ts", "first_name: 'Telegram',\n        phone: '42777'",
     "first_name: 'Telegram Notifications',\n        phone: '42777'"),
    ("src/lib/serviceWorker/push.ts", "showNotification('Telegram Web', {", "showNotification('Telegram Web K', {"),
    ("src/lib/serviceWorker/push.ts", "    title = 'Telegram';\n", "    title = 'Telegram Web';\n"),
    # The link scheme, and a tg:// link the patch does not know.
    ("src/pages/cards/SignQRCard.tsx", "'tg://login?token='", "'tg://login/?token='"),
    ("src/components/instantView.tsx", "wrapUrl('tg://iv?url='", "wrapUrl('tg://iv/?url='"),
    ("src/lib/settingsSearch/link.ts", "const PREFIX = 'tg://settings';", "const PREFIX = 'tg://settings/';"),
    ("src/lib/richTextProcessor/wrapUrl.ts", "url.match(/^tg:(?:\\/\\/)?(.+?)", "url.match(/^tg:(?:\\/\\/)(.+?)"),
    ("src/lib/richTextProcessor/wrapUrl.ts", "export default function wrapUrl(",
     "export const RESOLVE = 'tg://resolve';\nexport default function wrapUrl("),
    ("src/lib/richTextProcessor/wrapUrl.ts", "export default function wrapUrl(",
     "export const RESOLVE = /tg:\\/\\/resolve/;\nexport default function wrapUrl("),
    ("src/lib/richTextProcessor/inferRichMessageNoAutolink.ts", "|tg:\\/\\/|", "|(?:tg):\\/\\/|"),
    # The colours.
    (THEME, "    'primary-color': '#3390ec',\n", "    'primary-color': '#3390EC',\n"),
    (THEME, "import {changeColorAccent, ColorRgb, ensureTextContrast,", "import {changeColorAccent, ensureTextContrast, ColorRgb,"),
    (THEME, "      hex: newAccentHex,\n      darkenAlpha: 0.04\n", "      hex: newAccentHex,\n      darkenAlpha: 0.05\n"),
    (THEME, "    if(!isNight/*  || true */) {\n", "    if(!isNight) {\n"),
    (THEME, "hex: isNight ? '#ffffff' : outgoingGradient ?", "hex: isNight ? '#fff' : outgoingGradient ?"),
    (STATE, "    accent_color: 0x3390ec,\n", "    accent_color: 0x3390EC,\n"),
    (STATE, "        fourth_background_color: 0x4f5bd5\n", "        fourth_background_color: 0x4f5bd6\n"),
    (STATE, "  baseThemeNight: 'hsla(299.142857,", "  baseThemeNight: 'hsla(299.14,"),
    ("src/lib/appManagers/utils/state/loadState.ts", "STATE_INIT, AppTheme} from '@config/state';",
     "STATE_INIT, type AppTheme} from '@config/state';"),
    ("src/lib/appManagers/utils/state/loadState.ts", "        theme.settings = [theme.settings as any];\n",
     "        theme.settings = [theme.settings];\n"),
    ("src/helpers/rowIconBackground.ts", "  blue: '#2196F3',", "  blue: '#2196f3',"),
    (BASE, '@include avatar-color("blue", #5CAFFA, #408ACF);', '@include avatar-color("blue", #5CAFFA, #408ACE);'),
    # People's identity colours: the avatars, the names, the code that
    # applies them, the plain uses of the blue gradient, and Telegram's blue
    # or cyan in a place the patch does not know.
    (BASE, '@include avatar-color("cyan", #53edd6, #28c9b7);', '@include avatar-color("cyan", #53EDD6, #28C9B7);'),
    (PEER_COLORS, "['#309EBA'], ['#368AD1']", "['#309EBA'], ['#3E88F7']"),
    (PEER_COLORS, "['#C7508B']];", "['#C7508B'], ['#A0A0A0']];"),
    (DIALOG_COLORS, "'cyan', 'blue', 'pink'] as const;", "'blue', 'cyan', 'pink'] as const;"),
    (PEER_COLORS, "const _DialogColorsFg = DialogColorsFg;", "const _DialogColorsFg = [...DialogColorsFg];"),
    (PEER_COLORS, "replaceColors(_DialogColorsFg.slice(), peerColorOptions);",
     "replaceColors(_DialogColorsFg.slice(), peerColorOptions || []);"),
    (ARCHIVE, "background: linear-gradient(#5CAFFA, #408ACF);", "background: linear-gradient(#5CAFFA 10%, #408ACF);"),
    (FEATURE_ICON, "background: linear-gradient(#5CAFFA, #408ACF);", "background: linear-gradient(#5CAFFA, #408ACF 90%);"),
    ("src/scss/partials/_avatar.scss", '  &[data-color="archive"] {\n',
     '  &[data-color="saved"] {\n    --color-top: #5cafFA;\n  }\n\n  &[data-color="archive"] {\n'),
    ("src/config/themePresets.ts", "name === 'blue') return 0x3e88f7;", "name === 'blue') return 0x368ad1;"),
    ("src/config/themePresets.ts", "name === 'blue') return 0x3e88f7;", "name === 'blue') return 0x28C9B7;"),
    (BASE, "--avatar-color-story-unread-to: #3da1fd;", "--avatar-color-story-unread-to: #3DA1FD;"),
    (BASE, "--message-checkbox-color: #61c642;", "--message-checkbox-color: #61C642;"),
    (BASE, "--message-out-time-color: rgba(255, 255, 255, .6);", "--message-out-time-color: rgba(255, 255, 255, .5);"),
    ("src/components/wallet/wallet.module.scss", "linear-gradient(#70a7db, #408acf)", "linear-gradient(#70a7db, #408acf 90%)"),
    (BASE, "  --badge-text-color: #fff;\n  --original-ripple-color", "  --badge-text-color: white;\n  --original-ripple-color"),
    ("src/scss/partials/_button.scss", ".btn-color-primary {\n  background: var(--primary-color);\n  color: #fff;",
     ".btn-color-primary {\n  background: var(--primary-color);\n  color: white;"),
    ("src/scss/partials/_chat.scss", "    color: #fff !important;\n    background-color: var(--primary-color) !important;\n\t\tz-index: 3;",
     "    background-color: var(--primary-color) !important;\n    color: #fff !important;\n\t\tz-index: 3;"),
    ("src/components/popups/starGiftValue.module.scss", "  background: var(--primary-button-color);\n  color: #fff;",
     "  background: var(--primary-button-color);\n  color: white;"),
    ("src/components/wallet/tonConnect/tonConnect.module.scss", "  background-color: var(--primary-color);\n  color: #fff;",
     "  background-color: var(--primary-color);\n  color: white;"),
    ("src/scss/partials/_checkbox.scss", "        stroke: #fff;\n", "        stroke: white;\n"),
    ("src/components/popups/webAppLocationAccess.module.scss", "color: var(--white);", "color: #fff;"),
    (FEATURE_ICON, "  &:global(.background-gradient-stories) {\n",
     "  &:global(.background-gradient-premium) {\n    background: var(--premium-gradient);\n  }\n\n"
     "  &:global(.background-gradient-stories) {\n"),
    (FEATURE_ICON, "&:global(.background-gradient-avatar)", "&:global(.background-gradient-peer)"),
    ("src/scss/partials/_badge.scss", "  &-primary {\n    background-color: var(--primary-color);\n",
     "  &-primary {\n    background: var(--primary-color);\n"),
    ("src/scss/partials/_slider.scss", "        .badge {\n          background-color: var(--primary-color);\n",
     "        .badge {\n          background: var(--primary-color);\n"),
    (CHATLIST, "    background-color: var(--chatlist-status-color);\n  }\n",
     "    background: var(--chatlist-status-color);\n  }\n"),
    (CHATLIST, "          color: rgba(255, 255, 255, .7);", "          color: rgba(255, 255, 255, .6);"),
    (CHATLIST, "          --color: #fff;\n", "          --color: white;\n"),
    # The birthday banner: its strings, what its new code calls, the places
    # it edits, and a way to gifts the edits do not know.
    ("src/lang.ts", "  'SendMessageTitle': 'Send message',\n", "  'SendMessageTitle': 'Send a message',\n"),
    ("src/lang.ts", "  'Suggestion.BirthdayContacts.Today': 'Birthday today',\n",
     "  'Suggestion.BirthdayContacts.Today': 'Today',\n"),
    ("src/components/popups/pickUser.tsx", "export default function showPickUserPopup(options: PopupPickUserOptions) {",
     "export default function showPickUserPopup(options: PickUserOptions) {"),
    ("src/lib/appImManager.ts", "  public async setPeer(options: Partial<ChatSetInnerPeerOptions> = {}, animate?: boolean)",
     "  public async setPeer(options: ChatSetPeerOptions = {}, animate?: boolean)"),
    # The profile's Birthday row: the places it edits.
    (PROFILE, "PeerProfile.Birthday = () => {\n  const context = useContext(PeerProfileContext);\n",
     "PeerProfile.Birthday = () => {\n  const context = usePeerProfile();\n"),
    (PROFILE, "    if(isToday()) {\n      return () => showSendGiftPopup({\n",
     "    if(isToday() && canGift()) {\n      return () => showSendGiftPopup({\n"),
    (BIRTHDAYS, "import showSendGiftPopup from '@components/popups/sendGift';",
     "import showSendGiftPopup from '@components/popups/sendGift/index';"),
    (BIRTHDAYS, "import {toastNew} from '@components/toast';", "import {toastNew, toastError} from '@components/toast';"),
    (BIRTHDAYS, "import {i18n} from '@lib/langPack';", "import {i18n, I18n} from '@lib/langPack';"),
    (BIRTHDAYS, "import {useAppState} from '@stores/appState';", "import {useAppConfig} from '@stores/appState';"),
    (BIRTHDAYS, "import {createEffect, createMemo,", "import {createEffect, createComputed, createMemo,"),
    (BIRTHDAYS, "showSendGiftPopup({peerId, birthday: birthdayPeerIds().has(peerId)});",
     "showSendGiftPopup({peerId, birthday: true});"),
    (BIRTHDAYS, "      prependPeerIds: nearbyContacts().map(({peerId}) => peerId),\n",
     "      prependPeerIds: contacts().map(({peerId}) => peerId),\n"),
    (BIRTHDAYS, "{i18n('Suggestion.BirthdayContacts.Subtitle')}", "{i18n('Suggestion.BirthdayContacts.Gift')}"),
    (BIRTHDAYS, "  const [{appConfig}] = useAppState();", "  const [{appConfig, premium}] = useAppState();"),
    (BIRTHDAYS, "() => !appConfig.premium_purchase_blocked;",
     "() => !appConfig.premium_purchase_blocked && !appConfig.stars_purchase_blocked;"),
    (BIRTHDAYS, "    canLoadBirthdayContacts() &&\n    promoDataLoaded() &&\n",
     "    promoDataLoaded() &&\n    canLoadBirthdayContacts() &&\n"),
    (BIRTHDAYS, "    if(canLoadBirthdayContacts()) void loadContactBirthdays(true);\n",
     "    if(canLoadBirthdayContacts()) void loadContactBirthdays();\n"),
    (BIRTHDAYS, "    if(canLoadBirthdayContacts()) {\n      void loadContactBirthdays();\n",
     "    if(canLoadBirthdayContacts() && !destroyed) {\n      void loadContactBirthdays();\n"),
    (BIRTHDAYS, "    if(!canLoadBirthdayContacts()) {\n", "    if(!canLoadBirthdayContacts() || !promoDataLoaded()) {\n"),
    (BIRTHDAYS, "appGiftsManager.getStarGiftOptions().catch(() => {});", "appGiftsManager.getStarGiftOptions().catch(noop);"),
    (BIRTHDAYS, "toastNew({langPackKey: 'Suggestion.BirthdayContacts.Dismissed'});",
     "toastNew({langPackKey: 'Suggestion.BirthdayContacts.Dismissed', duration: 3000});"),
    (BIRTHDAYS, "  const onDismissed = () => {\n",
     "  const onDismissed = () => {\n    showSendGiftPopup({peerId: rootScope.myId});\n"),
    # Tags of Saved Messages: each gate, the imports the patch adds to, the
    # limit of tags it leaves to the server, a gate it does not know, and the
    # function asked outside the tag gates.
    (CONTEXT_MENU, "      if(this.isTag && !rootScope.premium) {\n", "      if(this.isTag && !rootScope.isPremium) {\n"),
    (CONTEXT_MENU, "          if(!rootScope.premium && tags) {\n", "          if(tags && !rootScope.premium) {\n"),
    (CONTEXT_MENU, patch._GUARD_WITH_PROVIDER, patch._GUARD_WITH_PROVIDER.replace("import ", "import type ", 1)),
    (CONTEXT_MENU, "  private onAddTaskClick = async() => {\n",
     "  private onTagsPromo = () => hotReloadGuard.showPremiumPopup({feature: 'saved_tags'});\n\n  private onAddTaskClick = async() => {\n"),
    (BUBBLES, "        if(!rootScope.premium) {\n          hotReloadGuard.showPremiumPopup({feature: 'saved_tags'});\n",
     "        if(!this.chat.isPremium) {\n          hotReloadGuard.showPremiumPopup({feature: 'saved_tags'});\n"),
    (BUBBLES, "      if(reactionsElement.getType() === ReactionLayoutType.Tag) {\n",
     "      if(reactionsElement.getType() === ReactionLayoutType.Tag && !rootScope.premium) {\n"
     "        hotReloadGuard.showPremiumPopup({feature: 'saved_tags'});\n        return;\n      }\n\n"
     "      if(reactionsElement.getType() === ReactionLayoutType.Tag) {\n"),
    (TOPBAR_SEARCH, "import usePremium from '@stores/premium';\n", "import usePremium from '@stores/premium.ts';\n"),
    (TOPBAR_SEARCH, "  const isPremium = usePremium();\n", "  const isPremium = usePremium() as () => boolean;\n"),
    (TOPBAR_SEARCH, "    const premium = isPremium();\n", "    const premium = isPremium() || false;\n"),
    (TOPBAR_SEARCH, "      if(!isPremium()) {\n        hotReloadGuard.showPremiumPopup({feature: 'saved_tags'});\n",
     "      if(isPremium() === false) {\n        hotReloadGuard.showPremiumPopup({feature: 'saved_tags'});\n"),
    (REACTIONS_MENU, "        rootScope.premium ? 'Reactions.Tag.Description' : 'Reactions.Tag.PremiumHint',\n",
     "        this.premium ? 'Reactions.Tag.Description' : 'Reactions.Tag.PremiumHint',\n"),
    (REACTIONS_MENU, patch._GUARD, patch._GUARD.replace("import ", "import type ", 1)),
    ("src/lib/appManagers/apiManagerMethods.ts",
     "        reactions: ['reactions_user_max_default', 'reactions_user_max_premium'],\n",
     "        reactions: 'reactions_user_max_premium',\n"),
    ("src/lib/appManagers/appReactionsManager.ts", "      this.apiManager.getLimit('reactions'),\n",
     "      this.apiManager.getLimit('reactions', true),\n"),
    ("src/components/chat/chat.ts", "  public async sendReaction(options: SendReactionOptions) {\n",
     "  public async sendReaction(options: SendReactionOptions) {\n    savedTagsAvailable();\n"),
    # Links: the host check, the hosts it is given, the links the client
    # makes, the invite link row, and a Telegram link host the patch does
    # not know (a new one, one more of a kept kind).
    (MATCH_HOST, "  const match = matchUrlHost(url, TELEGRAM_LINK_HOSTS);\n",
     "  const match = matchUrlHost(url, TELEGRAM_LINK_HOSTS, true);\n"),
    (MATCH_HOST, "const TELEGRAM_LINK_HOSTS = ['t.me', 'telegram.me'];", "const TELEGRAM_LINK_HOSTS = ['t.me'];"),
    ("src/helpers/addAnchorListener.ts", "const match = matchTelegramUrlHost(u);", "const match = matchUrlHost(u, ['t.me']);"),
    ("src/helpers/copyContact.ts", "export const T_ME = 'https://t.me/';", "export const T_ME = 'https://t.me/' as const;"),
    ("src/components/popups/myQrCode/link.ts", "  return `https://t.me/+${phone}`;", "  return 'https://t.me/+' + phone;"),
    ("src/lib/appManagers/utils/stories/storyLink.ts", "  return `https://t.me/${username}/s/${storyId}`;",
     "  return `https://t.me/s/${username}/${storyId}`;"),
    ("src/components/sidebarLeft/tabs/businessChatLinks.tsx", "copyLink('https://t.me/' + path)", "copyLink(`https://t.me/${path}`)"),
    # The links of the new version: a tg: link of each kind the patch turns
    # into plm:, a new tg: link it does not know, and a telegram.org host.
    ("src/lib/richTextProcessor/wrapRichText.ts", "'tg://sendgrams?to='", "'tg://sendgrams/?to='"),
    ("src/helpers/string/normalizeLinkUrl.ts", "url.protocol === 'tg:'", "url.protocol == 'tg:'"),
    ("src/components/chat/inputEditor/richMessage.ts", "url.startsWith('tg://user?')", "url.startsWith('tg://user/?')"),
    ("src/lib/appManagers/utils/richMessage/validateRichMessage.ts", "'tg:', 'tonsite:'", "'tonsite:', 'tg:'"),
    ("src/lib/internalLinkProcessor.ts", "element.href.replace(/^tg:(?:", "element.href.replace(/^(?:tg):(?:"),
    ("src/helpers/copyContact.ts", "export function copyPeerId(", "const FAQ = 'https://telegram.org/faq';\nexport function copyPeerId("),
    # The help section of Settings.
    (patch.SETTINGS, "import askQuestion, {openTelegramFaq} from '@components/askQuestion';",
     "import askQuestion, {openTelegramFaq as openFaq} from '@components/askQuestion';"),
    (patch.SETTINGS, "{/* help, the way tdesktop ends its main settings */}", "{/* help */}"),
    # Telegram's site on the screens a user reaches.
    ("src/lang.ts", "[Android](https://telegram.org/android)", "[Android](https://telegram.org/apk)"),
    ("src/components/sidebarLeft/tabs/chatAutomation.tsx", "learnMoreAnchor.href = 'https://telegram.org';",
     "learnMoreAnchor.href = 'https://telegram.org/faq';"),
    # What ci/check_bundle.py looks for in the built code.
    ("src/config/modes.ts", "const httpOnly = Modes.http = isFlagOn('http');", "const httpOnly = (Modes.http = isFlagOn('http'));"),
    ("src/config/modes.ts", " && !isFlagOn('noMultipleTransports'),", " && isFlagOn('noMultipleTransports') === false,"),
    # The message about the new version, and where the client reads it from.
    ("public/changelogs/en_2.3.md", "Web K", "Web  K"),
    ("public/changelogs/ru_2.3.md", "Web K", "Web  K"),
    ("src/lib/appManagers/apiUpdatesManager.ts", "fetch(`changelogs/${lang}_", "fetch(`news/${lang}_"),
    (patch.SETTINGS_SEARCH, "{id: 'AppSettingsTab:TelegramFaq', sectionId: 'AppSettingsTab',", "{id: 'AppSettingsTab:Faq', sectionId: 'AppSettingsTab',"),
    (patch.SETTINGS_SEARCH_OPENERS, "export const WALLET_ENTRIES = new Set([", "export const WALLET_ENTRIES =  new Set(["),
    (patch.SETTINGS_SEARCH_REGISTRY, "NON_NAVIGABLE_SECTIONS, WALLET_ENTRIES} from './openers';",
     "WALLET_ENTRIES, NON_NAVIGABLE_SECTIONS} from './openers';"),
    (patch.SETTINGS_SEARCH_REGISTRY, "(isWalletReleased() || !WALLET_ENTRIES.has(entry.id)));\n", "(isWalletReleased() || !WALLET_ENTRIES.has(entry.id)) );\n"),
    ("src/components/chat/bubbleParts/adminLogsResolver/index.tsx", "lines.push(`https://t.me/${action.new_value}`);",
     "lines.push('https://t.me/' + action.new_value);"),
    (PROFILE, "exportedInvite.link.indexOf('t.me/')", "exportedInvite.link.indexOf('/t.me/')"),
    ("src/components/popups/forward.tsx", "    copyTextToClipboard(url);\n", "    copyTextToClipboard(url || 'https://t.me/');\n"),
    ("src/helpers/getWebViewTgLink.ts", "return 'https://t.me/' + ", "return 'https://telegram.me/' && 'https://t.me/' + "),
    # The screens of the login code: the anchors of the edits, what they rely
    # on, and a link to the Telegram app or a string naming Telegram that the
    # patch does not know.
    (patch.LANG_SIGN, "'Login.Code.Resending': 'Requesting a new code...',", "'Login.Code.Resending': 'Requesting a new code…',"),
    (patch.SENT_CODE, "  return sentCode.timeout || 0;\n}\n", "  return sentCode.timeout ?? 0;\n}\n"),
    (patch.AUTH_CODE, "}, 'jolly_roger').then((animation) => {", "}, 'fragment').then((animation) => {"),
    (patch.AUTH_CODE, "key = 'PhoneNumber.Code.Fragment.Info';", "key = 'PhoneNumber.Code.Fragment';"),
    (patch.AUTH_CODE, "    const key = getResendLangKey(sentCode.next_type);\n",
     "    const key = getResendLangKey(sentCode.next_type, sentCode.type);\n"),
    (patch.AUTH_CODE, "          text=\"Login.Next\"\n", "          text=\"Login.Continue\"\n"),
    ("src/lib/lottie/lottieLoader.ts", "  | 'UtyanSearch'\n", "  | 'UtyanSearch2'\n"),
    ("src/pages/cards/SignInCard.tsx", "      const dcs = new Set([1, 2, 3, 4, 5]);\n",
     "      const dcs = new Set([1, 2, 3, 4, 5]);\n      const privacy = 'tg://settings/phone_privacy';\n"),
    (patch.LANG_SIGN, "  'Login.Code.Resending': 'Requesting a new code...',\n",
     "  'Login.Code.Resending': 'Requesting a new code...',\n  'Pluma.Code.OpenTelegram': 'Open Telegram',\n"),
    ("src/global.d.ts", "    | 'WIDGET_RESPONSE_TIMEOUT'\n", "    | 'WIDGET_RESPONSE_TIMEOUT_EXPIRED'\n"),
    (patch.AUTH_CODE, "      resending = false;\n\n      return continueLogin(code, {\n",
     "      resending = false;\n      return continueLogin(code, {\n"),
    (patch.AUTH_CODE, "      console.error('auth.resendCode error:', err);\n", "      console.error('auth.resendCode', err);\n"),
    # No AI message editor: each edit.
    *((rel, old, old.replace(": ", ":  ", 1) if ": " in old else old.replace(" = ", " =  ", 1))
      for rel, old, _ in patch.NO_AI_EDITOR_EDITS),
)


def upstream_files():
    """The files the patch reads, as {path: bytes} of the pinned commit, or
    None without a checkout of it in ./upstream (ci/fetch-upstream.sh)."""
    env = patch.load_env(ROOT / "upstream.env")
    git = ["git", "-C", str(ROOT / "upstream")]
    try:
        head = subprocess.run(git + ["rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    if head != env["UPSTREAM_REF"]:
        return None
    archive = subprocess.run(git + ["archive", "--format=tar", "HEAD", *UPSTREAM_PATHS],
                             capture_output=True, check=True).stdout
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for m in tar.getmembers():
            if m.isfile():
                files[m.name] = tar.extractfile(m).read()
    return files


class RecordingTree(patch.Tree):
    """A tree that remembers what the patch wrote."""

    def __init__(self, root, written):
        super().__init__(root)
        self.written = written

    def write(self, rel, text):
        self.written.add(str(rel))
        super().write(rel, text)

    def write_bytes(self, rel, data):
        self.written.add(str(rel))
        super().write_bytes(rel, data)

    def remove(self, rel):
        self.written.add(str(rel))
        super().remove(rel)


@unittest.skipIf(not os.environ.get("CI") and upstream_files() is None,
                 "no checkout of the pinned upstream (ci/fetch-upstream.sh)")
class UpstreamTest(unittest.TestCase):
    """The patch on the commit upstream.env pins. CI fetches it first, and
    there these tests never skip."""

    @classmethod
    def setUpClass(cls):
        cls.files = upstream_files()
        if cls.files is None:
            raise AssertionError("no checkout of the pinned upstream in ./upstream (ci/fetch-upstream.sh)")
        cls.dir = tempfile.TemporaryDirectory()
        cls.root = pathlib.Path(cls.dir.name)
        for name, data in cls.files.items():
            p = cls.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def setUp(self):
        self.written = set()

    def tearDown(self):
        # Back to the pinned upstream: what the patch or a test wrote.
        for rel in self.written:
            if rel in self.files:
                (self.root / rel).write_bytes(self.files[rel])
            else:
                (self.root / rel).unlink(missing_ok=True)
        self.written.clear()

    def run_patch(self, url="wss://pluma.chat/apiws"):
        c = config(args={"server_url": url})
        tree = RecordingTree(self.root, self.written)
        patch.patch(tree, c)
        patch.verify(tree, c)
        return tree, c

    def test_patch(self):
        tree, c = self.run_patch()
        dc = tree.read(DC)
        self.assertIn("  return 'wss://pluma.chat/apiws';\n", dc)
        self.assertNotIn("dcOptions", dc)
        self.assertIn(f"modulus: '{c.modulus}'", tree.read(RSA))
        self.assertNotIn("testPublicKeysHex", tree.read(RSA))
        app = tree.read(APP)
        self.assertIn("  id: 10004,\n", app)
        self.assertIn("export const BASE_DC_ID = 1;\n", tree.read(patch.BASE_DC))
        self.assertIn("export const MAIN_DOMAINS: string[] = [];\n", app)
        self.assertNotIn("isMainDomain) {", app)
        self.assertNotIn("loadScript(", tree.read("src/lib/telegramMeWebManager.ts"))
        self.assertIn("<title>{{title}}</title>", tree.read("index.html"))
        self.assertIn("title: 'Pluma',", tree.read("vite.config.ts"))
        for rel in ("public/site.webmanifest", "public/site_apple.webmanifest"):
            m = json.loads(tree.read(rel))
            self.assertEqual((m["name"], m["short_name"]), ("Pluma", "Pluma"))
            self.assertNotIn("scope_extensions", m)
            self.assertNotIn("gcm_sender_id", m)
            self.assertNotIn("screenshots", m)
        self.assertEqual(patch.load_env(self.root / ".env.production.local"), patch.TRANSPORT_FLAGS)

        # The brand.
        for rel, _ in patch.ICONS:
            self.assertEqual((self.root / "public" / rel).read_bytes(), (patch.BRAND / "web" / rel).read_bytes())
        self.assertFalse((self.root / "public" / patch.SCREENSHOT[0]).exists())
        index = tree.read("index.html")
        self.assertIn('<g id="logo" fill="none" stroke-linecap="round" style="stroke: var(--primary-text-color)"', index)
        self.assertIn('<path stroke-width="30" stroke-opacity="0.76" d="M180,382 L94.6,372"/>', index)
        self.assertIn('<meta name="msapplication-TileColor" content="#5b7a5e">', index)
        self.assertIn("'Login.Title': 'Sign in to Pluma',", tree.read("src/langSign.ts"))
        lang = tree.read("src/lang.ts")
        for s in ("'AppName': 'Pluma',", "'BoostingStars': 'Pluma Stars',",
                  "'Premium.Boarding.Peer.Title': '[%@](profile) is a subscriber of\\nPluma Premium',",
                  "'TelegramFeaturesUrl': 'https://t.me/TelegramTips',"):
            self.assertIn(s, lang)
        self.assertIn("  return `Pluma Web ${App.version} (${App.build})`;\n", app)
        self.assertNotIn("'ReportBug'", tree.read(SIDEBAR))
        self.assertIn("const url = 'plm://login?token=' +", tree.read("src/pages/cards/SignQRCard.tsx"))
        self.assertIn("url.match(/^plm:(?:\\/\\/)?(.+?)(?:\\?|$)/)", tree.read("src/lib/richTextProcessor/wrapUrl.ts"))
        self.assertIn("const PREFIX = 'plm://settings';", tree.read("src/lib/settingsSearch/link.ts"))
        theme = tree.read(THEME)
        for s in ("'primary-color': '#5b7a5e'", "'primary-color': '#9dbb9f'", "'surface-color': '#131513'",
                  "element.style.setProperty('--on-primary-color',"):
            self.assertIn(s, theme)
        state = tree.read(STATE)
        self.assertIn("accent_color: 0x5B7A5E,\n    message_colors: [0xE3EAE2],\n    outbox_accent_color: 0x5B7A5E,", state)
        self.assertIn("accent_color: 0x9DBB9F,\n    message_colors: [0x2C3A2D],\n    outbox_accent_color: 0xB2CEB4,", state)
        self.assertIn(".btn-color-primary {\n  background: var(--primary-color);\n  color: var(--on-primary-color);",
                      tree.read("src/scss/partials/_button.scss"))
        self.assertNotIn("#fff", tree.read(CHATLIST).split("&.active {", 1)[1].split("\n      }\n", 1)[0])
        # People's identity colours: blue is sage and cyan a teal, the other
        # five stay Telegram's; a dark theme has its own name colours.
        base = tree.read(BASE)
        for s in ('  @include avatar-color("cyan", #5BCBC4, #2C9C98); // pluma\n',
                  '  @include avatar-color("blue", #7FA082, #5B7A5E); // pluma\n',
                  '  @include avatar-color("red", #FF845E, #D45246);\n',
                  '  @include avatar-color("pink", #FF8AAC, #D95574);\n'):
            self.assertIn(s, base)
        colors = tree.read(PEER_COLORS)
        for s in ("const DialogColorsFg: Array<string[]> = [['#CC5049'], ['#D67722'], ['#955CDB'], ['#40A920'], "
                  "['#1F8A80'], ['#4F6E52'], ['#C7508B']];\n",
                  "const DialogColorsFgNight: {[colorId: number]: string[]} = {4: ['#53CCC6'], 5: ['#9DBB9F']};\n",
                  "const _DialogColorsFg = DialogColorsFg.slice();\n",
                  "    _DialogColorsFg.map((colors, colorId) => (isNight && DialogColorsFgNight[colorId]) || colors),\n",
                  "  if(isNight) {\n    newColors = replaceColors(newColors, peerColorOptions, true);\n"):
            self.assertIn(s, colors)
        for rel in (ARCHIVE, FEATURE_ICON):
            self.assertIn("background: linear-gradient(var(--peer-avatar-blue-top), var(--peer-avatar-blue-bottom));",
                          tree.read(rel))
        # The feature icon: the glyph is dark on the dark theme's accent and
        # white on its gradients, as on letter avatars.
        icon = tree.read(FEATURE_ICON)
        self.assertIn("  background-color: var(--primary-color);\n\n  color: var(--on-primary-color);\n", icon)
        for gradient in ("avatar", "archive", "stories"):
            self.assertIn(f"  &:global(.background-gradient-{gradient}) {{\n"
                          "    color: white; // pluma: a gradient, not the accent fill\n", icon)

        # The birthday banner: shown without Premium for sale, its tap opens
        # the chat or the list of today's birthdays, no gift anywhere.
        birthdays = tree.read(BIRTHDAYS)
        for s in ("import showPickUserPopup from '@components/popups/pickUser';\n",
                  "import appImManager from '@lib/appImManager';\n",
                  "  const canShowBirthdayContacts = () => (\n    promoDataLoaded() &&\n"
                  "    !dismissedSuggestions().has(BIRTHDAY_CONTACTS_TODAY_SUGGESTION_KEY)\n",
                  "  onMount(() => {\n    void loadContactBirthdays();\n  });\n",
                  "      openChat(contacts()[0].peerId);\n",
                  "    appImManager.setPeer({peerId});\n",
                  "    const todayPeerIds = contacts().map(({peerId}) => peerId);\n",
                  "      titleLangKey: 'SendMessageTitle',\n      peerType: ['custom'],\n",
                  "getMoreCustom: async() => ({result: todayPeerIds, isEnd: true}),",
                  "      onSelect: ([{peerId}]) => openChat(peerId)\n",
                  "<PendingSuggestion.Subtitle>{i18n('SendMessageTitle')}</PendingSuggestion.Subtitle>",
                  # Closing it stays as upstream has it.
                  "closable={props.onDismiss}",
                  "    rootScope.managers.appPromoManager.dismissSuggestion(BIRTHDAY_CONTACTS_TODAY_SUGGESTION_KEY);\n"):
            self.assertIn(s, birthdays)
        for s in ("Gift", "premium_purchase_blocked", "appConfig", "toastNew", "useAppState", "nearbyContacts",
                  "canLoadBirthdayContacts", "createEffect"):
            self.assertNotIn(s, birthdays)
        self.assertNotIn("setInnerPeer", birthdays)
        # The profile's Birthday row: a gift only while Premium is for sale.
        profile = tree.read(PROFILE)
        for s in ("PeerProfile.Birthday = () => {\n  const context = useContext(PeerProfileContext);\n"
                  "  const appConfig = useAppConfig();\n",
                  "    if(isToday() && !appConfig.premium_purchase_blocked) {\n"
                  "      return () => showSendGiftPopup({\n"):
            self.assertIn(s, profile)

        # Tags of Saved Messages: every tag gate asks savedTagsAvailable,
        # which is true; the other Premium checks of these files stay.
        self.assertIn("export default function savedTagsAvailable() {\n  return true;\n}\n", tree.read(SAVED_TAGS))
        imp = "import savedTagsAvailable from '@appManagers/utils/reactions/savedTagsAvailable';\n"
        for rel in (CONTEXT_MENU, BUBBLES, TOPBAR_SEARCH, REACTIONS_MENU):
            self.assertEqual(tree.read(rel).count(imp), 1, rel)
        menu = tree.read(CONTEXT_MENU)
        for s in ("      if(this.isTag && !savedTagsAvailable()) {\n",
                  "          if(!savedTagsAvailable() && tags) {\n",
                  "  private onAddTaskClick = async() => {\n    if(!rootScope.premium) {\n"):
            self.assertIn(s, menu)
        self.assertIn("        if(!savedTagsAvailable()) {\n          hotReloadGuard.showPremiumPopup({feature: 'saved_tags'});\n",
                      tree.read(BUBBLES))
        search = tree.read(TOPBAR_SEARCH)
        for s in ("    const premium = savedTagsAvailable();\n",
                  "      if(!savedTagsAvailable()) {\n        hotReloadGuard.showPremiumPopup({feature: 'saved_tags'});\n"):
            self.assertIn(s, search)
        for s in ("isPremium", "usePremium"):
            self.assertNotIn(s, search)
        self.assertIn("        savedTagsAvailable() ? 'Reactions.Tag.Description' : 'Reactions.Tag.PremiumHint',\n",
                      tree.read(REACTIONS_MENU))
        # How many tags a message takes stays the server's limit.
        self.assertIn("      this.apiManager.getLimit('reactions'),\n",
                      tree.read("src/lib/appManagers/appReactionsManager.ts"))
        users = [rel for rel in tree.sources() if "savedTagsAvailable" in tree.read(rel)]
        self.assertEqual(sorted(users), sorted([SAVED_TAGS, CONTEXT_MENU, BUBBLES, TOPBAR_SEARCH, REACTIONS_MENU]))

        # Links: pluma.chat is a link host of the app, its exact host only,
        # beside t.me and telegram.me; the links the client makes are on it.
        match = tree.read(MATCH_HOST)
        for s in ("export const PLUMA_LINK_HOST = 'pluma.chat';\n",
                  "  if(matchUrlHost(url, [PLUMA_LINK_HOST])?.subdomain === '') {\n"
                  "    // pluma: the site's own pages (its root, its sections, its files) open in the browser\n"
                  "    const first = url.pathname.split('/')[1].toLowerCase();\n"
                  "    if(!first || PLUMA_SITE_PATHS.has(first)) {\n      return;\n    }\n\n"
                  "    return {prefix: undefined};\n  }\n\n"
                  "  const match = matchUrlHost(url, TELEGRAM_LINK_HOSTS);\n",
                  "const TELEGRAM_LINK_HOSTS = ['t.me', 'telegram.me'];\n"):
            self.assertIn(s, match)
        # The pages of the site pluma.chat open in the browser: the same list
        # as the other clients have.
        self.assertIn("const PLUMA_SITE_PATHS = new Set(['iphone', 'ipad', 'android', 'mac', 'windows', 'linux', "
                      "'web', 'pero', 'app', 'en', 'dl', 'ios', 'collect', 'assets', '_l', '.well-known', "
                      "'favicon.svg', 'og.png', 'apple-touch-icon.png', '404.html', 'progress.json']);\n", match)
        self.assertIn("const T_ME = 'https://pluma.chat/';", tree.read("src/helpers/copyContact.ts"))
        self.assertIn("    let url = 'https://pluma.chat/';\n", menu)
        self.assertIn("  return `https://pluma.chat/+${phone}`;\n", tree.read("src/components/popups/myQrCode/link.ts"))
        self.assertIn("  return `https://pluma.chat/${username}/s/${storyId}`;\n",
                      tree.read("src/lib/appManagers/utils/stories/storyLink.ts"))
        business = tree.read("src/components/sidebarLeft/tabs/businessChatLinks.tsx")
        self.assertIn("copyLink('https://pluma.chat/' + path)", business)
        self.assertIn("a.textContent = 'pluma.chat/' + path;", business)
        # The tg: links of the new version.
        self.assertIn("'plm://sendgrams?to='", tree.read("src/lib/richTextProcessor/wrapRichText.ts"))
        self.assertIn("url.startsWith('plm://user?')", tree.read("src/components/chat/inputEditor/richMessage.ts"))
        self.assertIn("  'plm:',\n", tree.read("src/helpers/string/normalizeLinkUrl.ts"))
        self.assertIn("['http:', 'https:', 'plm:', 'tonsite:']",
                      tree.read("src/lib/appManagers/utils/richMessage/validateRichMessage.ts"))
        self.assertIn("element.href.replace(/^plm:(?:", tree.read("src/lib/internalLinkProcessor.ts"))
        # No help section in Settings or its search; the About text and the
        # version under it stay.
        settings = tree.read(patch.SETTINGS)
        for s in ("openTelegramFaq", "askQuestion", "AskAQuestion"):
            self.assertNotIn(s, settings)
        self.assertIn("<span dir=\"ltr\">{getAppVersionText()}</span>", settings)
        self.assertNotIn("TelegramFaq", tree.read(patch.SETTINGS_SEARCH))
        # No message about the version that names Telegram.
        self.assertFalse(list((tree.root / "public/changelogs").glob(f"*_{c.version}.md")))
        # What Settings hides while Premium cannot be bought is not in its search.
        for key in patch.SETTINGS_SEARCH_SALE_ROWS:
            self.assertIn(f"  'AppSettingsTab:{key}',\n", tree.read(patch.SETTINGS_SEARCH_OPENERS))
        self.assertIn("!SALE_ENTRIES.has(entry.id)", tree.read(patch.SETTINGS_SEARCH_REGISTRY))
        # Round videos have no button of their text, and gifts no entry.
        self.assertIn("    if(false) { // pluma: the server has no transcription to offer\n      wrapRoundVideoBubble({\n",
                      tree.read(BUBBLES))
        self.assertNotIn("id: 'gifts'", tree.read("src/components/popups/myQrCode.tsx"))
        self.assertIn("  return `https://pluma.chat/${username}`;\n", tree.read("src/helpers/qrCode/paintQrCode.ts"))
        self.assertEqual(tree.read("src/components/chat/bubbleParts/adminLogsResolver/index.tsx")
                         .count("pluma.chat/${action."), 4)
        self.assertIn("        url: exportedInvite.link.replace(/^https?:\\/\\//, '')\n", profile)
        self.assertIn("'GroupDescription3': 'Public links such as pluma.chat/title',", lang)
        # Kept: the links turned back into an in-app route, and Telegram's own.
        self.assertIn("element = wrapTelegramUrlToAnchor('t.me/' + username);",
                      tree.read("src/lib/richTextProcessor/wrapRichText.ts"))
        self.assertIn("'https://t.me/giftcode/' + slug", tree.read("src/components/popups/giftLink.tsx"))
        self.assertIn("'EditBot.Buttons.Caption': 'Use [@BotFather](https://t.me/botfather) to manage this bot.',", lang)

    def test_identity_colors(self):
        # A colour is one line of the table: a dark name colour that is the
        # light one needs none of its own.
        key, _, name = patch.IDENTITY_COLORS["blue"][2]
        self.assertEqual(key, "name")
        blue = patch.IDENTITY_COLORS["blue"][:3] + (("dark name", None, name),)
        with mock.patch.dict(patch.IDENTITY_COLORS, {"blue": blue}):
            tree, _ = self.run_patch()
        self.assertIn("const DialogColorsFgNight: {[colorId: number]: string[]} = {4: ['#53CCC6']};\n",
                      tree.read(PEER_COLORS))
        # An identity that is not one of the seven stops the patch.
        self.tearDown()
        with mock.patch.dict(patch.IDENTITY_COLORS, {"teal": patch.IDENTITY_COLORS["cyan"]}), \
                self.assertRaisesRegex(patch.PatchError, "IDENTITY_COLORS: 'teal'"):
            self.run_patch()

    def test_icon_changed(self):
        # An icon upstream replaced is one Pluma's render was not made for.
        rel = "public/assets/img/favicon.ico"
        self.written.add(rel)
        (self.root / rel).write_bytes(self.files[rel] + b"\0")
        with self.assertRaisesRegex(patch.PatchError, "favicon.ico"):
            self.run_patch()

    def test_dev_server(self):
        tree, _ = self.run_patch("ws://localhost:11443/apiws")
        self.assertIn("  return 'ws://localhost:11443/apiws';\n", tree.read(DC))

    def test_damage(self):
        for rel, old, new in DAMAGE:
            with self.subTest(rel=rel, old=old[:60]):
                self.tearDown()
                text = self.files[rel].decode("utf-8")
                self.assertIn(old, text, "the damage does not apply to the pinned upstream")
                self.written.add(rel)
                (self.root / rel).write_text(text.replace(old, new), encoding="utf-8")
                with self.assertRaises(patch.PatchError) as e:
                    self.run_patch()
                self.assertIn(pathlib.PurePath(rel).name, str(e.exception))

    def test_no_gift_entries(self):
        tree, _ = self.run_patch()
        self.assertIn("const hasGift = false;", tree.read("src/components/chat/input.ts"))
        self.assertNotIn("hasGift = good", tree.read("src/components/chat/input.ts"))
        links = tree.read("src/lib/internalLinkProcessor.ts")
        self.assertNotIn("return showSendGiftPicker();", links)
        self.assertNotIn("return showSendGiftPopup(", links)

    def test_no_way_to_an_emoji_status(self):
        tree, _ = self.run_patch()
        web_app = tree.read("src/components/webApp.tsx")
        self.assertIn("if(true) { // pluma: the server does not serve account.updateEmojiStatus\n"
                      "      telegramWebView.dispatchWebViewEvent('emoji_status_failed', {error: 'SERVER_ERROR'});\n", web_app)
        self.assertNotIn("bot_can_manage_emoji_status) {", web_app)
        self.assertNotIn("feature: 'emoji_status'", tree.read("src/lib/internalLinkProcessor.ts"))

    def test_no_telegram_site_on_screens(self):
        tree, _ = self.run_patch()
        lang = tree.read("src/lang.ts")
        self.assertIn("'ChatList.Main.EmptyPlaceholder.SubtitleNoContacts': "
                      "'Use Pluma app on your Android or iOS device to sync your contacts',", lang)
        self.assertIn("respond to the messages you receive.',\n", lang)
        automation = tree.read("src/components/sidebarLeft/tabs/chatAutomation.tsx")
        self.assertNotIn("telegram.org", automation)
        self.assertNotIn("learnMoreAnchor", automation)

    def test_premium_stickers(self):
        tree, _ = self.run_patch()
        self.assertIn("export default function premiumStickersAvailable() {\n  return true;\n}\n", tree.read(patch.PREMIUM_STICKERS))
        for rel, _, new in patch.PREMIUM_STICKER_GATES:
            with self.subTest(rel=rel):
                self.assertIn(new, tree.read(rel))
                self.assertEqual(tree.read(rel).count(patch.PREMIUM_STICKERS_IMPORT), 1)
        # Only the gates and the file of the function know it.
        users = [rel for rel in tree.sources() if "premiumStickersAvailable" in tree.read(rel)]
        self.assertEqual(sorted(users), sorted([patch.PREMIUM_STICKERS, *[rel for rel, _, _ in patch.PREMIUM_STICKER_GATES]]))
        # The Premium effects of the send menu stay Premium's.
        self.assertIn("if(!rootScope.premium && !reactionsMenu.freeCustomEmoji.has(stickerDocId)) {",
                      tree.read("src/components/chat/sendContextMenu.ts"))

    def test_premium_stickers_verify(self):
        tree, c = self.run_patch()
        for rel, old, new in patch.PREMIUM_STICKER_GATES:
            with self.subTest(rel=rel):
                text = tree.read(rel)
                self.written.add(rel)
                (self.root / rel).write_text(text.replace(new, old), encoding="utf-8")
                with self.assertRaisesRegex(patch.PatchError, rel):
                    patch.verify(tree, c)
                (self.root / rel).write_text(text, encoding="utf-8")
        text = tree.read(patch.PREMIUM_STICKERS)
        (self.root / patch.PREMIUM_STICKERS).write_text(text.replace("return true", "return false"), encoding="utf-8")
        with self.assertRaisesRegex(patch.PatchError, patch.PREMIUM_STICKERS):
            patch.verify(tree, c)
        (self.root / patch.PREMIUM_STICKERS).write_text(text, encoding="utf-8")

    def test_login_code_screens(self):
        tree, _ = self.run_patch()
        lang = tree.read(patch.LANG_SIGN)
        # The real Telegram in Pluma's strings; the rest is renamed.
        self.assertIn("  'Pluma.Code.SentTelegram': '**Check Telegram**\\nWe\\'ve sent the code for **%s** to your "
                      "Telegram, in a message from the Pluma account.',\n", lang)
        self.assertIn("  'Pluma.Code.NotDelivered': '**Code didn\\'t reach Telegram**\\nThe code for **%s** didn\\'t "
                      "reach your Telegram. Let Telegram find you by your number: **Settings → Privacy and Security → "
                      "Phone Number → Who can find me by my number? → Everybody**.\\n\\nNo Telegram? Ask the "
                      "administrator for the code and enter it here.',\n", lang)
        for line in ("  'Pluma.Code.OpenTelegram': 'Open Telegram',", "  'Pluma.Code.NotReceived': '[Didn\\'t get the code?]()',",
                     "  'Pluma.Code.OpenTelegramSettings': 'Open Telegram settings',",
                     "  'Pluma.Code.SendAgainIn': 'Send again in %s',", "  'Pluma.Code.SendAgain': '[Send again]()',",
                     "  'Pluma.Code.Sending': 'Sending…',", "  'Pluma.Code.AskAdministrator': 'Ask the administrator',",
                     "  'Pluma.Code.AskAdministratorText': 'Ask the Pluma administrator for your code and enter it here.',",
                     "  'Login.Code.SentInApp': 'We have sent you a message in Pluma\\nwith the code.',",
                     "  'Login.Title': 'Sign in to Pluma',"):
            self.assertIn(line + "\n", lang)
        card = tree.read(patch.AUTH_CODE)
        self.assertIn("const TELEGRAM_CHAT_LINK = /^tg:\\/\\/resolve\\?domain=\\w+$/;\n", card)
        self.assertIn("const TELEGRAM_PHONE_PRIVACY_LINK = 'tg://settings/phone_privacy';\n", card)
        self.assertIn("        button = {url: TELEGRAM_PHONE_PRIVACY_LINK, text: 'Pluma.Code.OpenTelegramSettings'};\n", card)
        self.assertIn("          button = {url: type.url, text: 'Pluma.Code.OpenTelegram'};\n", card)
        self.assertIn("      }, 'UtyanSearch').then((animation) => {\n", card)
        self.assertNotIn("jolly_roger", card)
        # The errors of a resend: the expired code back to the number, the
        # administrator's code with the row gone, a flood wait held back to its
        # end; and no answer applied once the card has gone.
        self.assertIn("    if(err.type === 'PHONE_CODE_EXPIRED') {\n"
                      "      toastNew({langPackKey: 'PHONE_CODE_EXPIRED'});\n"
                      "      navigate({name: 'signIn'});\n", card)
        self.assertIn("      sentCode = {...sentCode, next_type: undefined};\n"
                      "      persistSentCode();\n"
                      "      updateResend();\n"
                      "      showSimpleConfirmationPopup({\n"
                      "        titleLangKey: 'Pluma.Code.AskAdministrator',\n"
                      "        descriptionLangKey: 'Pluma.Code.AskAdministratorText',\n", card)
        self.assertIn("      sentCode.resend_deadline = tsNow(true) + floodWait.waitTime;\n", card)
        self.assertIn("      if(handlePlumaResendError(err)) {\n        return;\n      }\n\n"
                      "      console.error('auth.resendCode error:', err);\n", card)
        self.assertIn("      resending = false;\n"
                      "      // pluma: an answer that comes after the card has gone is dropped, as its error is: applied, it\n"
                      "      // would store the code card's state again and start a countdown that nothing stops\n"
                      "      if(isGone()) {\n        return;\n      }\n\n"
                      "      return continueLogin(code, {\n", card)
        self.assertIn("    | 'SEND_CODE_UNAVAILABLE'\n", tree.read("src/global.d.ts"))
        self.assertIn("export function getPlumaResendLangKeys(sentCode: SentCode)", tree.read(patch.SENT_CODE))

    def test_login_code_screens_verify(self):
        tree, c = self.run_patch()
        # Each edit, undone.
        for rel, old, new in patch.LOGIN_CODE_EDITS:
            with self.subTest(rel=rel, new=new[:60]):
                text = tree.read(rel)
                (self.root / rel).write_text(text.replace(new, old), encoding="utf-8")
                with self.assertRaisesRegex(patch.PatchError, rel):
                    patch.verify(tree, c)
                (self.root / rel).write_text(text, encoding="utf-8")
        card = tree.read(patch.AUTH_CODE)
        lang = tree.read(patch.LANG_SIGN)
        for rel, text, damaged, error in (
            # A Telegram app's link twice, and one more of them.
            (patch.AUTH_CODE, card, card + "const again = 'tg://settings/phone_privacy';\n", "the Telegram app's link"),
            (patch.AUTH_CODE, card, card + "const chat = 'tg://resolve?domain=';\n", "a tg: link"),
            # Fragment's sticker back.
            (patch.AUTH_CODE, card, card + "const sticker = 'jolly_roger';\n", "jolly_roger"),
            # One of Pluma's strings twice, and another one naming Telegram.
            (patch.LANG_SIGN, lang, lang.replace(patch.LOGIN_CODE_STRING_LINES[-1] + "\n",
                                                 patch.LOGIN_CODE_STRING_LINES[-1] + "\n  'Pluma.Code.OpenTelegram': 'Open Telegram',\n"),
             "Pluma.Code.OpenTelegram"),
            (patch.LANG_SIGN, lang, lang.replace("'Open Telegram settings'", "'Open Telegram settings now'"), "still says Telegram"),
        ):
            with self.subTest(error=error):
                (self.root / rel).write_text(damaged, encoding="utf-8")
                with self.assertRaisesRegex(patch.PatchError, error):
                    patch.verify(tree, c)
                (self.root / rel).write_text(text, encoding="utf-8")

    def test_saved_tags_file_of_upstream(self):
        self.written.add(SAVED_TAGS)
        (self.root / SAVED_TAGS).write_text("export default function savedTagsAvailable() {\n  return false;\n}\n")
        with self.assertRaisesRegex(patch.PatchError, "savedTagsAvailable.ts"):
            self.run_patch()

    def test_env_file_of_upstream(self):
        self.written.add(".env.production.local")
        (self.root / ".env.production.local").write_text("VITE_MTPROTO_HAS_HTTP=1\n")
        with self.assertRaisesRegex(patch.PatchError, r"\.env\.production\.local"):
            self.run_patch()


# --- the bundle ---------------------------------------------------------------


class BundleTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.site = pathlib.Path(self.dir.name)
        self.record = config().record()
        url, modulus, api_hash = self.record["server_url"], self.record["modulus"], self.record["api_hash"]
        self.write("index.html", "<!DOCTYPE html><html><head><title>Pluma</title></head></html>")
        for name in check_bundle.MANIFESTS:
            self.write(name, json.dumps({"name": "Pluma", "short_name": "Pluma"}))
        self.write("index.worker-abc.js",
                   f"function Re(e){{return Le(e),`{url}`}}var k=[{{modulus:`{modulus}`,exponent:`010001`}}];"
                   f"var s={{API:{{}},layer:233}};var a={{id:10004,hash:`{api_hash}`}};"
                   "var m={multipleTransports:!1};var t=`https://t.me/`+n;"
                   # What stays with the transport off: the flags' names and the settings tab.
                   "var f=[`http`,`noMultipleTransports`];var w=b(`http`)?`http`:b(`noMultipleTransports`)?`websocket`:`auto`;"
                   "var h=u.startsWith(`http`);"
                   "var l={\"Login.Title\":`Sign in to Pluma`};"
                   "var q=`plm://login?token=`+o;")
        self.write("index.worker-abc.js.map", json.dumps({"sourcesContent": ["// see https://web.telegram.org/a/"]}))
        self.write("assets/img/logo.png", b"\x89PNG\r\n\x1a\n\x00\x01")
        self.write("version", "2.3 (686)\n")
        for rel, _ in patch.ICONS:
            self.write(rel, (patch.BRAND / "web" / rel).read_bytes())

    def tearDown(self):
        self.dir.cleanup()

    def write(self, rel, data):
        p = self.site / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, str):
            data = data.encode()
        p.write_bytes(data)

    def check(self, target="server"):
        return check_bundle.check(self.site, self.record, target)

    def test_good(self):
        self.assertEqual(self.check(), 7 + len(patch.ICONS))

    def test_rejects(self):
        url = self.record["server_url"]
        for rel, data in (
            ("a.js.map", json.dumps({"sourcesContent": ["{id: 1, host: '149.154.175.50', port: 80}"]})),
            ("b.js", "var u=`wss://${a}ws${d}.web.telegram.org/${p}`;"),
            ("c.js", f"var k=`{TWEB_PROD_MODULUS}`;"),
            ("d.wasm", b"\x00asm\x01\x00\x00\x00 2001:b28:f23f:f005::a "),
            ("e.js", f"var u=`{url}`,v=`wss://other.example/apiws`;"),
            ("f.js", "var m={multipleTransports:!z(`noMultipleTransports`)};"),
            ("f2.js", 'var m={multipleTransports:!(z("noMultipleTransports")||q.has("noMultipleTransports"))};'),
            ("g.js", "(m.http=z(`http`))&&(m.multipleTransports=!1);"),
            ("g2.js", "const a=m.http=z('http');"),
            ("site.webmanifest", json.dumps({"name": "Telegram Web", "short_name": "Telegram Web"})),
            ("index.html", "<title>Telegram Web</title>"),
            ("changelogs/en_2.3.md", "Lock Telegram with a passcode."),
            ("site_apple.webmanifest", "{"),
            ("assets/img/favicon.ico", b"\x00\x00\x01\x00\x01\x00"),
            (patch.SCREENSHOT[0], b"\xff\xd8\xff\xe0"),
            ("h.js", "var l={\"Login.Title\":`Sign in to Telegram`};"),
            ("i.js", "var q=`tg://login?token=`+o;"),
        ):
            with self.subTest(rel=rel):
                self.tearDown()
                self.setUp()
                self.write(rel, data)
                with self.assertRaises(patch.PatchError):
                    self.check()

    def test_rejects_missing(self):
        code = (self.site / "index.worker-abc.js").read_text()
        for gone in (self.record["server_url"], self.record["modulus"], self.record["api_hash"], "layer:233",
                     "Sign in to Pluma",
                     "plm://login?token="):
            with self.subTest(gone=gone[:30]):
                self.write("index.worker-abc.js", code.replace(gone, "x"))
                with self.assertRaises(patch.PatchError):
                    self.check()
        self.write("index.worker-abc.js", code)
        (self.site / patch.ICONS[0][0]).unlink()
        with self.assertRaises(patch.PatchError):
            self.check()
        self.write(patch.ICONS[0][0], (patch.BRAND / "web" / patch.ICONS[0][0]).read_bytes())
        (self.site / "index.html").unlink()
        with self.assertRaises(patch.PatchError):
            self.check()

    def test_rejects_other_target(self):
        with self.assertRaisesRegex(patch.PatchError, "server build, not dev"):
            self.check("dev")

    def test_rejects_empty(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(patch.PatchError):
            check_bundle.check(d, self.record, "server")


class PremiumForEveryoneTest(unittest.TestCase):
    # The upstream files, made of the texts the edits expect.
    def tree(self, root, edits=patch.PREMIUM_FOR_EVERYONE_EDITS):
        (root / "src/lib/mtproto").mkdir(parents=True, exist_ok=True)
        (root / "src/lib/mtproto/dcConfigurator.ts").write_text("")
        files = {}
        for edit in edits:
            rel, old = edit[0], edit[1]
            count = edit[3] if len(edit) > 3 else 1
            files[rel] = files.get(rel, "") + (old + "x\n") * count
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def test_applies(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            with self.assertRaisesRegex(patch.PatchError, "the edit of task 071 is not there"):
                patch.verify_premium_for_everyone(tree)
            patch.premium_for_everyone(tree)
            patch.verify_premium_for_everyone(tree)
            # A second run is refused: nothing is left to edit.
            with self.assertRaises(patch.PatchError):
                patch.premium_for_everyone(tree)

    def test_upstream_changed(self):
        for i, edit in enumerate(patch.PREMIUM_FOR_EVERYONE_EDITS):
            changed = edit[1][:-2] + "~" + edit[1][-1]
            edits = [e if j != i else (edit[0], changed) + tuple(edit[2:]) for j, e in enumerate(patch.PREMIUM_FOR_EVERYONE_EDITS)]
            with self.subTest(edit=i), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d), edits)
                with self.assertRaisesRegex(patch.PatchError, "occurrences"):
                    patch.premium_for_everyone(tree)

    def test_check(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.premium_for_everyone(tree)
            for edit in patch.PREMIUM_FOR_EVERYONE_EDITS:
                rel, old, new = edit[0], edit[1], edit[2]
                patched = tree.read(rel)
                tree.write(rel, patched.replace(new, old))
                with self.subTest(file=rel), self.assertRaisesRegex(patch.PatchError, "the edit of task 071 is not there"):
                    patch.verify_premium_for_everyone(tree)
                tree.write(rel, patched)
            patch.verify_premium_for_everyone(tree)


class NoAiEditorTest(unittest.TestCase):
    # The upstream files, made of the texts the edits expect, with the
    # context's maker and the button's makers where upstream has them.
    def tree(self, root, edits=patch.NO_AI_EDITOR_EDITS):
        (root / "src/lib/mtproto").mkdir(parents=True, exist_ok=True)
        (root / "src/lib/mtproto/dcConfigurator.ts").write_text("")
        files = {patch.AI_CHAT_INPUT: "  public getAiEditorContext() {return createAiEditorContext(this);}\n",
                 "src/components/chat/inputState/createAiEditorContext.ts":
                     "export default function createAiEditorContext(input: ChatInput) {}\n"}
        for rel in patch.AI_BUTTON_USES:
            files[rel] = "<AiEditorButton />\n" if rel.endswith("inputFieldMessage.tsx") else "useAiEditorButton({});\n"
        for rel, old, _ in edits:
            files[rel] = files.get(rel, "") + old + "x\n"
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def sources(self, tree):
        return {rel: tree.read(rel) for rel in tree.sources()}

    def test_applies(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            with self.assertRaisesRegex(patch.PatchError, "the AI editor is offered again"):
                patch.verify_no_ai_editor(self.sources(tree))
            patch.no_ai_editor(tree)
            patch.verify_no_ai_editor(self.sources(tree))
            with self.assertRaises(patch.PatchError):
                patch.no_ai_editor(tree)

    def test_no_field_gets_the_context(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.no_ai_editor(tree)
            self.assertNotIn(".getAiEditorContext(", tree.read(patch.AI_CHAT_INPUT))
            self.assertNotIn("getAiEditorContext", tree.read(patch.AI_NEW_MEDIA))
            self.assertIn("const aiAvailable = false;", tree.read(patch.AI_MARKUP_TOOLTIP))

    def test_upstream_changed(self):
        for i, edit in enumerate(patch.NO_AI_EDITOR_EDITS):
            changed = edit[1][:-2] + "~" + edit[1][-1]
            edits = [e if j != i else (edit[0], changed) + tuple(edit[2:]) for j, e in enumerate(patch.NO_AI_EDITOR_EDITS)]
            with self.subTest(edit=i), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d), edits)
                with self.assertRaisesRegex(patch.PatchError, "occurrences"):
                    patch.no_ai_editor(tree)

    def test_check(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.no_ai_editor(tree)
            for i, (rel, old, new) in enumerate(patch.NO_AI_EDITOR_EDITS):
                patched = tree.read(rel)
                tree.write(rel, patched.replace(new, old))
                with self.subTest(edit=i), self.assertRaisesRegex(patch.PatchError, "the AI editor is offered again"):
                    patch.verify_no_ai_editor(self.sources(tree))
                tree.write(rel, patched)
            patch.verify_no_ai_editor(self.sources(tree))

    def test_another_way_in(self):
        # A field handed the context, or a button made somewhere else; a
        # mention in a comment is not one.
        cases = (
            ("src/components/stories/input.ts", "      ai: chat.input.getAiEditorContext(),\n", "uses of the AI editor's context"),
            ("src/components/popups/other.tsx", "const ai = createAiEditorContext(input);\n", "uses of the AI editor's context"),
            ("src/components/popups/other.tsx", "<AiEditorButton context={ai} />\n", "AI editor buttons"),
            (patch.AI_NEW_MEDIA, "useAiEditorButton({});\n", "AI editor buttons"),
        )
        for rel, added, message in cases:
            with self.subTest(file=rel, added=added), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d))
                patch.no_ai_editor(tree)
                path = pathlib.Path(d) / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                tree.write(rel, (tree.read(rel) if path.exists() else "") + added)
                with self.assertRaisesRegex(patch.PatchError, message):
                    patch.verify_no_ai_editor(self.sources(tree))
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.no_ai_editor(tree)
            tree.write(patch.AI_NEW_MEDIA, tree.read(patch.AI_NEW_MEDIA) + "// ai: chat.input.getAiEditorContext()\n")
            patch.verify_no_ai_editor(self.sources(tree))


if __name__ == "__main__":
    unittest.main()
