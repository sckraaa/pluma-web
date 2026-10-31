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
        self.assertEqual((c.app_name, c.api_id, c.layer), ("Pluma", 10004, 228))
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
                  "public/browserconfig.xml", "public/assets/img", "package.json", "index.html", "vite.config.ts")

THEME = "src/helpers/themeController.ts"
STATE = "src/config/state.ts"
SIDEBAR = "src/components/sidebarLeft/index.ts"
BASE = "src/scss/base.scss"
CHATLIST = "src/scss/partials/_chatlist.scss"
BIRTHDAYS = "src/components/sidebarLeft/birthdaySuggestions.tsx"
PROFILE = "src/components/peerProfile.tsx"

DC = "src/lib/mtproto/dcConfigurator.ts"
RSA = "src/lib/mtproto/rsaKeysManager.ts"
APP = "src/config/app.ts"

# Damage to each place the patch edits or checks, as (file, text in the
# pinned upstream, replacement): every one must stop the patch with an error
# that names the file.
DAMAGE = (
    ("src/lib/mtproto/schema.ts", '"layer":228', '"layer":229'),
    ("public/version", "2.2 (676)", "2.3 (700)"),
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
    (APP, "baseDcId: 2 as TrueDcId,", "baseDcId: 4 as TrueDcId,"),
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
    (SIDEBAR, "`Telegram Web${App.suffix} ${App.version}", "`Telegram Web ${App.suffix} ${App.version}"),
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
    # The colours.
    (THEME, "    'primary-color': '#3390ec',\n", "    'primary-color': '#3390EC',\n"),
    (THEME, "    'link-color': '#8774E1', // SCSS resolves", "    'link-color': '#8774E1', // resolves"),
    (THEME, "import {changeColorAccent, ColorRgb, getAccentColor,", "import {changeColorAccent, getAccentColor, ColorRgb,"),
    (THEME, "      hex: newAccentHex,\n      darkenAlpha: 0.04\n", "      hex: newAccentHex,\n      darkenAlpha: 0.05\n"),
    (THEME, "    if(!isNight/*  || true */) {\n", "    if(!isNight) {\n"),
    (THEME, "hex: isNight ? '#ffffff' : rgbaToHexa(", "hex: isNight ? '#fff' : rgbaToHexa("),
    (STATE, "    accent_color: 0x3390ec,\n", "    accent_color: 0x3390EC,\n"),
    (STATE, "        fourth_background_color: 0x4f5bd5\n", "        fourth_background_color: 0x4f5bd6\n"),
    (STATE, "  baseThemeNight: 'hsla(299.142857,", "  baseThemeNight: 'hsla(299.14,"),
    ("src/lib/appManagers/utils/state/loadState.ts", "STATE_INIT, AppTheme} from '@config/state';",
     "STATE_INIT, type AppTheme} from '@config/state';"),
    ("src/lib/appManagers/utils/state/loadState.ts", "        theme.settings = [theme.settings as any];\n",
     "        theme.settings = [theme.settings];\n"),
    ("src/helpers/rowIconBackground.ts", "  blue: '#2196F3',", "  blue: '#2196f3',"),
    (BASE, '@include avatar-color("blue", #5CAFFA, #408ACF);', '@include avatar-color("blue", #5CAFFA, #408ACE);'),
    (BASE, "--avatar-color-story-unread-to: #3da1fd;", "--avatar-color-story-unread-to: #3DA1FD;"),
    (BASE, "--message-checkbox-color: #61c642;", "--message-checkbox-color: #61C642;"),
    (BASE, "--message-out-time-color: rgba(255, 255, 255, .6);", "--message-out-time-color: rgba(255, 255, 255, .5);"),
    (BASE, "  --badge-text-color: #fff;\n  --original-ripple-color", "  --badge-text-color: white;\n  --original-ripple-color"),
    ("src/scss/partials/_button.scss", ".btn-color-primary {\n  background: var(--primary-color);\n  color: #fff;",
     ".btn-color-primary {\n  background: var(--primary-color);\n  color: white;"),
    ("src/scss/partials/_chat.scss", "    color: #fff !important;\n    background-color: var(--primary-color) !important;",
     "    background-color: var(--primary-color) !important;\n    color: #fff !important;"),
    ("src/scss/partials/_checkbox.scss", "        stroke: #fff;\n", "        stroke: white;\n"),
    ("src/components/popups/webAppLocationAccess.module.scss", "color: var(--white);", "color: #fff;"),
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
    (BIRTHDAYS, "// Preview-only: 1 opens the gift popup directly,", "// Preview only: 1 opens the gift popup directly,"),
    (BIRTHDAYS, "showSendGiftPopup({peerId, birthday: birthdayPeerIds().has(peerId)});",
     "showSendGiftPopup({peerId, birthday: true});"),
    (BIRTHDAYS, "      prependPeerIds: nearbyContacts().map(({peerId}) => peerId),\n",
     "      prependPeerIds: contacts().map(({peerId}) => peerId),\n"),
    (BIRTHDAYS, "{i18n('Suggestion.BirthdayContacts.Subtitle')}", "{i18n('Suggestion.BirthdayContacts.Gift')}"),
    (BIRTHDAYS, "  const [{appConfig}] = useAppState();", "  const [{appConfig, premium}] = useAppState();"),
    (BIRTHDAYS, "TEST_BIRTHDAY_CONTACTS || !appConfig.premium_purchase_blocked;",
     "TEST_BIRTHDAY_CONTACTS || !appConfig.premium_purchase_blocked && !appConfig.stars_purchase_blocked;"),
    (BIRTHDAYS, "      canLoadBirthdayContacts() &&\n      promoDataLoaded() &&\n",
     "      promoDataLoaded() &&\n      canLoadBirthdayContacts() &&\n"),
    (BIRTHDAYS, "    if(!canLoadBirthdayContacts()) {\n", "    if(!canLoadBirthdayContacts() || !promoDataLoaded()) {\n"),
    (BIRTHDAYS, "appGiftsManager.getStarGiftOptions().catch(() => {});", "appGiftsManager.getStarGiftOptions().catch(noop);"),
    (BIRTHDAYS, "toastNew({langPackKey: 'Suggestion.BirthdayContacts.Dismissed'});",
     "toastNew({langPackKey: 'Suggestion.BirthdayContacts.Dismissed', duration: 3000});"),
    (BIRTHDAYS, "  const onDismissed = () => {\n",
     "  const onDismissed = () => {\n    showSendGiftPopup({peerId: rootScope.myId});\n"),
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
        self.assertIn("t.textContent = `Pluma Web ${App.version} (${App.build})`;", tree.read(SIDEBAR))
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

        # The birthday banner: shown without Premium for sale, its tap opens
        # the chat or the list of today's birthdays, no gift anywhere.
        birthdays = tree.read(BIRTHDAYS)
        for s in ("import showPickUserPopup from '@components/popups/pickUser';\n",
                  "import appImManager from '@lib/appImManager';\n",
                  "    TEST_BIRTHDAY_CONTACTS || (\n      promoDataLoaded() &&\n"
                  "      !dismissedSuggestions().has(BIRTHDAY_CONTACTS_TODAY_SUGGESTION_KEY)\n",
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
                  "      rootScope.managers.appPromoManager.dismissSuggestion(BIRTHDAY_CONTACTS_TODAY_SUGGESTION_KEY);\n"):
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
                   f"var s={{API:{{}},layer:228}};var a={{id:10004,hash:`{api_hash}`}};"
                   "var m={multipleTransports:!1};var t=`https://t.me/`+n;"
                   "var l={\"Login.Title\":`Sign in to Pluma`};"
                   "var q=`plm://login?token=`+o;")
        self.write("index.worker-abc.js.map", json.dumps({"sourcesContent": ["// see https://web.telegram.org/a/"]}))
        self.write("assets/img/logo.png", b"\x89PNG\r\n\x1a\n\x00\x01")
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
        self.assertEqual(self.check(), 6 + len(patch.ICONS))

    def test_rejects(self):
        url = self.record["server_url"]
        for rel, data in (
            ("a.js.map", json.dumps({"sourcesContent": ["{id: 1, host: '149.154.175.50', port: 80}"]})),
            ("b.js", "var u=`wss://${a}ws${d}.web.telegram.org/${p}`;"),
            ("c.js", f"var k=`{TWEB_PROD_MODULUS}`;"),
            ("d.wasm", b"\x00asm\x01\x00\x00\x00 2001:b28:f23f:f005::a "),
            ("e.js", f"var u=`{url}`,v=`wss://other.example/apiws`;"),
            ("f.js", "var m={multipleTransports:location.search.indexOf(`noMultipleTransports=1`)===-1};"),
            ("g.js", "if(location.search.indexOf(`http=1`)>0){}"),
            ("site.webmanifest", json.dumps({"name": "Telegram Web", "short_name": "Telegram Web"})),
            ("index.html", "<title>Telegram Web</title>"),
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
        for gone in (self.record["server_url"], self.record["modulus"], self.record["api_hash"], "layer:228",
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


if __name__ == "__main__":
    unittest.main()
