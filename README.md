# Pluma for the web

Builds of the official Telegram web client Web K ([morethanwords/tweb](https://github.com/morethanwords/tweb)) for a [Pluma](https://github.com/sckraaa/pluma) server, a self-hosted Telegram-compatible server. This project is not affiliated with Telegram.

The repository holds no copy of the app's code. CI fetches the upstream commit pinned in [`upstream.env`](upstream.env), patches it with [`ci/patch.py`](ci/patch.py) and builds the static site. Every edit must match the upstream source exactly. If an update moves any of the edited places, the build fails; it never quietly produces a client that talks to Telegram.

## Upstream

tweb has no releases, so Pluma pins a commit: [`346844bf`](https://github.com/morethanwords/tweb/commit/346844bf8c002bc1af4de20e78ae1d0df0265019) of 2026-09-22 (version 2.2 (676)), the last one whose MTProto schema (`src/lib/mtproto/schema.ts`) is layer 228, the layer the server speaks.

- Layer 228 came with [`2117883f`](https://github.com/morethanwords/tweb/commit/2117883fd23f2985818cd1ceef41c13efd255225) "Implement ephemeral messages" of 2026-07-28.
- The next commit, [`8197da75`](https://github.com/morethanwords/tweb/commit/8197da75848ea31e79dea31f5d63b57854fcd6d8) "Layer 229" of the same day, moves to layer 229. The 17 `keyboardButton…` constructors give way to one `keyboardButton` with a button type and a new `keyboardInlineButton`; `replyInlineMarkup`, `keyboardButton` and eight more constructors change their ids; 31 constructors and 6 methods are new. A client of that layer sends and expects constructors a layer-228 server does not know.

## What the patch changes

- **Server.** One WebSocket URL, `wss://<host>/apiws`, serves every datacenter, connection type (client, download, upload) and mode (test, premium). The sign-in page does not warm up connections to datacenters 2–5: the server is datacenter 1, the only one.
- **No HTTP transport.** tweb can also carry MTProto over HTTP: as an alternative and, in its default build, as the transport it starts on. The Pluma gateway takes MTProto over WebSocket only, so the build switches tweb's HTTP transport off (`.env.production.local`, which Vite reads after upstream's `.env`), and the patch removes its Telegram addresses. Every connection, uploads included, goes over WebSocket.
- **Server key.** The server's RSA key, as tweb's hex modulus and exponent, replaces Telegram's production and test keys.
- **App identity.** The app uses Pluma's `api_id`/`api_hash` ([`config/app.env`](config/app.env)); the page title and the installed web app are "Pluma".
- **Brand.** Pluma's name, icons, `plm://` links and colours instead of Telegram's ([Branding](#branding)).
- **Birthdays.** The banner above the chat list when contacts have a birthday today shows although Pluma sells no Premium (upstream hides it then), and it leads to the chat, not to a gift: the contact's chat or, when several have a birthday today, the list of them, where the one picked opens their chat, the way a tap in the chat list opens it. It reads "Send message" where upstream's offers a gift ("Send them a Gift."); closing it hides it for the day as upstream does, without the toast that a gift can be sent later in Settings. The client takes the birthdays from `contacts.getBirthdays`, shows the banner once `help.getPromoData` has answered and unless its `dismissed_suggestions` hold `BIRTHDAY_CONTACTS_TODAY`, and tells the server of a close with `help.dismissSuggestion`. The Birthday row of a contact's profile, two taps away, offers a gift on the birthday only while Premium is for sale, as the chat's own gift entry does; otherwise it copies the date, as on any other day.
- **Telegram's own services.** None are contacted (next section).

After the edits, the sources are checked again. After the build, [`ci/check_bundle.py`](ci/check_bundle.py) reads every file of the site, source maps included: the server URL, the server key, the `api_hash`, layer 228, Pluma's icons, "Sign in to Pluma" and the `plm://login` link of the QR code must be there; no Telegram datacenter address, MTProto endpoint, server key or credential may be; the code may open no WebSocket but the server's.

## What the client sends outside the server

| What | Upstream | Pluma |
|---|---|---|
| MTProto over WebSocket | `wss://kws1.web.telegram.org/apiws` and the like, one host per datacenter and connection type | the server's URL |
| MTProto over HTTP | `https://pluto.web.telegram.org/apiw1` and the like, or `http://149.154.x.x/apiw1` | off, addresses removed |
| Session sync with t.me | scripts from `//t.me/_websync_` and `//telegram.me/_websync_` after sign-in | removed |
| Web push | subscription with the push key (VAPID) of upstream's build, or the GCM sender id of its manifest | none until the server sends web push with a key of its own; notifications while the page is open still work |
| Behaviour on web.telegram.org | Telegram's own credentials and push key; visitors from search engines sent to Web A at random | never: no host counts as Telegram's domain |
| Warming up datacenters | handshakes with datacenters 1–5 on the sign-in page | the server only |

tweb looks up no backup datacenter addresses (no DNS or Firebase records, unlike the mobile and desktop apps). The site loads nothing from other hosts: emoji, fonts, animations and sounds are part of it, files come from the server over MTProto. A headless browser that cannot resolve any host name but `localhost` signs in and sends messages ([Checking on a local stand](#checking-on-a-local-stand)).

Left as they are, since they need the user to act:

- links in the interface to telegram.org, t.me, fragment.com, ads.telegram.org and the like (the menu's *Telegram Features* and *Report a Bug* are gone, [Branding](#branding));
- maps.google.com, when the user opens a shared location;
- payments: card details go to the payment provider's tokenizer (Stripe, Smart Glocal) when a user pays an invoice, as in Telegram;
- location-based groups: the user's position goes to nominatim.openstreetmap.org for the address when a user creates one.

## Branding

The client looks like Pluma, not like Telegram:

- **Name.** Every "Telegram" in the built-in English strings becomes the app's name (`PLUMA_APP_NAME`): "Sign in to Pluma", "Pluma Premium", "Pluma Stars". Keys and code identifiers, the mini-app API (`window.Telegram`), storage names and the URLs of Telegram's sites stay. The patch counts the words it renames and the ones it leaves, so a new string upstream stops the build until someone has looked at it. The menu's footer reads "Pluma Web 2.2 (676)" and links to this repository; the menu loses *Telegram Features* (t.me/TelegramTips) and *Report a Bug* (bugs.telegram.org).
- **Icons and logos.** Favicons, app icons, the Safari and Windows tiles, the notification icon and badge and the logo in the middle of the QR code are Pluma's, and Telegram's screenshot leaves the manifests. The sign-in page draws the mark in the theme's text colour.
- **Links.** Pluma's apps use `plm://` where Telegram's use `tg://`, which stays with Telegram's apps installed beside them. The QR code signs in with `plm://login?token=…`; the links the client makes (bot commands, hashtags, settings, instant view, voice chats) are `plm://`, and it opens `plm://` links, not `tg://` ones. A web page cannot register `plm://` with the system (browsers take `web+` schemes only), so that is the desktop and mobile apps' part.
- **Colours.** The default light and dark themes are "graphite and sage": accent `#5B7A5E` and `#9DBB9F`, outgoing bubbles `#E3EAE2` and `#2C3A2D` (Web K draws no gradient), sage wallpapers, and dark text on the light accent of the dark theme. Themes a browser saved with an earlier build switch from Telegram's defaults to these. The *Day* and *Dark Blue* themes and the accent presets a user picks stay as upstream has them.

The assets come from the owner's brand kit. [`brand/src`](brand/src) holds its SVGs and two derived from the mark (a tight favicon and the QR code's logo); [`brand/web`](brand/web) holds the files rendered from them, at the paths of upstream's `public/`. The patch copies them over upstream's files, each checked by its SHA-256, and `ci/check_bundle.py` finds them in the site. After changing an SVG, render them again (rsvg-convert of librsvg and ImageMagick 7) and commit what changed:

```sh
brand/render.sh
```

## Configuration

Set these in the repository's *Settings → Secrets and variables → Actions → Variables*:

| Variable | |
|---|---|
| `PLUMA_SERVER_URL` | The WebSocket URL of the server's MTProto gateway: `wss://<host>/apiws`. A page served over HTTPS can open only `wss://`, so the gateway's WebSocket port (11443) sits behind the TLS proxy of the server's web site. |
| `PLUMA_RSA_PUBLIC_KEY` | The server key as a PKCS#1 PEM: `openssl rsa -in server_pkcs1.key -RSAPublicKey_out` |

Neither is a secret: every copy of the page carries them. The build prints the key's fingerprint (`server key 0x… (…)`), in hex and decimal; the decimal one must be the server's `SERVER_RSA_KEY_FINGERPRINT`.

- **No server variables set.** The build targets the development server of [`config/dev`](config/dev): the server repository's docker compose stack on the machine that runs the browser, at `ws://localhost:11443/apiws`, with the development key.
- **Some but not all set.** The build fails.

## The site

The artifact of a run, `pluma-web-<version>-<target>`, holds `pluma-web-<version>-<target>.tar.gz` (the site) and its SHA-256, and is kept for 30 days:

```sh
gh run download <run id> -n pluma-web-2.2-676-server
shasum -a 256 -c pluma-web-2.2-676-server.tar.gz.sha256
tar -xzf pluma-web-2.2-676-server.tar.gz
```

Unlike an APK, the site is not encrypted: it is static content that the server's web site serves to anyone who opens it, so the artifact discloses nothing the site does not.

Serve the directory as it is, under one path of one HTTPS origin: the page, its workers and its service worker must come from the same place. Serving it is the server's business, with the TLS proxy for `/apiws`.

On `main`, a build for the server is also published as the image `ghcr.io/sckraaa/pluma-web:<commit>`: Caddy with the site in `/srv` ([`ci/site.Dockerfile`](ci/site.Dockerfile)). The server runs it with its own Caddyfile, which adds TLS and the proxy for `/apiws` (`docker-compose.web.yaml` and `docs/ops/deployment.md` of the server repository).

## When it builds

| Trigger | Build | Artifact |
|---|---|---|
| Push to `main` | yes | yes |
| Manual run (*Actions → web → Run workflow*) | yes | yes |
| Pull request | yes | no |
| Weekly canary | the pinned upstream on a fresh runner image | no |

The build typechecks the patched sources and bundles them with Vite, as upstream's own build does. pnpm's package store is kept in the GitHub Actions cache.

Since the repository is public, set *Settings → Actions → General → Fork pull request workflows* to require approval for all outside collaborators.

## Local build

You need Linux or macOS with git, Python 3, Node.js (`NODE_VERSION` of `upstream.env`, which CI uses, or another version the `engines` of upstream's `package.json` allow) and pnpm `PNPM_VERSION`:

```sh
ci/fetch-upstream.sh
ci/configure.sh          # the development server; set SERVER_URL and RSA_PUBLIC_KEY for another
ci/build.sh dev          # out/pluma-web-<version>-dev/ and out/pluma-web-<version>-dev.tar.gz
```

The patch applies to a fresh checkout only: to patch again, fetch the upstream again.

## Checking on a local stand

[`e2e/run.sh`](e2e/run.sh) checks the client against the server the way a user would, in headless Chromium ([Playwright](https://playwright.dev)). It needs a checkout of the server repository, Docker, Go and what the local build needs:

```sh
PLUMA_SERVER_DIR=~/pluma e2e/run.sh
```

It starts the server's e2e stand with its own throwaway key, builds the client for that stand and serves it on `localhost`. A phone on the allowlist signs in with the code from `pluma-admin`, signs up, sends a message to Saved Messages and creates a chat folder; a second browser signs in to the same account and must find the message and the folder, which only the server can have given it. Web K takes the folder limits from the server's `help.getAppConfig`: without them it creates no folder. The browser resolves no host name but `localhost`, and any request elsewhere fails the run. Screenshots of every step go to `.e2e/screenshots`; the stand and the browser's files are removed at the end.

To try the development build by hand, start the stand with the development key and the gateway's WebSocket port on 11443 (`docs/ops/clients.md` of the server repository), serve `out/pluma-web-<version>-dev/` on `localhost` (e.g. `python3 -m http.server --bind 127.0.0.1 --directory out/pluma-web-2.2-676-dev 8080`) and open it.

## Updating the upstream

1. Change `upstream.env` (commit, version, layer, toolchain). The layer must be one the server speaks.
2. Run `ci/fetch-upstream.sh` and `python3 ci/patch_test.py`: the tests apply the patch to the new commit, and their list of damage (`DAMAGE`) names the places the patch edits.
3. Push. Where the upstream moved something, `ci/patch.py` names the file and the text it expected.

## License

GPL-3.0, as the upstream ([LICENSE](LICENSE)).
