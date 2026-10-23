// Signs in to a Pluma stand with the web client, the way a user does
// (e2e/run.sh starts the stand, builds the client for it and serves it): a
// phone on the allowlist, the code pluma-admin issues, sign-up, a message to
// Saved Messages. Then a second browser signs in to the same account and
// finds the message there, which only the server can have given it.
import {test, expect} from '@playwright/test';
import {execFileSync} from 'node:child_process';
import path from 'node:path';

function env(name) {
  const value = process.env[name];
  if(!value) {
    throw new Error(`${name} is not set; run e2e/run.sh`);
  }
  return value;
}

const WEB_URL = env('PLUMA_E2E_URL');
const PHONE = env('PLUMA_E2E_PHONE');
const SERVER_DIR = env('PLUMA_SERVER_DIR');
const SCREENSHOTS = env('PLUMA_E2E_SCREENSHOTS');
const MESSAGE = `Hello from Pluma web, ${new Date().toISOString()}`;

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

// The code for the pending sign-in of the phone, from pluma-admin in the
// stand. It is not logged.
function loginCode() {
  const out = execFileSync('test/e2e/run.sh', ['admin', 'login-code', PHONE], {cwd: SERVER_DIR, encoding: 'utf8'});
  const m = /Login code for \+\d+: (\d+)/.exec(out);
  if(!m) {
    throw new Error('pluma-admin issued no login code');
  }
  return m[1];
}

let shots = 0;

// A step of the scenario, with a screenshot of the page after it (also when
// it fails).
async function step(page, name, body) {
  await test.step(name, async() => {
    let failed = true;
    try {
      await body();
      failed = false;
    } finally {
      const file = `${String(++shots).padStart(2, '0')}-${name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.png`;
      try {
        await page.screenshot({path: path.join(SCREENSHOTS, file)});
      } catch(err) {
        // A failed step reports its own error, not that of its screenshot.
        if(!failed) {
          throw err;
        }
      }
    }
  });
}

// A browser of its own (storage, workers, service worker). Every request it
// makes must stay on this machine: the page's own server and the stand's
// gateway. Anything else is refused and recorded.
async function newBrowser(browser, requests) {
  const context = await browser.newContext();
  await context.route((url) => !LOCAL_HOSTS.has(url.hostname), (route) => {
    requests.foreign.add(route.request().url());
    return route.abort('blockedbyclient');
  });
  context.on('request', (request) => {
    const url = new URL(request.url());
    if(!/^(https?|wss?):$/.test(url.protocol)) {
      return;
    }
    if(LOCAL_HOSTS.has(url.hostname)) {
      requests.local++;
    } else {
      requests.foreign.add(request.url());
    }
  });
  return context;
}

// Opens the client and signs in with the phone; a new account also signs up.
async function signIn(page, {signUp}) {
  await step(page, signUp ? 'Open the client' : 'Open the client again', async() => {
    await page.goto(WEB_URL);
    await expect(page).toHaveTitle('Pluma');
    // A desktop browser starts on the QR code; Pluma signs in by phone.
    const byPhone = page.getByRole('button', {name: /Log in by phone number/});
    const phone = page.locator('.input-field-phone .input-field-input');
    await expect(byPhone.or(phone)).toBeVisible();
    if(await byPhone.isVisible()) {
      await byPhone.click();
    }
    await expect(phone).toBeVisible();
  });

  await step(page, signUp ? 'Enter the phone' : 'Enter the phone again', async() => {
    await page.locator('.input-field-phone .input-field-input').pressSequentially(PHONE, {delay: 30});
    await page.getByRole('button', {name: 'Next'}).click();
    await expect(page.locator('input[autocomplete="one-time-code"]')).toBeAttached();
  });

  await step(page, signUp ? 'Enter the login code' : 'Enter the login code again', async() => {
    const code = page.locator('input[autocomplete="one-time-code"]');
    await code.focus();
    await page.keyboard.type(loginCode(), {delay: 50});
    if(signUp) {
      await expect(page.locator('.input-field', {hasText: 'First name'})).toBeVisible();
    }
  });

  if(signUp) {
    await step(page, 'Sign up', async() => {
      await page.locator('.input-field', {hasText: 'First name'}).locator('.input-field-input').pressSequentially('Pluma');
      await page.locator('.input-field', {hasText: 'Last name'}).locator('.input-field-input').pressSequentially('Web');
      await page.getByRole('button', {name: 'Start Messaging'}).click();
    });
  }

  await step(page, signUp ? 'Signed in' : 'Signed in again', async() => {
    await expect(page.locator('#page-chats')).toBeVisible({timeout: 60_000});
    await expect(page.locator('.left-sidebar-burger')).toBeVisible();
  });
}

async function openSavedMessages(page) {
  await page.locator('.left-sidebar-burger').click();
  await page.locator('.btn-menu-item', {hasText: 'Saved Messages'}).click();
  await expect(page.locator('#column-center .chat-info .peer-title', {hasText: 'Saved Messages'}).first()).toBeVisible();
}

test('sign in, sign up and keep a message in Saved Messages', async({browser}) => {
  const requests = {local: 0, foreign: new Set()};

  const first = await newBrowser(browser, requests);
  const page = await first.newPage();
  await signIn(page, {signUp: true});

  await step(page, 'Open Saved Messages', () => openSavedMessages(page));

  await step(page, 'Send a message', async() => {
    const input = page.locator('#column-center .input-message-input:not(.input-field-input-fake)');
    await input.click();
    await page.keyboard.type(MESSAGE);
    await page.keyboard.press('Enter');
    // Sent once the server has answered: the bubble leaves the pending
    // state (is-outgoing, is-sending) for sent or read.
    const bubble = page.locator('.bubble.is-out', {hasText: MESSAGE});
    await expect(bubble).toHaveClass(/\bis-(sent|read)\b/);
    await expect(bubble).not.toHaveClass(/\bis-(outgoing|sending|error)\b/);
  });
  await first.close();

  // A fresh browser has nothing stored: the message can only come from the
  // server.
  const second = await newBrowser(browser, requests);
  const again = await second.newPage();
  await signIn(again, {signUp: false});

  await step(again, 'The message is in Saved Messages', async() => {
    await openSavedMessages(again);
    await expect(again.locator('.bubble', {hasText: MESSAGE})).toBeVisible();
  });
  await second.close();

  console.log(`requests: ${requests.local} to this machine, ${requests.foreign.size} elsewhere`);
  expect([...requests.foreign], 'requests to anything but this machine').toEqual([]);
});
