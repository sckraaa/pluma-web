// Playwright for e2e/run.sh: one headless Chromium, no retries. Nothing
// outside this machine is reachable from the browser: every host name but
// localhost fails to resolve, so the client must work with the stand alone.
import {defineConfig, devices} from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: 'web.spec.mjs',
  timeout: 5 * 60_000,
  expect: {timeout: 30_000},
  workers: 1,
  retries: 0,
  reporter: [['list']],
  // Traces and test results; e2e/run.sh removes them.
  outputDir: process.env.PLUMA_E2E_OUTPUT,
  use: {
    ...devices['Desktop Chrome'],
    headless: true,
    locale: 'en-US',
    trace: 'off',
    screenshot: 'off',
    video: 'off',
    launchOptions: {
      args: ['--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost']
    }
  }
});
