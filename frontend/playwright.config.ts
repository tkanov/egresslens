import { defineConfig } from '@playwright/test'

// Two projects because the two specs want opposite things. `smoke` is the merge
// gate: small viewport, no video, no artifacts unless it fails. `demo` is the
// recorder behind `npm run demo:record`, which needs the large viewport and
// video that make a usable screen capture.
//
// `npm run test:e2e` still runs both. CI runs --project=smoke, because the demo
// spec depends on demo-output/ from a real Docker capture and cannot run without
// one.
export default defineConfig({
  testDir: './tests',
  timeout: 120_000,
  expect: {
    timeout: 10_000,
  },
  fullyParallel: false,
  // A smoke failure on CI is usually a real break, but retrying once
  // distinguishes that from a server that had not finished starting.
  retries: process.env.CI ? 1 : 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    // localhost, not 127.0.0.1. Vite binds to whatever `localhost` resolves to,
    // which on a machine that prefers IPv6 is [::1] only -- so an IPv4 literal
    // here never connects and the webServer URL check below times out waiting
    // for a server that is already up. Using the same name for both ends makes
    // them agree whichever family wins.
    baseURL: 'http://localhost:5173',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    deviceScaleFactor: 1,
  },
  projects: [
    {
      name: 'smoke',
      testMatch: /report-flow\.spec\.ts/,
      use: {
        browserName: 'chromium',
        viewport: { width: 1280, height: 900 },
        video: 'off',
      },
    },
    {
      name: 'demo',
      testMatch: /demo-recording\.spec\.ts/,
      use: {
        browserName: 'chromium',
        viewport: { width: 2560, height: 1440 },
        video: {
          mode: 'on',
          size: { width: 2560, height: 1440 },
        },
      },
    },
  ],
  // Started here rather than in the workflow so `npm run test:e2e` behaves the
  // same locally as on CI. reuseExistingServer keeps the documented demo flow
  // working, where both servers are already up by hand (see docs/demo.md).
  webServer: [
    {
      command: 'python -m uvicorn app.main:app --port 8000',
      cwd: '../backend',
      url: 'http://127.0.0.1:8000/health',
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
      stdout: 'pipe',
      stderr: 'pipe',
    },
    {
      command: 'npm run dev',
      url: 'http://localhost:5173',
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
    },
  ],
})
