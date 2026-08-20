import { defineConfig } from '@playwright/test'

// Three projects because the three specs want different things. `smoke` is the
// merge gate: small viewport, no video, no artifacts unless it fails. `demo` is
// the recorder behind `npm run demo:record`, which needs the large viewport and
// video that make a usable screen capture. `docs` is the still-image generator
// behind `npm run docs:screenshots`.
//
// `npm run test:e2e` names smoke and demo explicitly rather than running
// everything, because `docs` overwrites committed files in docs/images/ and a
// test run must not do that as a side effect. CI runs --project=smoke, because
// the demo spec depends on demo-output/ from a real Docker capture and cannot
// run without one.
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
    {
      name: 'docs',
      testMatch: /docs-screenshots\.spec\.ts/,
      use: {
        browserName: 'chromium',
        // Wide enough to clear Tailwind's xl breakpoint at 1280px, which is what
        // lays the five KPI cards out in one row instead of wrapping them.
        viewport: { width: 1400, height: 900 },
        deviceScaleFactor: 2,
        video: 'off',
        screenshot: 'off',
        // Pinned so a committed image does not depend on where it was generated.
        // RunDetails formats with the system locale and zone, so without this the
        // report shot renders whatever the generator's machine happened to be in,
        // and its clock disagrees with the timeline, which labels buckets in UTC.
        timezoneId: 'UTC',
        locale: 'en-GB',
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
