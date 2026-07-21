import { expect, test } from '@playwright/test'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const testDir = path.dirname(fileURLToPath(import.meta.url))
const demoOutputDir = path.resolve(testDir, '../../demo-output')
const pauseMs = Number(process.env.DEMO_RECORDING_PAUSE_MS ?? 1200)

type Page = import('@playwright/test').Page

async function pause(page: Page, multiplier = 1) {
  await page.waitForTimeout(pauseMs * multiplier)
}

async function prepareDemoPage(page: Page) {
  await page.addStyleTag({
    content: `
      html { font-size: 19px; }
      body { overflow-x: hidden; }
      [class~="max-w-2xl"] { max-width: 1080px !important; }
      [class~="max-w-6xl"] { max-width: 2100px !important; }
      [class~="p-6"] { padding: 36px !important; }
      table { font-size: 1.03rem; }
      #demo-caption {
        position: fixed !important;
        left: 50% !important;
        right: auto !important;
        bottom: 42px !important;
        transform: translateX(-50%) !important;
        z-index: 99999 !important;
        width: min(1200px, calc(100vw - 96px)) !important;
        max-width: none !important;
        padding: 20px 28px !important;
        border-radius: 10px !important;
        background: rgba(15, 23, 42, 0.95) !important;
        color: white !important;
        box-shadow: 0 18px 44px rgba(15, 23, 42, 0.32) !important;
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif !important;
        font-size: 30px !important;
        line-height: 1.3 !important;
        letter-spacing: 0 !important;
        text-align: center !important;
      }
    `,
  })
}

async function caption(page: Page, text: string, multiplier = 2.4) {
  await page.evaluate((message) => {
    document.getElementById('demo-caption')?.remove()
    const el = document.createElement('div')
    el.id = 'demo-caption'
    el.textContent = message
    document.body.appendChild(el)
  }, text)
  await pause(page, multiplier)
}

async function clearCaption(page: Page) {
  await page.evaluate(() => document.getElementById('demo-caption')?.remove())
}

async function chooseFile(page: Page, buttonName: string | RegExp, fileName: string) {
  const chooserPromise = page.waitForEvent('filechooser')
  await page.getByRole('button', { name: buttonName }).click()
  const chooser = await chooserPromise
  await chooser.setFiles(path.join(demoOutputDir, fileName))
  await expect(page.getByText(fileName, { exact: true }).first()).toBeVisible()
  await pause(page, 0.8)
}

test('records the live EgressLens upload and report flow', async ({ page }) => {
  await page.goto('/')
  await prepareDemoPage(page)
  await expect(page.getByText('Upload Egress Report')).toBeVisible()

  await caption(page, 'This starts with three files from a real Docker capture: parsed network events, run metadata, and raw strace for DNS enrichment.')
  await chooseFile(page, 'Choose file', 'egress.jsonl')
  await caption(page, 'egress.jsonl is a syscall event log. The count is network events, not HTTP requests.', 2.2)

  await chooseFile(page, 'Choose run.json', 'run.json')
  await caption(page, 'run.json explains what produced the traffic: command, image, exit code, timing, and working directory.', 2.2)

  await chooseFile(page, 'Choose egress.strace', 'egress.strace')
  await caption(page, 'egress.strace lets the backend infer domains from DNS traffic, then use reverse DNS when needed.', 2.2)

  await page.getByRole('button', { name: 'Upload and view report' }).click()
  await caption(page, 'Uploading: the backend groups events by destination IP, port, protocol, and domain candidates.', 2)

  await expect(page.getByTestId('report-page')).toBeVisible({ timeout: 30_000 })
  await prepareDemoPage(page)
  await expect(page).toHaveURL(/\/reports\/[0-9a-f-]+$/)
  await expect(page.getByTestId('kpi-section')).toContainText(/events/i)
  await expect(page.getByTestId('run-details-section')).toContainText('Command')
  await expect(page.getByTestId('top-destinations-section')).toContainText('Top destinations')
  await expect(page.getByTestId('timeline-section')).toContainText('Events over time')
  await expect(page.getByTestId('flags-section')).toContainText('Flags')
  await expect(page.getByTestId('export-markdown')).toBeVisible()

  const topDestinations = page.getByTestId('top-destinations-section')
  await expect(topDestinations).toContainText(/example\.com|passive DNS|reverse DNS|crt\.sh/i)

  await caption(page, 'KPI cards summarize captured network events: total events, unique IPs, unique ports, and failed connects.', 2.6)

  await page.getByTestId('run-details-section').scrollIntoViewIfNeeded()
  await caption(page, 'Run details answer: what command caused this traffic?', 2.4)

  await page.getByTestId('top-destinations-section').scrollIntoViewIfNeeded()
  await caption(page, 'Top destinations are IP:port groups. Port 53 is DNS. Port 443 is HTTPS/TLS. Domains appear when enrichment resolves them.', 3)

  await page.getByTestId('timeline-section').scrollIntoViewIfNeeded()
  await caption(page, 'The timeline shows when events happened during the short run, useful for spotting bursts or late network calls.', 2.4)

  await page.getByTestId('flags-section').scrollIntoViewIfNeeded()
  await caption(page, 'Flags call out report-level signals, such as elevated failure rate or unusual ports.', 2.4)

  await page.getByTestId('report-page').scrollIntoViewIfNeeded()
  await caption(page, 'The result is a shareable report: what ran, where it connected, which ports/protocols were used, and what domains were inferred.', 3)
  await clearCaption(page)
  await pause(page, 1)
})
