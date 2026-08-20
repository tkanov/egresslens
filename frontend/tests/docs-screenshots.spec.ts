// Regenerates the two screenshots the docs embed, so they cannot drift from the
// UI the way the hand-taken originals did. Those were captured before the three
// optional pickers and the fifth KPI card existed, and went on being shown for
// months next to prose describing features they did not contain.
//
// Run with `npm run docs:screenshots`. Deliberately excluded from
// `npm run test:e2e`, because a test run must not rewrite committed assets.
//
// Hermetic on purpose: it reuses the smoke fixtures, whose destinations are all
// RFC1918. parse_passive_dns reads egress.strace whatever the address range, but
// the reverse-DNS fallback gates on is_public_ip(), so no lookup is attempted
// and the images do not change with the network the generator ran on.
import { expect, test } from '@playwright/test'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const testDir = path.dirname(fileURLToPath(import.meta.url))
const fixtures = path.join(testDir, 'fixtures')
const images = path.resolve(testDir, '../../docs/images')

type Page = import('@playwright/test').Page

async function choose(page: Page, button: string, file: string) {
  const chooser = page.waitForEvent('filechooser')
  await page.getByRole('button', { name: button }).click()
  await (await chooser).setFiles(path.join(fixtures, file))
  await expect(page.getByText(file, { exact: true }).first()).toBeVisible()
}

// Size the viewport to the content so the capture needs no scroll-and-stitch
// pass -- that is what clips a ResponsiveContainer chart mid-resize.
//
// Measured from the content wrapper, not documentElement.scrollHeight: the page
// shell is min-h-screen, so scrollHeight can never report less than the viewport
// and a short page like the upload screen would be padded out with half a screen
// of blank space. PAGE_PADDING is the shell's p-6, which the wrapper's own box
// does not include.
//
// Two passes because dropping the scrollbar widens the content, which can reflow
// the tables and change the height that was just measured.
const PAGE_PADDING = 24

async function fitViewport(page: Page, testId: string) {
  const { width } = page.viewportSize()!
  for (let pass = 0; pass < 2; pass++) {
    const content = await page.getByTestId(testId).boundingBox()
    if (!content) throw new Error(`no bounding box for ${testId}`)
    await page.setViewportSize({
      width,
      height: Math.ceil(content.height) + PAGE_PADDING * 2,
    })
    await page.waitForTimeout(250)
  }
}

// The last picker clicked keeps focus and sits under the cursor, so without this
// one button is captured in a hover state the others are not in.
async function settleChrome(page: Page) {
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur())
  await page.mouse.move(0, 0)
  await page.waitForTimeout(150)
}

test('captures the upload screen', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByText('Upload Egress Report')).toBeVisible()

  // Shot with the pickers filled rather than empty: getting-started step 7 tells
  // the reader which artifact goes in which picker, and this is the state that
  // shows it. policy.json is left out because the allowlist is step 9.
  await choose(page, 'Choose file', 'egress.jsonl')
  await choose(page, 'Choose run.json', 'run.json')
  await choose(page, 'Choose egress.strace', 'egress.strace')

  await settleChrome(page)
  await fitViewport(page, 'upload-page')
  await page.screenshot({ path: path.join(images, 'ui-frontend.png') })
})

test('captures the report view', async ({ page }) => {
  await page.goto('/')
  await choose(page, 'Choose file', 'egress.jsonl')
  await choose(page, 'Choose run.json', 'run.json')
  await choose(page, 'Choose egress.strace', 'egress.strace')
  await page.getByRole('button', { name: 'Upload and view report' }).click()

  await expect(page.getByTestId('report-page')).toBeVisible({ timeout: 30_000 })

  // Asserted before capture so a section that threw and unmounted cannot be
  // committed as a documentation image.
  await expect(page.getByTestId('kpi-section')).toContainText('Unique destinations')
  await expect(page.getByTestId('run-details-section')).toContainText('python app.py dns example.com')
  await expect(page.getByTestId('timeline-section')).toContainText('Events over time')
  await expect(page.getByTestId('flags-section')).toContainText('Flags')

  // The enrichment the caption in step 8 promises. Both come from the strace
  // fixture's A-record answers, so this also proves passive DNS ran.
  const destinations = page.getByTestId('top-destinations-section')
  await expect(destinations).toContainText('api.internal.example')
  await expect(destinations).toContainText('legacy.internal.example')

  // recharts animates the bars in over ~1.5s with no promise to await.
  await expect(page.locator('.recharts-bar-rectangle').first()).toBeVisible()
  await page.waitForTimeout(2_000)

  await settleChrome(page)
  await fitViewport(page, 'report-page')
  await page.screenshot({ path: path.join(images, 'report.png') })
})
