// CI smoke test for the upload -> report path.
//
// Separate from demo-recording.spec.ts on purpose. That one is a recorder: it
// reads demo-output/ produced by a real Docker capture, injects narration
// captions, records 2560x1440 video and pauses deliberately between steps. None
// of that belongs in a merge gate, and it cannot run without a prior trace.
//
// This exists because the Frontend job only proves the app typechecks and
// bundles. A dependency bump can satisfy tsc and vite and still break at
// runtime -- react-router 7 changing route behaviour, or a Tailwind rename
// silently emitting no CSS -- and nothing in CI would have noticed.
//
// Fixtures use RFC1918 addresses deliberately. Enrichment gates its reverse-DNS
// lookups on is_public_ip(), so private destinations mean this test makes no
// outbound DNS query and cannot go red because a network was slow.
import { expect, test } from '@playwright/test'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const fixtures = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'fixtures')

async function choose(page: import('@playwright/test').Page, button: string, file: string) {
  const chooser = page.waitForEvent('filechooser')
  await page.getByRole('button', { name: button }).click()
  await (await chooser).setFiles(path.join(fixtures, file))
  await expect(page.getByText(file, { exact: true }).first()).toBeVisible()
}

test('uploads a report and renders every section', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByText('Upload Egress Report')).toBeVisible()

  await choose(page, 'Choose file', 'egress.jsonl')
  await choose(page, 'Choose run.json', 'run.json')
  await page.getByRole('button', { name: 'Upload and view report' }).click()

  await expect(page.getByTestId('report-page')).toBeVisible({ timeout: 30_000 })
  await expect(page).toHaveURL(/\/reports\/[0-9a-f-]+$/)

  // Each section is asserted on its own rather than just checking the page
  // rendered, so a component that throws and unmounts its subtree is caught
  // instead of passing on the strength of its siblings.
  await expect(page.getByTestId('kpi-section')).toContainText(/events/i)
  await expect(page.getByTestId('top-destinations-section')).toContainText('Top destinations')
  await expect(page.getByTestId('timeline-section')).toContainText('Events over time')
  await expect(page.getByTestId('flags-section')).toContainText('Flags')
  await expect(page.getByTestId('export-markdown')).toBeVisible()

  // Values, not just headings: this is what proves the fixture actually went
  // through parsing and aggregation rather than the page rendering empty.
  const runDetails = page.getByTestId('run-details-section')
  await expect(runDetails).toContainText('python app.py dns example.com')
  await expect(runDetails).toContainText('egresslens/base:latest')
  await expect(page.getByTestId('top-destinations-section')).toContainText('10.10.0.10')
})

test('reports a PASS verdict when the allowlist covers every destination', async ({ page }) => {
  await page.goto('/')
  await choose(page, 'Choose file', 'egress.jsonl')
  await choose(page, 'Choose policy.json', 'policy-pass.json')
  await page.getByRole('button', { name: 'Upload and view report' }).click()

  await expect(page.getByTestId('report-page')).toBeVisible({ timeout: 30_000 })
  await expect(page.getByTestId('policy-section')).toContainText('PASS')
})

test('reports a FAIL verdict for a destination off the allowlist', async ({ page }) => {
  await page.goto('/')
  await choose(page, 'Choose file', 'egress.jsonl')
  await choose(page, 'Choose policy.json', 'policy-fail.json')
  await page.getByRole('button', { name: 'Upload and view report' }).click()

  await expect(page.getByTestId('report-page')).toBeVisible({ timeout: 30_000 })

  const verdict = page.getByTestId('policy-section')
  await expect(verdict).toContainText('FAIL')
  // policy-fail.json allows only 10.10.0.10, so the DNS and refused-connect
  // destinations are the ones that must be reported as unexpected.
  await expect(verdict).toContainText('10.10.0.53')
  await expect(verdict).toContainText('10.10.0.99')
  await expect(page.getByTestId('flags-section')).toContainText(/unexpected destinations/i)
})
