# EgressLens Frontend

React + TypeScript UI for uploading trace artifacts and reading the resulting
egress report.

## Setup

Requires Node.js 20.19+ or 22.13+ — Vite 8 sets the 20.19 floor, ESLint 10 the
22.13 one.

```bash
npm install
npm run dev
```

The dev server runs at `http://localhost:5173` and proxies `/api` to the backend
at `http://localhost:8000`. The proxy resolves per request, so start order does
not matter — with the backend down the page still loads and only requests fail.

## Uploading

The upload page takes four files, only the first of which is required:

| Picker | File | Adds |
|---|---|---|
| Upload Egress Report | `egress.jsonl` | The events — required |
| Run metadata | `run.json` | Command, image, exit code, timing |
| Passive DNS trace | `egress.strace` | Domains for public IP destinations |
| Egress allowlist | `policy.json` | PASS / FAIL / inconclusive verdict |

All four come out of the CLI's output directory (`egresslens-output/` by
default), except `policy.json`, which you write yourself.

The report shows KPIs, a timeline, top destinations, flags, run details, and —
when an allowlist was uploaded — the policy verdict. Top destinations show the
primary domain when known, its source (`passive_dns` or `reverse_dns`), and the
candidate hit count. Reports uploaded without enrichment render with an empty
domain value. The report page can also export to Markdown.

## Scripts

| Script | What it does |
|---|---|
| `npm run dev` | Dev server on :5173 |
| `npm run build` | `tsc && vite build` → `dist/`; also the only typecheck path |
| `npm run lint` | ESLint, zero warnings tolerated — a CI merge gate |
| `npm run preview` | Serve the built `dist/` locally |
| `npm run test:e2e` | Full Playwright suite |
| `npm run test:e2e:smoke` | Smoke project only — a CI merge gate |
| `npm run demo:record` | Records the demo video (see [docs/demo.md](../docs/demo.md)) |

Playwright starts the backend and frontend itself, reusing them if already
running. Browsers install with `npx playwright install chromium`.

## Structure

| Path | Contents |
|---|---|
| `src/App.tsx` | Routes: `/` (upload) and `/reports/:id` (report) |
| `src/pages/` | `UploadPage`, `ReportPage` |
| `src/components/` | `KPICards`, `TopDestinations`, `TimelineChart`, `FlagsPanel`, `PolicyVerdict`, `RunDetails` |
| `src/components/ui/` | shadcn/ui primitives |
| `src/lib/` | `utils.ts` (cn helper), `portInfo.ts` (port→service), `ipLookup.ts` (WHOIS links) |
| `src/api.ts` | Backend client and response types |
| `tests/` | Playwright specs |

Built with React 18, Vite, Tailwind CSS, shadcn/ui, React Router, and Recharts;
linted with ESLint and tested with Playwright.

## Production builds

`npm run build` writes to `dist/`. The Vite proxy is a **dev-server** feature, so
a built bundle has no path to the backend unless you either set
`VITE_API_BASE_URL` at build time or serve `dist/` behind a reverse proxy that
fronts `/api`. Left unset, the client calls `/api/...` on its own origin.

If you serve the UI from an origin other than `localhost:5173` or `:3000`, also
set `ALLOWED_ORIGINS` on the backend so CORS permits it.
