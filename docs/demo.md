# EgressLens live demo

This demo runs a small Python app in Docker, captures live egress artifacts, uploads them through the UI, verifies the report page, and records the browser flow with Playwright.

## Prerequisites

- Docker 20.10+
- Python 3.9+ for the CLI, 3.10+ for the backend
- Node.js 20.19+ (or 22.13+)
- Backend dependencies installed in `backend/.venv`
- Frontend dependencies installed with `npm install`

If Playwright browsers are not installed yet, run:

```bash
cd frontend
npx playwright install chromium
```

## 1. Capture live demo artifacts

From the repo root:

```bash
scripts/demo_capture.sh
```

The script builds `egresslens/base:latest` when needed and runs:

```bash
egresslens run-app ./sample_app --args "all example.com"
```

It writes to `demo-output/`. The demo uploads three of the files it finds there:

- `egress.jsonl`
- `run.json`
- `egress.strace`

The traced app's own `cmd_stdout` and `cmd_stderr` land beside them, as does
`pip_install.log` from the untraced dependency install. The demo uses none of the
three.

Use `scripts/demo_capture.sh --rebuild` to force a Docker image rebuild. Override the demo domain with `DOMAIN=python.org scripts/demo_capture.sh`.

## 2. Start the backend

```bash
cd backend
source .venv/bin/activate
uvicorn app.main:app --reload --port 8000
```

Leave it running at `http://localhost:8000`.

## 3. Start the frontend

In another terminal:

```bash
cd frontend
npm run dev
```

Leave it running at `http://localhost:5173`.

## 4. Record the UI flow

In a third terminal:

```bash
cd frontend
npm run demo:record
```

The Playwright test uploads all three files from `demo-output/`, waits for the report page, verifies the key report sections, and records a video under `frontend/test-results/`.

## Expected result

A successful demo shows:

- run metadata from `run.json`
- total events and destination counts
- top destinations with ports and protocol labels
- domain enrichment from `egress.strace` when live DNS responses are available
- timeline and flags sections
- Markdown export button

The recorded flow uploads the three captured artifacts and does not exercise the
egress allowlist. To see a PASS/FAIL/INCONCLUSIVE verdict, upload a `policy.json`
by hand in the egress allowlist picker — see
[getting-started.md](getting-started.md) for a worked example.

The demo uses live network and DNS, so exact IPs, counts, and enrichment results can vary by machine and network.
