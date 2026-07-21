# EgressLens

Trace outbound network activity from Python apps in Docker, write the events as JSONL, and inspect the results in a small web UI.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Docker 20.10+](https://img.shields.io/badge/docker-20.10+-2496ED.svg)](https://www.docker.com/)

## What It Does

EgressLens runs an app under `strace`, captures IPv4 network syscalls, and produces:

- `egress.jsonl`: parsed connection events
- `egress.strace`: raw trace output
- `run.json`: command, image, timing, exit code, and event counts

The backend can enrich uploaded reports with domains from passive DNS seen in the trace, then bounded reverse DNS for unresolved public IPv4 addresses.

## Quick Start

Requirements: Docker 20.10+, Python 3.8+, and Node.js 18+ for the UI.

```bash
pip install -e cli/
docker build -t egresslens/base:latest .
egresslens run-app ./sample_app --args "dns example.com"
```

Output lands in `egresslens-output/`.

## Demo

Run the repeatable live demo and browser recording flow with [docs/demo.md](docs/demo.md).

## View A Report

Start the API:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Start the UI:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173` and upload:

- `egresslens-output/egress.jsonl` as the report
- `egresslens-output/run.json` for metadata
- `egresslens-output/egress.strace` for domain enrichment

![Report view](docs/images/report.png)

## CLI

Trace a Python project with an entry point named `__main__.py`, `main.py`, or `app.py`:

```bash
egresslens run-app ./my_python_app --args "arg1 arg2"
```

Trace an arbitrary command:

```bash
egresslens watch -- curl https://example.com
```

Useful options:

- `--out <path>`: write output somewhere else
- `--image <name>`: use a different image with `strace` installed

More detail: [cli/README.md](cli/README.md).

## Repo Map

- `cli/`: capture network activity and write trace artifacts
- `backend/`: FastAPI upload, aggregation, enrichment, and export API
- `frontend/`: React UI for uploads and reports
- `sample_app/`: small app for predictable demo traffic
- `docs/getting-started.md`: longer walkthrough with screenshots

## Security Model

Tracing requires Docker settings that reduce isolation:

- `--cap-add SYS_PTRACE`
- `--security-opt seccomp=unconfined`

The CLI still mounts the app read-only, drops other capabilities, uses `no-new-privileges`, and provides tmpfs scratch space. Treat traced code as code you are choosing to run.

## Limits

- IPv4 only. IPv6 connections are currently ignored.
- Domain enrichment sees UDP DNS A-record answers in `egress.strace`; it does not cover DNS-over-HTTPS, DNS-over-TLS, cached DNS, TCP DNS, AAAA records, or IPv6.
- Reverse DNS fallback skips private and non-routable IP ranges and is capped by backend configuration.

## License

MIT. See [LICENSE](LICENSE).
