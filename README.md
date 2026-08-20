# EgressLens

Trace outbound network activity from Python apps in Docker, write the events as JSONL, and inspect the results in a small web UI.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CLI Python 3.9+](https://img.shields.io/badge/cli%20python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![Docker 20.10+](https://img.shields.io/badge/docker-20.10+-2496ED.svg)](https://www.docker.com/)

## What It Does

EgressLens runs an app under `strace` and captures IPv4 network syscalls, writing `egress.jsonl` (parsed events), `egress.strace` (the raw trace), `run.json` (command, image, timing, counts), and the app's own output. Full list: [cli/README.md](cli/README.md#output).

Upload those to the UI for an aggregated report, with destinations named from DNS answers in the trace and bounded reverse DNS for the rest. Add an allowlist and the report gains a PASS/FAIL/INCONCLUSIVE verdict.

## Quick Start

Needs Docker 20.10+ and Python 3.9+. Viewing a report also needs Python 3.10+ for the backend and Node.js 20.19+ (or 22.13+) for the UI.

```bash
pip install -e cli/
docker build -t egresslens/base:latest .
egresslens run-app ./sample_app --args "dns example.com"
```

Output lands in `egresslens-output/`.

## View A Report

Start the API, then the UI:

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -e ../cli
uvicorn app.main:app --reload --port 8000
```

```bash
cd frontend
npm install && npm run dev
```

Open `http://localhost:5173` and upload `egress.jsonl`, the only required file. `run.json`, `egress.strace` and `policy.json` each add something; the walkthrough is [docs/getting-started.md](docs/getting-started.md).

![Report view](docs/images/report.png)

## Egress Policy

Upload a `policy.json` allowlist and every observed destination is checked against it. The verdict is three-way, not a boolean:

| Verdict | Meaning | Flag raised |
|---|---|---|
| **PASS** | Every observed destination matched a rule | (none) |
| **FAIL** | At least one did not | "Unexpected destinations", high |
| **INCONCLUSIVE** | An allowlist was uploaded but nothing was observed | "Egress policy not evaluated", medium |

Before trusting one: `ip`/CIDR rules are a hard gate, but `domain` rules match a name attributed from the traced process's own DNS traffic, which evading code could forge. Do not read "not FAIL" as PASS either, because INCONCLUSIVE means the capture gave the allowlist nothing to judge, and a failed capture looks identical to a genuinely quiet run. A PASS covers only what was captured, so read it against [Limits](#limits).

`egresslens check egresslens-output/ --policy policy.json` returns the same verdict as an exit code, without Docker or the backend, so a capture can gate CI. Exit codes and the reverse-DNS default: [cli/README.md](cli/README.md#exit-codes). Rule syntax, matching semantics, and known gotchas: [docs/policy.md](docs/policy.md).

## CLI

```bash
egresslens run-app ./my_python_app --args "arg1 arg2"       # a Python project
egresslens watch -- curl https://example.com                # any command
egresslens check egresslens-output/ --policy policy.json    # judge a capture
```

`run-app` looks for an entry point named `__main__.py`, `main.py`, or `app.py`, and installs `requirements.txt` before tracing starts, so the trace covers the app and not pip. A failed install exits 90 without writing a report. Options, exit codes, and programmatic use: [cli/README.md](cli/README.md).

> **Known bug:** `__main__.py` is checked first but fails with `ModuleNotFoundError`, because the runner invokes it in a way that leaves the module off `sys.path`. Use `main.py` or `app.py` for now.

## Repo Map

- `cli/`: capture network activity, write trace artifacts, judge them with `egresslens check`
- `backend/`: FastAPI upload, aggregation, enrichment, policy, and export API
- `frontend/`: React UI for uploads and reports
- `sample_app/`: small app for predictable demo traffic
- `Dockerfile` and its helper scripts at the repo root: the tracing image
- `scripts/demo_capture.sh`: one live capture for the demo flow
- `docs/`: [getting started](docs/getting-started.md), [policy reference](docs/policy.md), [demo flow](docs/demo.md)

## Security Model

Tracing needs `--cap-add SYS_PTRACE` and `--security-opt seccomp=unconfined`, which reduce isolation. The CLI still mounts the app read-only, drops other capabilities, uses `no-new-privileges`, and provides tmpfs scratch space. Treat traced code as code you are choosing to run.

## Limits

- IPv4 only. IPv6 destinations are counted as `ipv6_connects_skipped`, not captured, and `egresslens check` says so rather than printing a bare PASS.
- Only strace's `network` syscall class is traced, so egress submitted another way (`io_uring`, for example) is invisible and cannot raise a policy FAIL.
- Datagram egress that never calls `connect()` is still reported. A UDP `connect()` that transmits nothing is not a destination, and is counted as `udp_probes_skipped`; a connected UDP socket written with `write()`, or through a `dup()` of its fd, is not recorded at all.
- Domain enrichment reads UDP DNS A-record answers only, so DNS-over-HTTPS, TCP DNS, cached DNS and AAAA records are out of scope. Reverse DNS fallback skips private ranges, and is on by default in the backend but off in `egresslens check`.

Full detail: [docs/getting-started.md#limitations](docs/getting-started.md#limitations).

## License

MIT. See [LICENSE](LICENSE).
