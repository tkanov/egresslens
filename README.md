# EgressLens

Trace outbound network activity from Python apps in Docker, write the events as JSONL, and inspect the results in a small web UI.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CLI Python 3.9+](https://img.shields.io/badge/cli%20python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![Docker 20.10+](https://img.shields.io/badge/docker-20.10+-2496ED.svg)](https://www.docker.com/)

## What It Does

EgressLens runs an app under `strace`, captures IPv4 network syscalls, and writes:

- `egress.jsonl` — parsed connection events
- `egress.strace` — raw trace output
- `run.json` — command, image, timing, exit code, and event counts

Upload those to the UI for an aggregated report. The backend names destinations using domains from passive DNS seen in the trace, then bounded reverse DNS for unresolved public IPv4 addresses.

Add an allowlist of the destinations an app is expected to reach and the report gains a PASS/FAIL/INCONCLUSIVE verdict, flagging anything off the list — with the caveats in [Egress Policy](#egress-policy).

## Quick Start

Requirements: Docker 20.10+ and Python 3.9+ for the CLI. Viewing a report also needs Python 3.10+ for the backend API and Node.js 20.19+ (or 22.13+) for the UI.

```bash
pip install -e cli/
docker build -t egresslens/base:latest .
egresslens run-app ./sample_app --args "dns example.com"
```

Output lands in `egresslens-output/`. Longer walkthrough with screenshots: [docs/getting-started.md](docs/getting-started.md). Repeatable live demo and browser recording: [docs/demo.md](docs/demo.md).

## View A Report

Start the API:

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Start the UI:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173` and upload `egresslens-output/egress.jsonl` — the only required file. The other three each add something: `run.json` (run metadata), `egress.strace` (domain enrichment), and a `policy.json` allowlist (a verdict).

![Report view](docs/images/report.png)

## Egress Policy

Upload a `policy.json` allowlist alongside a report and every observed destination is checked against it. The verdict is three-way, not a boolean:

| Verdict | Meaning | Flag raised |
|---|---|---|
| **PASS** | Every observed destination matched a rule | — |
| **FAIL** | At least one did not | "Unexpected destinations", high |
| **INCONCLUSIVE** | An allowlist was uploaded but nothing was observed | "Egress policy not evaluated", medium |

```json
{
  "allow": ["*.github.com", "pypi.org", "140.82.112.0/20", { "ip": "151.101.0.0/16", "port": 443 }]
}
```

Three things to know before trusting a verdict:

- **`ip`/CIDR rules are a hard gate; `domain` rules are advisory.** IP rules match the real kernel-level destination. Domain rules match a name attributed from DNS answers in the traced process's *own* trace, so code actively trying to evade the allowlist could forge that attribution.
- **Do not read "not FAIL" as PASS.** INCONCLUSIVE means the capture gave the allowlist nothing to judge — a failed capture, the wrong file uploaded, and a genuinely quiet run all look identical there.
- **A PASS is bounded by what was captured** (see [Limits](#limits)) and is independent of the other flags, so a PASS can appear next to an "Unusual ports" flag.

Full rule syntax, matching semantics, the trust model, and known gotchas: [docs/policy.md](docs/policy.md).

## CLI

```bash
egresslens run-app ./my_python_app --args "arg1 arg2"   # a Python project
egresslens watch -- curl https://example.com            # any command
```

`run-app` looks for an entry point named `__main__.py`, `main.py`, or `app.py`.

> **Known bug:** `__main__.py` is checked first but does not currently run — the runner invokes it in a way that leaves the module off `sys.path`, so it fails with `ModuleNotFoundError`. Use `main.py` or `app.py` until this is fixed.

Useful options: `--args "<args>"` passes arguments to the traced app, `--out <path>` writes output elsewhere, `--image <name>` uses a different image with `strace` installed. More detail: [cli/README.md](cli/README.md).

## Repo Map

- `cli/`: capture network activity and write trace artifacts
- `backend/`: FastAPI upload, aggregation, enrichment, policy, and export API
- `frontend/`: React UI for uploads and reports
- `sample_app/`: small app for predictable demo traffic
- `scripts/`: `demo_capture.sh`, the entry point for the demo flow
- `Dockerfile`: the tracing image, plus `docker-build.sh` / `docker-teardown.sh`
- [`docs/getting-started.md`](docs/getting-started.md): longer walkthrough with screenshots
- [`docs/policy.md`](docs/policy.md): egress policy reference
- [`docs/demo.md`](docs/demo.md): repeatable live demo and browser recording

## Security Model

Tracing requires Docker settings that reduce isolation: `--cap-add SYS_PTRACE` and `--security-opt seccomp=unconfined`.

The CLI still mounts the app read-only, drops other capabilities, uses `no-new-privileges`, and provides tmpfs scratch space. Treat traced code as code you are choosing to run.

## Limits

- IPv4 only. Destinations are captured from `connect()` and from `sendto`/`sendmsg`/`sendmmsg` on unconnected sockets, so datagram egress that never calls `connect()` is reported. IPv6 (`AF_INET6`) destinations are not captured: those reached via `connect()` are counted (reported as `ipv6_connects_skipped`), but an IPv6 destination named on a send\* call is neither captured nor counted.
- Only syscalls in strace's `network` class are seen. Egress submitted another way — `io_uring`, for example — is not captured, and cannot raise a policy FAIL.
- Domain enrichment reads UDP DNS A-record answers from `recvfrom`/`recvmsg` lines in `egress.strace`. It does not cover DNS-over-HTTPS, DNS-over-TLS, cached DNS, TCP DNS, AAAA records, IPv6, or answers received via `recvmmsg`.
- Reverse DNS fallback skips private and non-routable IP ranges and is capped by backend configuration.
- Policy `domain` rules only match destinations that were named during enrichment, so include `egress.strace` when using them; unresolved IPs can still be covered with `ip`/CIDR rules.

## License

MIT. See [LICENSE](LICENSE).
