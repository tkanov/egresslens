# EgressLens

Trace outbound network activity from Python apps in Docker, write the events as JSONL, and inspect the results in a small web UI.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CLI Python 3.9+](https://img.shields.io/badge/cli%20python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![Docker 20.10+](https://img.shields.io/badge/docker-20.10+-2496ED.svg)](https://www.docker.com/)

## What It Does

EgressLens runs an app under `strace`, captures IPv4 network syscalls, and writes:

- `egress.jsonl`: parsed connection events
- `egress.strace`: raw trace output
- `run.json`: command, image, timing, exit code, event counts
- `cmd_stdout` and `cmd_stderr`: whatever the traced app printed
- `pip_install.log`: `run-app` only, with a `requirements.txt`: the untraced install's output

Upload those to the UI for an aggregated report, with destinations named from DNS answers in the trace and bounded reverse DNS for the rest. Add an allowlist and the report gains a PASS/FAIL/INCONCLUSIVE verdict (see [Egress Policy](#egress-policy)).

## Quick Start

Needs Docker 20.10+ and Python 3.9+. Viewing a report also needs Python 3.10+ for the backend and Node.js 20.19+ (or 22.13+) for the UI.

```bash
pip install -e cli/
docker build -t egresslens/base:latest .
egresslens run-app ./sample_app --args "dns example.com"
```

Output lands in `egresslens-output/`. With an allowlist to hand,
`egresslens check egresslens-output/ --policy policy.json` turns that capture
into a pass/fail exit code (see [Egress Policy](#egress-policy)).

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

Open `http://localhost:5173` and upload `egress.jsonl`, the only required file. Optional extras: `run.json` (run metadata), `egress.strace` (domain enrichment), `policy.json` (a verdict).

![Report view](docs/images/report.png)

## Egress Policy

Upload a `policy.json` allowlist and every observed destination is checked against it. The verdict is three-way, not a boolean:

| Verdict | Meaning | Flag raised |
|---|---|---|
| **PASS** | Every observed destination matched a rule | (none) |
| **FAIL** | At least one did not | "Unexpected destinations", high |
| **INCONCLUSIVE** | An allowlist was uploaded but nothing was observed | "Egress policy not evaluated", medium |

Before trusting a verdict:

- `ip`/CIDR rules are a hard gate. `domain` rules match a name attributed from DNS answers in the traced process's own trace, which evading code could forge, so treat them as advisory.
- Do not read "not FAIL" as PASS. INCONCLUSIVE means the capture gave the allowlist nothing to judge, and a failed capture looks identical to a genuinely quiet run.
- A PASS covers only what was captured (see [Limits](#limits)) and is independent of the other flags, so it can appear next to an "Unusual ports" flag.

### As A CI Gate

`egresslens check` computes the same verdict from a capture directory and returns it as an exit code. It needs neither Docker nor the backend, only the files a capture wrote.

```bash
egresslens check egresslens-output/ --policy policy.json
egresslens run-app ./my_app --policy policy.json      # capture, then judge
```

`0` is PASS, `1` is FAIL, `3` is INCONCLUSIVE and `2` is any input error, deliberately not `1`: a broken allowlist must never be reported as a violated one. The full table, including the codes `run-app` returns when a capture fails before there is anything to judge, is in [cli/README.md](cli/README.md#exit-codes).

Reverse DNS is off by default here, because a gate that depends on live DNS is not reproducible. `--format json` puts the whole verdict on stdout for a job that wants to annotate a PR.

Rule syntax, matching semantics, and known gotchas: [docs/policy.md](docs/policy.md).

## CLI

```bash
egresslens run-app ./my_python_app --args "arg1 arg2"   # a Python project
egresslens watch -- curl https://example.com            # any command
```

`run-app` looks for an entry point named `__main__.py`, `main.py`, or `app.py`. Options: `--args` (arguments for the traced app), `--out` (output path), `--image` (another image with `strace` installed), `--policy` (judge the capture afterwards, see [As A CI Gate](#as-a-ci-gate)), `--reverse-dns` (allow live reverse DNS when judging). `watch` takes the same options except `--args`.

`run-app` installs `requirements.txt` before tracing starts, so the trace covers the app and not pip. PyPI and its CDN are deliberately absent from the report; pip's output lands in `pip_install.log`, and a failed install exits 90 without writing a report.

> **Known bug:** `__main__.py` is checked first but fails with `ModuleNotFoundError`, because the runner invokes it in a way that leaves the module off `sys.path`. Use `main.py` or `app.py` for now.

More detail: [cli/README.md](cli/README.md).

## Repo Map

- `cli/`: capture network activity, write trace artifacts, judge them with `egresslens check`
- `backend/`: FastAPI upload, aggregation, enrichment, policy, and export API
- `frontend/`: React UI for uploads and reports
- `sample_app/`: small app for predictable demo traffic
- `Dockerfile`, with `docker-build.sh`, `docker-teardown.sh`, and `test-docker.sh` beside it at the repo root: the tracing image
- `scripts/demo_capture.sh`: one live capture for the demo flow
- `docs/`: [getting started](docs/getting-started.md), [policy reference](docs/policy.md), [demo flow](docs/demo.md)

## Security Model

Tracing needs `--cap-add SYS_PTRACE` and `--security-opt seccomp=unconfined`, which reduce isolation. The CLI still mounts the app read-only, drops other capabilities, uses `no-new-privileges`, and provides tmpfs scratch space. Treat traced code as code you are choosing to run.

## Limits

- IPv4 only. IPv6 destinations are not captured; those reached via `connect()` are at least counted, as `ipv6_connects_skipped`, and `egresslens check` says so rather than reporting a bare PASS.
- Only strace's `network` syscall class is traced, so egress submitted another way (`io_uring`, for example) is invisible and cannot raise a policy FAIL.
- Destinations are captured from `connect()` and from `sendto`/`sendmsg`/`sendmmsg` on unconnected sockets, so datagram egress that never calls `connect()` is still reported. A UDP `connect()` that transmits nothing is not a destination and is counted as `udp_probes_skipped`; a connected UDP socket written with `write()`, or through a `dup()` of its fd, is not recorded at all.
- Domain enrichment reads UDP DNS A-record answers only. DNS-over-HTTPS, DNS-over-TLS, TCP DNS, cached DNS, AAAA records, and `recvmmsg` are out of scope. Reverse DNS fallback skips private ranges; it is on by default in the backend, bounded by its configuration, and off by default in `egresslens check`, bounded by `--reverse-dns-timeout` and `--reverse-dns-max-ips`.

Full detail: [docs/getting-started.md#limitations](docs/getting-started.md#limitations).

## License

MIT. See [LICENSE](LICENSE).
