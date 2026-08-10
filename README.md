# EgressLens

Trace outbound network activity from Python apps in Docker, write the events as JSONL, and inspect the results in a small web UI.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CLI Python 3.9+](https://img.shields.io/badge/cli%20python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![Docker 20.10+](https://img.shields.io/badge/docker-20.10+-2496ED.svg)](https://www.docker.com/)

## What It Does

EgressLens runs an app under `strace`, captures IPv4 network syscalls, and produces:

- `egress.jsonl`: parsed connection events
- `egress.strace`: raw trace output
- `run.json`: command, image, timing, exit code, and event counts

The backend can enrich uploaded reports with domains from passive DNS seen in the trace, then bounded reverse DNS for unresolved public IPv4 addresses.

You can also tell EgressLens which destinations an app is expected to reach. Give it an allowlist and it flags anything off the list, with a PASS/FAIL/INCONCLUSIVE verdict on the report. See [Egress Policy](#egress-policy).

## Quick Start

Requirements: Docker 20.10+, and Python 3.9+ for the CLI. Viewing a report needs
Python 3.10+ for the backend API and Node.js 20.19+ (or 22.12+) for the UI.

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

Open `http://localhost:5173` and upload. Only the first file is required:

- `egresslens-output/egress.jsonl` — the report itself
- `egresslens-output/run.json` — optional, adds run metadata
- `egresslens-output/egress.strace` — optional, enables domain enrichment
- `policy.json` — optional allowlist (see [Egress Policy](#egress-policy))

![Report view](docs/images/report.png)

## Egress Policy

Upload an allowlist alongside a report to turn it into a verdict: every observed
destination is checked against the policy, and anything that does not match is
reported as unexpected.

The verdict is three-way, not a boolean:

| Verdict | Meaning | Flag raised |
|---|---|---|
| **PASS** | Every observed destination matched a rule | — |
| **FAIL** | At least one did not | "Unexpected destinations", high |
| **INCONCLUSIVE** | An allowlist was uploaded but nothing was observed | "Egress policy not evaluated", medium |

That third case is deliberately not a PASS. With no observed destinations the
allowlist was never exercised, so a failed capture, the wrong file uploaded, and
a genuinely quiet run all look identical — reporting compliance there would be a
vacuous truth dressed up as a security result. **Do not read "not FAIL" as
PASS.** All three verdicts appear in the markdown export.

The policy is a JSON file with an `allow` list. Each entry is either a shorthand
string or an object:

```json
{
  "allow": [
    "*.github.com",
    "pypi.org",
    "140.82.112.0/20",
    { "domain": "files.pythonhosted.org" },
    { "ip": "151.101.0.0/16", "port": 443 }
  ]
}
```

- A **domain** matches exactly (`pypi.org`), or as a leading-wildcard covering
  subdomains only (`*.github.com` matches `api.github.com`, not the apex or
  `notgithub.com`).
- An **ip** is a single address or a CIDR range.
- An object rule may add a **port**; every field it declares must match.

`allow` is the only key read — there is no deny list, and an allowlist holds at
most 1000 rules. Note that unknown keys *inside* a rule object are rejected, but
unknown *top-level* keys are currently ignored silently, so a stray `deny` block
is dropped without warning rather than failing the upload.

Combining `domain` and `ip` in one rule does not give you an IP hard gate: a rule
that names a domain is only ever reached through domain matching, so the same IP
seen unresolved will not match it. Write the `ip` rule separately.

A destination is expected if an `ip`/CIDR rule covers it, or — when it resolved
to one or more domains — if **every** observed domain matches a rule. That last
part fails closed on purpose: a shared IP that served both an allowed and a
disallowed name is reported as unexpected rather than passing on the allowed one.
Destinations that could not be named (unresolved IPs) match `ip`/CIDR rules only.

**Trust model.** `ip`/CIDR rules match the real kernel-level destination — the
address passed to `connect()`, or to `sendto`/`sendmsg`/`sendmmsg` on an
unconnected socket — and are a hard gate. `domain` rules match the name
attributed during enrichment, which is derived from DNS answers seen in the
traced process's *own* trace — so code that is actively trying to evade the
allowlist could forge that attribution. Treat `domain` rules as advisory (great
for catching accidental or non-adversarial egress drift) and use `ip`/CIDR rules
where you need a verdict the traced code cannot influence by choice of name.

A verdict is only as complete as the capture behind it: a PASS means nothing
off-allowlist was *observed*, and the observation set is bounded by
[Limits](#limits) below. IPv6 destinations and any egress submitted outside
strace's `network` syscall class are not observed, so they cannot raise a FAIL.
An INCONCLUSIVE verdict says the capture yielded nothing to judge at all.

The policy verdict is independent of the other flags: an allowlisted destination
on an uncommon port can still raise the "Unusual ports" flag, so a report may
show a **PASS** verdict alongside other flags.

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
- `backend/`: FastAPI upload, aggregation, enrichment, policy, and export API
- `frontend/`: React UI for uploads and reports
- `sample_app/`: small app for predictable demo traffic
- `scripts/`: `demo_capture.sh`, the entry point for the demo flow
- `Dockerfile`: the tracing image, plus `docker-build.sh` / `docker-teardown.sh`
- [`docs/getting-started.md`](docs/getting-started.md): longer walkthrough with screenshots
- [`docs/demo.md`](docs/demo.md): repeatable live demo and browser recording

## Security Model

Tracing requires Docker settings that reduce isolation:

- `--cap-add SYS_PTRACE`
- `--security-opt seccomp=unconfined`

The CLI still mounts the app read-only, drops other capabilities, uses `no-new-privileges`, and provides tmpfs scratch space. Treat traced code as code you are choosing to run.

## Limits

- IPv4 only. Destinations are captured from `connect()` and from `sendto`/`sendmsg`/`sendmmsg` on unconnected sockets, so datagram egress that never calls `connect()` is reported. IPv6 (`AF_INET6`) destinations are not captured: those reached via `connect()` are counted (reported as `ipv6_connects_skipped`), but an IPv6 destination named on a send\* call is neither captured nor counted.
- Only syscalls in strace's `network` class are seen. Egress submitted another way — `io_uring`, for example — is not captured, and cannot raise a policy FAIL.
- Domain enrichment reads UDP DNS A-record answers from `recvfrom`/`recvmsg` lines in `egress.strace`. It does not cover DNS-over-HTTPS, DNS-over-TLS, cached DNS, TCP DNS, AAAA records, IPv6, or answers received via `recvmmsg`.
- Reverse DNS fallback skips private and non-routable IP ranges and is capped by backend configuration.
- Policy `domain` rules only match destinations that were named during enrichment, so include `egress.strace` when using them; unresolved IPs can still be covered with `ip`/CIDR rules.

## License

MIT. See [LICENSE](LICENSE).
