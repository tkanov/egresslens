# EgressLens CLI

Runs a command in a Docker container under `strace` and records every outbound
IPv4 connection it makes.

## Install

From the repo root:

```bash
pip install -e cli/
```

This is what puts the `egresslens` command on your PATH. Installing
`cli/requirements.txt` alone pulls in the dependencies but not the command.

The `[docker]` extra (`pip install -e './cli[docker]'`) adds the Docker SDK.
Without it the runner shells out to the `docker` CLI instead, which works fine –
the extra just selects which path runs.

## Quick start

Build the tracing image once, then trace the sample app:

```bash
docker build -t egresslens/base:latest .
egresslens run-app ./sample_app --args "dns example.com"
```

Output goes to `egresslens-output/`.

## Commands

### `run-app` – trace a Python project

```bash
egresslens run-app ./my_python_app --args "arg1 arg2"
```

Finds the entry point (`__main__.py`, `main.py`, or `app.py`, in that order),
installs `requirements.txt` if present, and runs it under trace.

The install runs *before* `strace` starts, so pip's own resolution and downloads
are not traced. Tracing them made PyPI and its CDN show up as destinations the
app reached, which for `sample_app` was 84% of the captured events. pip's output
goes to `pip_install.log`, not to `cmd_stdout`/`cmd_stderr`.

A failed install exits `90`, a status reserved for it: the app never ran, so no
trace is written and no report is produced. Any earlier capture in the output
directory is removed first, so nothing stale can be mistaken for this run. The
reason for the failure is in `pip_install.log`.

> **Known bug:** the `__main__.py` case does not work. The runner invokes
> `python -m <app dir name>` while the working directory *is* that directory, so
> the module is never on `sys.path` under that name and the run fails with
> `ModuleNotFoundError`. Since `__main__.py` is checked first, the canonical
> runnable-package layout is the one that breaks. Use `main.py` or `app.py` for
> now; the failure is pinned by a strict xfail in `test_docker_runner.py`.

### `watch` – trace any command

```bash
egresslens watch -- curl https://example.com
```

Everything after `--` is the command. It runs inside the tracing image, so the
binaries and libraries it needs must already be in that image – `watch` does not
install anything.

### `check` – judge a capture against an allowlist

```bash
egresslens check egresslens-output/ --policy policy.json
```

Reads the artifacts a capture already wrote and returns the verdict as an exit
code. No Docker, no backend, and no network unless you opt into reverse DNS.
`run-app` and `watch` accept `--policy` too, which runs the same check on the
capture they just took.

Domains come from the DNS answers in `egress.strace` (read automatically when it
sits beside the events file) and from any `domain`/`domain_source` fields the
events carry.
Live reverse DNS is off by default: it needs egress from wherever the gate runs
and PTR records change, so the same artifacts could pass one run and fail the
next. `--reverse-dns` opts in.

The output names how much of a PASS rests on a hard `ip`/CIDR rule and how much
on a domain rule, since a domain is attributed from the traced process's own DNS
traffic and evading code could forge it. `--format json` puts the whole verdict
on stdout and nothing else, unexpected destinations included.

#### Exit codes

Every code any of the three commands can return. This is the only copy, the other
docs link here.

| Code | Command | Meaning |
|---|---|---|
| `0` | all | PASS, or a capture that ran with no allowlist to judge it |
| `1` | `check` | FAIL – at least one destination was off the allowlist |
| `1` | `run-app` | The app directory could not be used (no entry point, bad syntax) |
| `2` | `check` | Error – missing or unreadable artifacts, or a malformed allowlist |
| `3` | `check` | INCONCLUSIVE – an allowlist was supplied and nothing was observed |
| `90` | `run-app` | Installing `requirements.txt` failed, so the app never ran and no report was written |
| other | `run-app`, `watch` | The traced command's own exit code, passed through |

`2` is never `1`: a policy that could not be read must not be reported as a
policy that was violated. `3` is not a pass either – see
[docs/policy.md](../docs/policy.md#verdicts).

Two codes are shared and cannot be told apart by number alone: `run-app` returns
`1` both for an unusable app directory and, under `--policy`, for a FAIL, and a
traced command that exits `3` on its own is indistinguishable from INCONCLUSIVE.
Both are deliberate – the alternative is rewriting exit codes the capture owns –
and both are unambiguous in `--format json` and on stderr.

With `--policy` on `run-app` or `watch`, a non-pass verdict becomes the exit code
and a passing one leaves the traced command's own code alone. The exception is a
capture that failed before writing a report, `90` and the `run-app` `1` above:
there is nothing to judge, the command has already said what went wrong, and
turning that into a `2` would point at the allowlist instead of at pip. Without
`--policy` nothing changes at all.

### Options

| Option | Commands | Description |
|---|---|---|
| `--out <path>` | `run-app`, `watch` | Where to write output (default `egresslens-output/`) |
| `--image <name>` | `run-app`, `watch` | Tracing image to use (default `egresslens/base:latest`) |
| `--args "<args>"` | `run-app` | Arguments passed to the traced app |
| `--policy <path>` | all three | Allowlist to judge the capture against, required by `check` |
| `--reverse-dns` | all three | Allow live reverse DNS for unnamed public IPs (off by default) |
| `--events <path>` | `check` | Events file (default `<dir>/egress.jsonl`) |
| `--strace <path>` | `check` | Trace to read passive DNS from (default: the `egress.strace` beside the events file, if present) |
| `--format text\|json` | `check` | Output format (default `text`) |
| `--version` | – | Print the version |

`check` also takes `--reverse-dns-timeout` (default `0.5`) and
`--reverse-dns-max-ips` (default `100`), matching the backend's bounds.

## Output

Written to the output directory:

| File | Contents |
|---|---|
| `egress.jsonl` | One JSON object per network event |
| `egress.strace` | Raw strace output – upload this for domain enrichment |
| `run.json` | Run ID, command, image, timing, exit code, event counts |
| `cmd_stdout` | The traced command's stdout |
| `cmd_stderr` | The traced command's stderr |
| `pip_install.log` | `run-app` only, with a `requirements.txt`: the untraced install's output |

`run.json`'s `counts` record what the capture could *not* put in the report, so
the gap is visible even when the destinations are not:

| Counter | Meaning |
|---|---|
| `ipv6_connects_skipped` | AF_INET6 `connect()` calls seen but not captured (IPv4 only) |
| `udp_probes_skipped` | UDP `connect()` calls that transmitted nothing, so no packet reached the address |

`check` reads both. It raises a note for skipped IPv6 connections, because those
destinations were reached and are not in the verdict, and stays quiet about the
UDP probes, because those addresses were never contacted – glibc's address
sorting `connect()`s a UDP socket to each candidate answer purely to ask the
kernel which source address it would pick. Both counters appear under `capture`
in `--format json`; of the two, only `ipv6_connects_skipped` is rendered by the
UI and the markdown export.

Two shapes stay fail-closed and are counted as probes even though they might not
be: a connected UDP socket written with `write()` instead of `send*()`, and
traffic sent through a `dup()` of a connected fd. `-e trace=network` records
neither syscall, so nothing in the trace can tell them apart from a probe.

A UDP `connect()` with no send on the same socket is excluded, and counted under
`counts.udp_probes_skipped`. `connect()` on a datagram socket only sets a default
peer, it transmits nothing. glibc's resolver does one per candidate address to
learn which source address the kernel would pick (RFC 6724), so reporting them
would list destinations the process never contacted – for an app calling
`socket.gethostbyname` that was two thirds of its events. The test is
behavioural, not a port filter: a `connect()` followed by any send or receive on
that socket is real egress and is kept, including DNS over a connected socket. A
*failed* UDP `connect()` is also kept, since setting a peer is a local operation
and a refusal there is egress the app genuinely attempted.

## Docker image

The default image is `egresslens/base:latest`, built by `./docker-build.sh` (or
`docker build -t egresslens/base:latest .` from the repo root). Any replacement
passed via `--image` must have `strace` installed.

Tracing needs `CAP_SYS_PTRACE` and relaxed seccomp. See the
[main README](../README.md) for what that means for isolation.

## Programmatic use

```python
from pathlib import Path
from egresslens.watch import watch_command

exit_code = watch_command(
    command=["curl", "https://example.com"],
    output_dir=Path("egresslens-output"),
    image="egresslens/base:latest",
)
```

The verdict is a separate call, returning the exit code documented above:

```python
from pathlib import Path
from egresslens.check_command import EXIT_PASS, check_command

verdict = check_command(
    directory=Path("egresslens-output"),
    policy_path=Path("policy.json"),
)
if verdict != EXIT_PASS:
    ...
```

## Tests

pytest is not a declared dependency, so install it alongside the package:

```bash
pip install -e './cli[docker]' pytest
cd cli && pytest -v
```

`test_strace_integration.py` traces real loopback TCP and UDP sockets with a
locally installed `strace` and skips cleanly if `strace` is missing.

## Requirements

- Python 3.9+
- Docker – required for `run-app` and `watch`, not optional, there is no
  host-only mode. `check` needs neither Docker nor the backend: it reads files.
