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
Without it the runner shells out to the `docker` CLI instead, which works fine —
the extra just selects which path runs.

## Quick start

Build the tracing image once, then trace the sample app:

```bash
docker build -t egresslens/base:latest .
egresslens run-app ./sample_app --args "dns example.com"
```

Output goes to `egresslens-output/`.

## Commands

### `run-app` — trace a Python project

```bash
egresslens run-app ./my_python_app --args "arg1 arg2"
```

Finds the entry point (`__main__.py`, `main.py`, or `app.py`, in that order),
installs `requirements.txt` if present, and runs it under trace.

> **Known bug:** the `__main__.py` case does not work. The runner invokes
> `python -m <app dir name>` while the working directory *is* that directory, so
> the module is never on `sys.path` under that name and the run fails with
> `ModuleNotFoundError`. Since `__main__.py` is checked first, the canonical
> runnable-package layout is the one that breaks. Use `main.py` or `app.py` for
> now; the failure is pinned by a strict xfail in `test_docker_runner.py`.

### `watch` — trace any command

```bash
egresslens watch -- curl https://example.com
```

Everything after `--` is the command. It runs inside the tracing image, so the
binaries and libraries it needs must already be in that image — `watch` does not
install anything.

### Options

| Option | Commands | Description |
|---|---|---|
| `--out <path>` | both | Where to write output (default `egresslens-output/`) |
| `--image <name>` | both | Tracing image to use (default `egresslens/base:latest`) |
| `--args "<args>"` | `run-app` | Arguments passed to the traced app |
| `--version` | — | Print the version |

## Output

Written to the output directory:

| File | Contents |
|---|---|
| `egress.jsonl` | One JSON object per network event |
| `egress.strace` | Raw strace output — upload this for domain enrichment |
| `run.json` | Run ID, command, image, timing, exit code, event counts |
| `cmd_stdout` | The traced command's stdout |
| `cmd_stderr` | The traced command's stderr |

IPv6 destinations are not captured. Those reached via `connect()` are counted in
`run.json` under `counts.ipv6_connects_skipped`, so the number is visible even
though the destinations are not.

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
- Docker — required, not optional; there is no host-only mode
