# EgressLens CLI

Monitor network egress by running commands in isolated Docker containers and capturing network syscalls with `strace`.

## Quick start

From the project root, run the sample app:

```bash
egresslens run-app ./sample_app --args "dns example.com"
```

Output goes to `egresslens-output/` (use `--out <path>` to change it).

## Installation

```bash
pip install -r requirements.txt
```

Or from project root: `pip install -e cli/`

## Usage

```bash
egresslens watch -- <command>
```

**Options:** `--out <path>` · `--mode docker|host` · `--image <name>` · `--no-enrich`

**Examples:**

```bash
egresslens watch -- curl https://example.com

egresslens watch --out ./results -- curl https://example.com

egresslens run-app ./my_python_app --args "arg1 arg2"
```

## Primary outputs

- `egress.jsonl` — network connection events
- `run.json` — run metadata (timestamps, exit code, counts)

## Docker image

Build an image with strace for better performance:

```bash
./docker-build.sh
```

Default image: `egresslens/base:latest`. Override with `--image`; the image must have `strace` installed.

## Programmatic usage

```python
from pathlib import Path
from egresslens.watch import watch_command

exit_code = watch_command(
    command=["curl", "https://example.com"],
    output_dir=Path("egresslens-output"),
    mode="docker",
    image="egresslens/base:latest",
)
```

## Requirements

- Python 3.8+
- Docker (for `--mode docker`)

## Security

Requires elevated Docker capabilities (`CAP_SYS_PTRACE`) and relaxed seccomp for strace. See the main project README for details.
