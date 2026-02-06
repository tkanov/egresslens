# EgressLens CLI

Command-line tool for monitoring network egress by running commands in isolated Docker containers and capturing network syscalls using `strace`.

## Installation

Install dependencies:

```bash
pip install -r requirements.txt
```

Install in development mode:

```bash
pip install -e .
```

Or install from the project root:

```bash
pip install -e cli/
```

## Usage

```bash
egresslens watch -- <command>
```

### Options

- `--out <path>`: Output directory (default: `egresslens-output/`)
- `--mode docker|host`: Execution mode (default: `docker`)
- `--image <name>`: Docker image with strace pre-installed (default: `egresslens/base:latest`)
- `--no-enrich`: Disable DNS enrichment (reverse lookups)

### Examples

```bash
# Monitor a curl command
egresslens watch -- curl https://example.com

# Use custom output directory
egresslens watch --out ./results -- curl https://example.com

# Use a different Docker image
egresslens watch --image alpine:latest -- wget https://example.com
```

## Output

The CLI generates two files in the output directory:

- `egress.jsonl`: JSONL file with network connection events
- `run.json`: Metadata about the run (timestamps, exit code, counts, etc.)

## Programmatic Usage

You can also use `watch.py` as a Python module:

```python
from pathlib import Path
from egresslens.watch import watch_command

# Run a command and monitor network egress
exit_code = watch_command(
    command=["curl", "https://example.com"],
    output_dir=Path("egresslens-output"),
    mode="docker",
    image="egresslens/base:latest",
    no_enrich=False,
)

# The function returns the exit code from the executed command
# Output files are written to the specified output_dir
```

## Requirements

- Python 3.8+
- Docker (for `--mode docker`)
- Docker image with `strace` pre-installed (e.g. `egresslens/base:latest` from `./docker-build.sh`)

## Docker Image

For better performance, you can build a custom Docker image with strace pre-installed:

```bash
# From the project root
./docker-build.sh

# Or manually
docker build -t egresslens/base:latest .
```

Then use it with:

```bash
egresslens watch --image egresslens/base:latest -- curl https://example.com
```

The CLI defaults to `egresslens/base:latest`. Build it first with `./docker-build.sh`. You can override with `--image` (e.g. `--image ubuntu:24.04`), but the image must have `strace` installed.

## Security Note

This tool requires elevated Docker capabilities (`CAP_SYS_PTRACE`) and relaxed seccomp settings to use `strace`. This reduces container isolation. See the main project README for security recommendations.

## Python Support

The `run-app` command supports running Python projects with automatic dependency installation:

```bash
# Python app with requirements.txt
egresslens run-app ./my_python_app --args "arg1 arg2"

# Dependencies are automatically installed from requirements.txt
# The root filesystem is read-only, but pip can write to:
# - /tmp (100MB tmpfs for installations)
# - /root/.local (100MB tmpfs for user site-packages)
# - /root/.cache (50MB tmpfs for pip cache)
```

**Note:** Python dependencies are installed fresh in each container run into temporary in-memory filesystems. This is by design for security and reproducibility. No persistent state is stored in the container.