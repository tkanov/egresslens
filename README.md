# EgressLens

Monitor outbound network activity from Python apps in Docker. Trace connections with `strace`, generate JSONL logs for analysis, and explore results in a web UI.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)](#prerequisites)
[![Docker 20.10+](https://img.shields.io/badge/docker-20.10+-2496ED.svg)](https://www.docker.com/)

---

## Prerequisites

- **Docker** - EgressLens runs applications in Docker containers to isolate and trace network activity
- **Python 3.8+** - for running the CLI
- **Linux/macOS** - EgressLens is built with Unix-like systems in mind

---

## Installation

```bash
# Clone the repository, and then
cd egresslens

# Install the CLI
pip install -e .
```

---

## Quick start

Analyze a Python app in 30 seconds:

```bash
egresslens run-app ./sample_app --args "dns example.com"
```

**Output files generated:**
- `egresslens-output/egress.jsonl` - network events
- `egresslens-output/run.json` - metadata and statistics
- `egresslens-output/cmd_stdout` - app output

---

## Security

EgressLens uses `strace` to trace network syscalls. Because `strace` relies on the Linux `ptrace` facility, Docker must run containers with **elevated capabilities** and **relaxed seccomp**.

> **WARNING**: This reduces container isolation compared to default Docker settings. Treat traced applications as untrusted code.

### Required Docker settings

The CLI runs containers with:

| Setting | Purpose |
|---------|---------|
| `--cap-add SYS_PTRACE` | Required for `strace` to attach to processes |
| `--security-opt seccomp=unconfined` | Allows `ptrace` syscalls (blocked by default seccomp) |
| `--read-only` | Root filesystem is read-only |
| `tmpfs` for `/tmp` (100MB), `/root/.local` (100MB), `/root/.cache` (50MB) | Writable scratch space for strace, pip installs, and Python app output |
| `--cap-drop ALL` | Drops all capabilities except those explicitly added |
| `--security-opt no-new-privileges` | Prevents privilege escalation |

**Volume mounts:**

| Container path | Host path | Mode |
|----------------|-----------|------|
| `/work` | App directory | Read-only |
| `/output` | Output directory (e.g. `egresslens-output/`) | Read-write |

### Recommendations

1. **Treat the target as untrusted** – Even inside Docker, the traced application runs with less isolation than a typical container.
2. **Use a throwaway VM or dedicated sandbox** – Avoid running EgressLens on production hosts. Use a disposable VM, CI runner, or dedicated analysis machine.
3. **Only mount the project directory** – The app directory is mounted read-only at `/work`. Do not mount sensitive paths.
4. **No secrets in environment** – Do not pass API keys, tokens, or other secrets to the container via environment variables. The container has network access and the traced app may exfiltrate them.
5. **Use the pre-built image** – The `egresslens/base` image is built for tracing. Avoid custom images from untrusted sources.

---

## Docker configuration

### Prerequisites

- Docker Engine 20.10+ (with BuildKit recommended)
- On Linux: your user must be in the `docker` group, or run with `sudo`

### Troubleshooting

#### "Operation not permitted" or ptrace errors

If you see errors like `ptrace(PTRACE_TRACEME, ...): Operation not permitted`:

1. **Verify capabilities** – Ensure the container is started with `--cap-add SYS_PTRACE` and `--security-opt seccomp=unconfined`. EgressLens sets these automatically; if you run Docker manually, include them.
2. **Check Docker daemon** – Some Docker installations (e.g. rootless Docker) may restrict `ptrace`. Try running with a standard Docker installation.
3. **SELinux/AppArmor** – On systems with mandatory access control, policies may block `ptrace`. You may need to adjust local policy or run in a less restrictive environment.

#### Permission denied on mounted volume

The app directory is mounted read-only at `/work`. If the app needs to write files, it must use `/tmp` or another tmpfs path. EgressLens provides tmpfs for `/tmp` (100MB), `/root/.local` (100MB), and `/root/.cache` (50MB). For `run-app` with `requirements.txt`, pip installs into `/tmp/pypackages` and dependencies are loaded from there. No persistent state is stored in the container.

#### Different Docker versions

- **Docker Desktop (Mac/Windows)** – Runs containers in a Linux VM. EgressLens should work; ensure the Docker Desktop Linux VM has sufficient resources.
- **Podman** – Podman’s rootless mode may have limitations with `ptrace`. Prefer rootful Podman or Docker for EgressLens.
- **Kubernetes** – Running EgressLens-style tracing in Kubernetes typically requires privileged pods; this is outside the scope of the default setup.

### Building the base image

For best performance, build the image with strace pre-installed:

```bash
# From the project root
./docker-build.sh

# Or manually
docker build -t egresslens/base:latest .
```

Then run with:

```bash
egresslens run-app ./sample_app --image egresslens/base:latest --args "dns example.com"
```

The CLI defaults to `egresslens/base:latest`. You can override with `--image` (e.g. `--image ubuntu:24.04`), but custom images must have `strace` installed; otherwise the run will fail.

---

## Project structure

- **[cli/](cli/README.md)**  
  Command-line tool for running a user-specified command in a Docker container, tracing its network syscalls with `strace`, and generating JSONL event logs and run metadata. This is the main entrypoint for capturing egress data.

- **[sample_app/](sample_app/README.md)**  
  A tiny Python app used for testing EgressLens. It performs DNS lookups and queries [crt.sh](https://crt.sh/) for certificate transparency entries, providing predictable network activity for demo and test runs.

- **[backend/](backend/README.md)**  
  FastAPI backend *(in progress)* for uploading, aggregating, and serving reports generated by the CLI.

- **[frontend/](frontend/README.md)**  
  React + TypeScript web UI *(in progress)* for exploring egress analysis reports.

---

## Analyzing Python projects

EgressLens provides a `run-app` command for analyzing **Python projects**. This command automatically discovers your app's entry point, installs dependencies, and captures all network activity.

### App structure requirements

Your Python app directory must contain one of these entry points:
- `__main__.py` (run as: `python -m <app_name>`)
- `main.py` (run as: `python main.py`)
- `app.py` (run as: `python app.py`)

**Optional: Automatic dependency installation**
- Include a `requirements.txt` file in your app directory
- Dependencies will be installed automatically before the app runs

### Example

```
my_app/
├── app.py              # Entry point (required)
├── requirements.txt    # Dependencies (optional)
└── other_modules.py    # Additional files
```

### Usage

```bash
# Basic usage
egresslens run-app ./your_python_app

# With arguments
egresslens run-app ./your_python_app --args "arg1 arg2"

# Example with sample_app
egresslens run-app ./sample_app --args "dns example.com"
```

---

