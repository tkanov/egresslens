"""Docker runner for executing commands with strace."""

import shlex
import subprocess
from pathlib import Path
from typing import Optional

try:
    import docker
    from docker.errors import DockerException, ImageNotFound
    DOCKER_SDK_AVAILABLE = True
except ImportError:
    DOCKER_SDK_AVAILABLE = False


DEFAULT_IMAGE = "egresslens/base:latest"

# strace's -s bounds how many bytes of each syscall string argument are recorded.
# The backend derives passive-DNS domains from captured recvfrom()/recvmsg()
# buffers, so this must be large enough to hold a whole DNS response. The old
# value of 256 truncated most real answers -- multiple A-records, EDNS, or CNAME
# chains easily exceed it -- which silently dropped enrichment. 4096 covers UDP
# DNS responses including EDNS0, at the cost of somewhat larger trace files.
STRACE_STRING_LIMIT = 4096

# Container exit status reported when the pre-trace setup step fails (see
# _build_strace_cmd). 90 sits above sysexits.h (64-78) and below the shell's
# 126-165 band, and pip itself exits 1-4. The status alone is not proof, because
# a traced app is free to exit 90 too -- see setup_step_failed.
SETUP_FAILED_EXIT_CODE = 90

# Where the dependency install's own stdout/stderr goes. Not /output/cmd_stdout:
# that file is the traced app's output, and mixing pip into it would make the
# app look like it printed things it never printed.
PIP_LOG_NAME = "pip_install.log"


def setup_step_failed(exit_code: int, strace_output_path: Path) -> bool:
    """Whether a run ended in the untraced setup step instead of the command.

    Two facts, because the exit status on its own is ambiguous. The container
    reports SETUP_FAILED_EXIT_CODE, *and* the trace is empty or absent: strace
    writes at least its own exit line for any command it runs, so an empty trace
    means strace never started, which is only true if the setup step failed
    first. An app that exits 90 by itself leaves a real trace, and treating that
    as a failed install would throw away a complete capture and replace it with a
    diagnostic about pip that is simply false.
    """
    if exit_code != SETUP_FAILED_EXIT_CODE:
        return False
    if not strace_output_path.exists():
        return True
    return strace_output_path.stat().st_size == 0


class DockerRunner:
    """Runner for executing commands in Docker containers with strace."""

    def __init__(self, image: str = DEFAULT_IMAGE):
        """Initialize Docker runner.

        Args:
            image: Docker image to use (must have strace pre-installed)
        """
        self.image = image
        self.client = None
        if DOCKER_SDK_AVAILABLE:
            try:
                self.client = docker.from_env()
            except DockerException:
                self.client = None

    def _build_strace_cmd(
        self,
        command: list[str],
        setup_command: Optional[str] = None,
    ) -> tuple[str, list[str]]:
        """Build the strace invocation and return the container path and command list.

        setup_command, when given, is a shell fragment (not user input) that runs
        in the container *before* strace starts, so its own network activity is
        not attributed to the traced command. If it fails, the container exits
        with SETUP_FAILED_EXIT_CODE and strace never runs at all.
        """
        escaped_cmd = " ".join(shlex.quote(arg) for arg in command)
        container_strace_path = "/output/egress.strace"

        # Capture the command's stdout/stderr into files under /output so callers can inspect them.
        cmd_capture = f"{escaped_cmd} > /output/cmd_stdout 2> /output/cmd_stderr"
        inner = shlex.quote(cmd_capture)
        script = (
            f"strace -f -ttt -e trace=network -s {STRACE_STRING_LIMIT} "
            f"-o {container_strace_path} -- sh -c {inner} && sync"
        )
        if setup_command:
            # sync before bailing out so whatever the setup step logged under
            # /output is durable; the trailing `&& sync` below is never reached
            # on this path.
            script = (
                f"{setup_command} || {{ sync; exit {SETUP_FAILED_EXIT_CODE}; }}\n"
                f"{script}"
            )
        strace_cmd = ["sh", "-c", script]
        return container_strace_path, strace_cmd

    def _ensure_output_parent(self, path: Path) -> None:
        """Ensure the parent directory for an output file exists."""
        path.parent.mkdir(parents=True, exist_ok=True)

    def _ensure_strace_file_exists(self, strace_output_path: Path) -> None:
        """Touch the strace output file if it doesn't exist to avoid downstream errors."""
        if not strace_output_path.exists():
            strace_output_path.touch()

    def _ran_only_the_setup_step(
        self,
        setup_command: Optional[str],
        exit_code: int,
        strace_output_path: Path,
    ) -> bool:
        """Whether this run got no further than its setup step.

        Used to skip _ensure_strace_file_exists, because creating the file would
        turn a run that never started into a zero-event capture, which reads as
        "no egress" instead of "no run".
        """
        return bool(setup_command) and setup_step_failed(exit_code, strace_output_path)

    def _default_image_hint(self) -> str:
        return (
            f"Docker image '{DEFAULT_IMAGE}' was not found locally. "
            "Build it from the repository root first: docker build -t egresslens/base:latest ."
        )

    def _ensure_default_image_available_sdk(self) -> Optional[str]:
        if self.image != DEFAULT_IMAGE or not self.client:
            return None
        try:
            self.client.images.get(self.image)
            return None
        except ImageNotFound:
            return self._default_image_hint()
        except Exception as e:
            return f"Failed to inspect Docker image '{self.image}': {e}"

    def _ensure_default_image_available_subprocess(self) -> Optional[str]:
        if self.image != DEFAULT_IMAGE:
            return None
        inspect_result = subprocess.run(
            ["docker", "image", "inspect", self.image],
            capture_output=True,
            text=True,
            check=False,
        )
        if inspect_result.returncode == 0:
            return None
        return self._default_image_hint()

    def run_with_strace(
        self,
        command: list[str],
        work_dir: Path,
        strace_output_path: Path,
        setup_command: Optional[str] = None,
    ) -> tuple[int, Optional[str]]:
        """Run command in Docker container with strace.

        Args:
            command: Command to run as list of strings
            work_dir: Working directory to mount (read-only)
            strace_output_path: Path where strace output will be saved
            setup_command: Optional shell fragment to run untraced beforehand

        Returns:
            Tuple of (exit_code, error_message). error_message is None on success.
        """
        if self.client:
            return self._run_with_docker_sdk(command, work_dir, strace_output_path, setup_command)
        else:
            return self._run_with_subprocess(command, work_dir, strace_output_path, setup_command)

    def _run_with_docker_sdk(
        self,
        command: list[str],
        work_dir: Path,
        strace_output_path: Path,
        setup_command: Optional[str] = None,
    ) -> tuple[int, Optional[str]]:
        """Run using Docker Python SDK."""
        try:
            # Prepare output dir and strace command
            self._ensure_output_parent(strace_output_path)
            image_error = self._ensure_default_image_available_sdk()
            if image_error:
                return 1, image_error
            _, strace_cmd = self._build_strace_cmd(command, setup_command)

            container = self.client.containers.run(
                self.image,
                command=strace_cmd,
                detach=True,
                read_only=True,
                tmpfs={
                    "/tmp": "rw,noexec,nosuid,size=100m",
                    "/root/.local": "rw,nosuid,size=100m",
                    "/root/.cache": "rw,nosuid,size=50m",
                },
                cap_drop=["ALL"],
                cap_add=["SYS_PTRACE"],
                security_opt=["seccomp=unconfined", "no-new-privileges"],
                volumes={
                    str(work_dir.absolute()): {
                        "bind": "/work",
                        "mode": "ro",
                    },
                    str(strace_output_path.parent.absolute()): {
                        "bind": "/output",
                        "mode": "rw",
                    }
                },
                working_dir="/work",
                remove=False,
            )

            # Wait for container to finish
            exit_code = container.wait()["StatusCode"]

            # Ensure strace file exists (touch if missing)
            if not self._ran_only_the_setup_step(setup_command, exit_code, strace_output_path):
                self._ensure_strace_file_exists(strace_output_path)

            # Remove container
            container.remove()

            return exit_code, None

        except Exception as e:
            return 1, f"Docker SDK error: {e}"

    def _run_with_subprocess(
        self,
        command: list[str],
        work_dir: Path,
        strace_output_path: Path,
        setup_command: Optional[str] = None,
    ) -> tuple[int, Optional[str]]:
        """Run using docker subprocess command."""
        try:
            # Prepare output dir and strace command
            self._ensure_output_parent(strace_output_path)
            image_error = self._ensure_default_image_available_subprocess()
            if image_error:
                return 1, image_error
            container_strace_path, strace_cmd = self._build_strace_cmd(command, setup_command)

            # Run container without --rm so we can copy files
            run_result = subprocess.run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--read-only",
                    "--tmpfs", "/tmp:rw,noexec,nosuid,size=100m",
                    "--tmpfs", "/root/.local:rw,nosuid,size=100m",
                    "--tmpfs", "/root/.cache:rw,nosuid,size=50m",
                    "--cap-drop", "ALL",
                    "--cap-add", "SYS_PTRACE",
                    "--security-opt", "seccomp=unconfined",
                    "--security-opt", "no-new-privileges",
                    "--volume", f"{work_dir.absolute()}:/work:ro",
                    "--volume", f"{strace_output_path.parent.absolute()}:/output:rw",
                    "--workdir", "/work",
                    self.image,
                ] + strace_cmd,
                capture_output=True,
                text=True,
                check=False,
            )

            if run_result.returncode != 0:
                return 1, f"Failed to start container: {run_result.stderr}"

            container_id = run_result.stdout.strip()
            if not container_id:
                return 1, "Failed to get container ID"

            # Wait for container to finish
            subprocess.run(["docker", "wait", container_id], capture_output=True, text=True, check=False)

            # Get exit code
            inspect_result = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.ExitCode}}", container_id],
                capture_output=True,
                text=True,
                check=False,
            )

            exit_code = 1
            if inspect_result.returncode == 0:
                try:
                    exit_code = int(inspect_result.stdout.strip())
                except ValueError:
                    pass

            # Ensure strace file exists (touch if missing)
            if not self._ran_only_the_setup_step(setup_command, exit_code, strace_output_path):
                self._ensure_strace_file_exists(strace_output_path)

            # Remove container
            subprocess.run(["docker", "rm", container_id], check=False, capture_output=True)

            return exit_code, None

        except Exception as e:
            return 1, f"Docker subprocess error: {e}"


def run_docker_command(
    command: list[str],
    work_dir: Path,
    image: str,
    strace_output_path: Path,
) -> tuple[int, Optional[str]]:
    """Convenience function to run command in Docker with strace.

    Args:
        command: Command to run as list of strings
        work_dir: Working directory to mount (read-only)
        image: Docker image to use
        strace_output_path: Path where strace output will be saved

    Returns:
        Tuple of (exit_code, error_message). error_message is None on success.
    """
    runner = DockerRunner(image=image)
    return runner.run_with_strace(command, work_dir, strace_output_path)


def run_python_app(
    app_path: Path,
    entry_point: str,
    app_args: list[str],
    has_requirements: bool,
    image: str,
    strace_output_path: Path,
) -> tuple[int, Optional[str]]:
    """Run a Python app in Docker with strace, installing dependencies if needed.

    Args:
        app_path: Path to the app directory (will be mounted as /work)
        entry_point: Name of the Python entry point file (e.g., "app.py", "main.py")
        app_args: Command-line arguments to pass to the app
        has_requirements: Whether to install from requirements.txt before tracing starts
        image: Docker image to use
        strace_output_path: Path where strace output will be saved

    Returns:
        Tuple of (exit_code, error_message). error_message is None on success.
    """
    # Build the command to run in the container
    # If entry_point is __main__.py, run as module; otherwise run the file directly
    if entry_point == "__main__.py":
        python_cmd = ["python", "-m", app_path.name] + app_args
    else:
        python_cmd = ["python", entry_point] + app_args

    # If requirements.txt exists, install dependencies first, outside the trace.
    # pip resolves and downloads from PyPI, and tracing that made every run report
    # PyPI's CDN as the app's own egress -- for sample_app that was 84% of the
    # events. The install therefore runs before strace starts: only the app is
    # traced, and PYTHONPATH is exported so strace's child inherits it.
    setup_command = None
    if has_requirements:
        # Install to /tmp since container filesystem is read-only
        # Use --break-system-packages for PEP 668 compliance in container
        install_cmd = (
            "pip install -q --break-system-packages --target=/tmp/pypackages "
            f"-r requirements.txt > /output/{PIP_LOG_NAME} 2>&1"
        )
        setup_command = f"{install_cmd} && export PYTHONPATH=/tmp/pypackages:$PYTHONPATH"

    # Use the standard Docker runner
    runner = DockerRunner(image=image)
    exit_code, error = runner.run_with_strace(
        python_cmd, app_path, strace_output_path, setup_command
    )

    if setup_command and error is None and setup_step_failed(exit_code, strace_output_path):
        pip_log = strace_output_path.parent / PIP_LOG_NAME
        error = (
            "Installing requirements.txt failed, so the app never ran and nothing "
            f"was traced. pip's output: {pip_log}"
        )

    return exit_code, error
