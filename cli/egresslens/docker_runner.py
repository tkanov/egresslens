"""Docker runner for executing commands with strace."""

import shlex
import subprocess
from pathlib import Path
from typing import Optional

try:
    import docker
    from docker.errors import DockerException
    DOCKER_SDK_AVAILABLE = True
except ImportError:
    DOCKER_SDK_AVAILABLE = False


class DockerRunner:
    """Runner for executing commands in Docker containers with strace."""

    def __init__(self, image: str = "egresslens/base:latest"):
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

    def _build_strace_cmd(self, command: list[str]) -> tuple[str, list[str]]:
        """Build the strace invocation and return the container path and command list."""
        escaped_cmd = " ".join(shlex.quote(arg) for arg in command)
        container_strace_path = "/output/egress.strace"

        # Capture the command's stdout/stderr into files under /output so callers can inspect them.
        cmd_capture = f"{escaped_cmd} > /output/cmd_stdout 2> /output/cmd_stderr"
        inner = shlex.quote(cmd_capture)
        strace_cmd = [
            "sh", "-c",
            f"strace -f -ttt -e trace=network -s 256 -o {container_strace_path} -- sh -c {inner} && sync"
        ]
        return container_strace_path, strace_cmd

    def _ensure_output_parent(self, path: Path) -> None:
        """Ensure the parent directory for an output file exists."""
        path.parent.mkdir(parents=True, exist_ok=True)

    def _ensure_strace_file_exists(self, strace_output_path: Path) -> None:
        """Touch the strace output file if it doesn't exist to avoid downstream errors."""
        if not strace_output_path.exists():
            strace_output_path.touch()

    def run_with_strace(
        self,
        command: list[str],
        work_dir: Path,
        strace_output_path: Path,
    ) -> tuple[int, Optional[str]]:
        """Run command in Docker container with strace.

        Args:
            command: Command to run as list of strings
            work_dir: Working directory to mount (read-only)
            strace_output_path: Path where strace output will be saved

        Returns:
            Tuple of (exit_code, error_message). error_message is None on success.
        """
        if self.client:
            return self._run_with_docker_sdk(command, work_dir, strace_output_path)
        else:
            return self._run_with_subprocess(command, work_dir, strace_output_path)

    def _run_with_docker_sdk(
        self,
        command: list[str],
        work_dir: Path,
        strace_output_path: Path,
    ) -> tuple[int, Optional[str]]:
        """Run using Docker Python SDK."""
        try:
            # Prepare output dir and strace command
            self._ensure_output_parent(strace_output_path)
            _, strace_cmd = self._build_strace_cmd(command)

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
    ) -> tuple[int, Optional[str]]:
        """Run using docker subprocess command."""
        try:
            # Prepare output dir and strace command
            self._ensure_output_parent(strace_output_path)
            container_strace_path, strace_cmd = self._build_strace_cmd(command)

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
        has_requirements: Whether to install from requirements.txt before running
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

    # If requirements.txt exists, install dependencies first
    if has_requirements:
        # Install to /tmp since container filesystem is read-only
        # Use --break-system-packages for PEP 668 compliance in container
        install_cmd = "pip install -q --break-system-packages --target=/tmp/pypackages -r requirements.txt"
        python_cmd_str = " ".join(shlex.quote(arg) for arg in python_cmd)
        # Set PYTHONPATH to include installed packages
        combined_cmd = ["sh", "-c", f"{install_cmd} && PYTHONPATH=/tmp/pypackages:$PYTHONPATH {python_cmd_str}"]
        command = combined_cmd
    else:
        command = python_cmd

    # Use the standard Docker runner
    runner = DockerRunner(image=image)
    return runner.run_with_strace(command, app_path, strace_output_path)

