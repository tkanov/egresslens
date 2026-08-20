#!/usr/bin/env python3
"""Tests for the Docker/strace runner.

docker_runner.py is the component that decides what actually gets traced and how
much isolation the traced code loses, and it had no tests at all -- so neither
the strace flags the backend depends on nor the container hardening flags were
pinned by anything. These tests cover command construction, and what a run leaves
behind in its output directory; they never talk to a Docker daemon.

The output-directory tests drive the run-app and watch commands rather than the
runner, because this is the module with the faked docker CLI.
"""

import json
import shlex
import subprocess
from types import SimpleNamespace

import pytest

from egresslens import docker_runner
from egresslens.docker_runner import (
    DEFAULT_IMAGE,
    PIP_LOG_NAME,
    SETUP_FAILED_EXIT_CODE,
    STRACE_STRING_LIMIT,
    DockerRunner,
    run_python_app,
)
from egresslens.run_app_command import run_app_command
from egresslens.watch import watch_command


@pytest.fixture(autouse=True)
def force_subprocess_path(monkeypatch):
    """Make every test in this module take the docker-CLI path, deterministically.

    Necessary, not cosmetic: run_python_app and run_docker_command construct their
    own DockerRunner, so on any machine with the Docker SDK installed and a
    reachable daemon -- every CI runner, now that the [docker] extra is installed
    -- they would take the SDK branch and try to start a real container instead of
    hitting the faked subprocess. Patching the flag also means docker.from_env()
    is never called, so nothing here probes a daemon at all.
    """
    monkeypatch.setattr(docker_runner, "DOCKER_SDK_AVAILABLE", False)


def subprocess_runner(image: str = DEFAULT_IMAGE) -> DockerRunner:
    """A runner on the subprocess path (see the autouse fixture above)."""
    runner = DockerRunner(image=image)
    assert runner.client is None, "expected the SDK path to be disabled"
    return runner


def inner_command(strace_cmd: list) -> list:
    """Recover the traced argv from the nested `sh -c` in a strace invocation.

    The inner script is `<argv> > /output/cmd_stdout 2> /output/cmd_stderr`, so
    the redirections are dropped to leave just the command being traced.
    """
    assert strace_cmd[0] == "sh"
    assert strace_cmd[1] == "-c"
    outer_tokens = shlex.split(strace_cmd[2])
    # ... -- sh -c '<inner>' && sync
    inner_script = outer_tokens[outer_tokens.index("--") + 3]

    argv = []
    for token in shlex.split(inner_script):
        if token.startswith(">") or token.endswith(">"):
            break
        argv.append(token)
    return argv


def container_script(argv: list) -> str:
    """The shell script the container runs, from a `docker run ... <image> sh -c <script>`."""
    cmd = argv[argv.index(DEFAULT_IMAGE) + 1:]
    assert cmd[:2] == ["sh", "-c"]
    return cmd[2]


def split_at_strace(script: str) -> tuple:
    """Split a container script into (what runs untraced first, the strace part)."""
    start = script.index("strace -f")
    return script[:start], script[start:]


# --- strace invocation: the backend depends on these flags ---------------------

def test_strace_flags_match_what_the_backend_parses():
    container_path, cmd = subprocess_runner()._build_strace_cmd(["python", "app.py"])
    script = cmd[2]

    assert container_path == "/output/egress.strace"
    # -f follows forks (pip and the app are separate processes); -ttt gives the
    # epoch timestamps the parser reads; trace=network is the syscall class that
    # includes connect and the send*/recv* family.
    assert "strace -f -ttt -e trace=network" in script
    assert f"-s {STRACE_STRING_LIMIT}" in script
    assert "-o /output/egress.strace" in script


def test_strace_string_limit_is_large_enough_for_a_dns_response():
    """The backend derives passive DNS from captured recvfrom/recvmsg buffers.

    512 bytes is the classic UDP DNS payload limit and EDNS0 goes past it, so a
    -s below that silently truncates answers and drops domain enrichment without
    any error. Pinned so it cannot be lowered unnoticed.
    """
    assert STRACE_STRING_LIMIT >= 4096


def test_traced_command_survives_shell_quoting():
    argv = ["python", "app.py", "--name", "two words", "semi;colon", "$(whoami)"]
    _, cmd = subprocess_runner()._build_strace_cmd(argv)
    assert inner_command(cmd)[: len(argv)] == argv


def test_command_stdout_and_stderr_are_captured_to_output():
    _, cmd = subprocess_runner()._build_strace_cmd(["python", "app.py"])
    assert "/output/cmd_stdout" in cmd[2]
    assert "/output/cmd_stderr" in cmd[2]


# --- container hardening: reduced isolation, so pin what is compensating -------

def fake_subprocess(monkeypatch, image_present=True, exit_code="0"):
    """Replace subprocess.run with a recorder that fakes the docker CLI."""
    calls = []

    def run(cmd, **kwargs):
        calls.append(list(cmd))
        if cmd[:3] == ["docker", "image", "inspect"]:
            return SimpleNamespace(returncode=0 if image_present else 1, stdout="", stderr="")
        if len(cmd) > 1 and cmd[1] == "run":
            return SimpleNamespace(returncode=0, stdout="container123\n", stderr="")
        if len(cmd) > 1 and cmd[1] == "inspect":
            return SimpleNamespace(returncode=0, stdout=f"{exit_code}\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(docker_runner.subprocess, "run", run)
    return calls


def docker_run_argv(calls: list) -> list:
    return next(cmd for cmd in calls if len(cmd) > 1 and cmd[1] == "run")


def test_container_runs_with_compensating_hardening(monkeypatch, tmp_path):
    calls = fake_subprocess(monkeypatch)
    strace_path = tmp_path / "out" / "egress.strace"

    exit_code, error = subprocess_runner().run_with_strace(
        ["python", "app.py"], tmp_path / "work", strace_path
    )

    assert (exit_code, error) == (0, None)
    argv = docker_run_argv(calls)

    # Tracing needs SYS_PTRACE and an unconfined seccomp profile; everything else
    # is dropped to compensate. Documented in README "Security Model".
    assert ["--cap-add", "SYS_PTRACE"] == argv[argv.index("--cap-add"):][:2]
    assert ["--cap-drop", "ALL"] == argv[argv.index("--cap-drop"):][:2]
    assert "--read-only" in argv
    assert "no-new-privileges" in argv
    assert "seccomp=unconfined" in argv

    # The app directory is mounted read-only; only /output is writable.
    assert f"{(tmp_path / 'work').absolute()}:/work:ro" in argv
    assert f"{strace_path.parent.absolute()}:/output:rw" in argv


def test_strace_file_is_created_even_when_the_container_wrote_nothing(monkeypatch, tmp_path):
    fake_subprocess(monkeypatch)
    strace_path = tmp_path / "out" / "egress.strace"

    subprocess_runner().run_with_strace(["python", "app.py"], tmp_path, strace_path)

    # Downstream parsing expects the file to exist rather than to be handled as a
    # special case in every caller.
    assert strace_path.exists()


def test_nonzero_container_exit_code_is_reported(monkeypatch, tmp_path):
    fake_subprocess(monkeypatch, exit_code="42")
    exit_code, error = subprocess_runner().run_with_strace(
        ["python", "app.py"], tmp_path, tmp_path / "egress.strace"
    )
    assert exit_code == 42
    assert error is None


def test_missing_default_image_explains_how_to_build_it(monkeypatch, tmp_path):
    fake_subprocess(monkeypatch, image_present=False)
    exit_code, error = subprocess_runner().run_with_strace(
        ["python", "app.py"], tmp_path, tmp_path / "egress.strace"
    )
    assert exit_code == 1
    assert error is not None
    assert DEFAULT_IMAGE in error
    assert "docker build" in error


def test_custom_image_is_not_probed_for_the_default_hint(monkeypatch, tmp_path):
    """Only the default image gets the build hint; a custom one is the user's job."""
    calls = fake_subprocess(monkeypatch, image_present=False)
    exit_code, error = subprocess_runner(image="my/own:tag").run_with_strace(
        ["python", "app.py"], tmp_path, tmp_path / "egress.strace"
    )
    assert (exit_code, error) == (0, None)
    assert not any(cmd[:3] == ["docker", "image", "inspect"] for cmd in calls)
    assert "my/own:tag" in docker_run_argv(calls)


# --- run_python_app: how a Python project is turned into a command -------------

def test_plain_entry_point_runs_the_file(monkeypatch, tmp_path):
    calls = fake_subprocess(monkeypatch)
    app_dir = tmp_path / "myapp"
    app_dir.mkdir()

    run_python_app(
        app_path=app_dir,
        entry_point="app.py",
        app_args=["dns", "example.com"],
        has_requirements=False,
        image=DEFAULT_IMAGE,
        strace_output_path=tmp_path / "egress.strace",
    )

    argv = docker_run_argv(calls)
    traced = inner_command(argv[argv.index(DEFAULT_IMAGE) + 1:])
    assert traced == ["python", "app.py", "dns", "example.com"]


def test_requirements_are_installed_before_the_app_runs(monkeypatch, tmp_path):
    calls = fake_subprocess(monkeypatch)
    app_dir = tmp_path / "myapp"
    app_dir.mkdir()

    run_python_app(
        app_path=app_dir,
        entry_point="main.py",
        app_args=[],
        has_requirements=True,
        image=DEFAULT_IMAGE,
        strace_output_path=tmp_path / "egress.strace",
    )

    argv = docker_run_argv(calls)
    script = " ".join(argv[argv.index(DEFAULT_IMAGE) + 1:])
    # The container filesystem is read-only, so packages go to the /tmp tmpfs and
    # PYTHONPATH points at them. --break-system-packages is for PEP 668.
    assert "pip install" in script
    assert "--target=/tmp/pypackages" in script
    assert "--break-system-packages" in script
    assert "PYTHONPATH=/tmp/pypackages" in script
    assert "-r requirements.txt" in script


def test_dependency_install_runs_outside_the_trace(monkeypatch, tmp_path):
    """pip's own downloads must not be reported as the app's egress.

    With strace on the outside, every run of an app with a requirements.txt
    reported PyPI's CDN as a destination the app reached -- for sample_app that
    was 84% of the events and 4 of the 5 unique destinations. So the install runs
    first, untraced, and strace wraps only the app.
    """
    calls = fake_subprocess(monkeypatch)
    app_dir = tmp_path / "myapp"
    app_dir.mkdir()

    run_python_app(
        app_path=app_dir,
        entry_point="app.py",
        app_args=["dns", "example.com"],
        has_requirements=True,
        image=DEFAULT_IMAGE,
        strace_output_path=tmp_path / "egress.strace",
    )

    script = container_script(docker_run_argv(calls))
    untraced, traced = split_at_strace(script)

    assert "pip install" in untraced
    assert "pip install" not in traced
    assert inner_command(["sh", "-c", traced]) == ["python", "app.py", "dns", "example.com"]


def test_pip_output_is_kept_out_of_the_app_capture_files(monkeypatch, tmp_path):
    """cmd_stdout/cmd_stderr are the app's output; pip gets its own log.

    pip used to share those files, so its noise was indistinguishable from
    whatever the app printed.
    """
    calls = fake_subprocess(monkeypatch)
    app_dir = tmp_path / "myapp"
    app_dir.mkdir()

    run_python_app(
        app_path=app_dir,
        entry_point="app.py",
        app_args=[],
        has_requirements=True,
        image=DEFAULT_IMAGE,
        strace_output_path=tmp_path / "egress.strace",
    )

    untraced, traced = split_at_strace(container_script(docker_run_argv(calls)))
    assert f"/output/{PIP_LOG_NAME}" in untraced
    assert "/output/cmd_stdout" not in untraced
    assert "/output/cmd_stderr" not in untraced
    assert "/output/cmd_stdout" in traced
    assert "/output/cmd_stderr" in traced


def test_an_app_without_requirements_is_traced_from_the_first_syscall(monkeypatch, tmp_path):
    """No install means nothing to exclude, so the command is what it always was."""
    calls = fake_subprocess(monkeypatch)
    app_dir = tmp_path / "myapp"
    app_dir.mkdir()

    run_python_app(
        app_path=app_dir,
        entry_point="app.py",
        app_args=["dns", "example.com"],
        has_requirements=False,
        image=DEFAULT_IMAGE,
        strace_output_path=tmp_path / "egress.strace",
    )

    script = container_script(docker_run_argv(calls))
    assert script.startswith("strace -f -ttt")
    assert "pip" not in script


def test_watch_style_invocation_is_unchanged():
    """`watch` installs nothing, so excluding the install must not touch it.

    Pinned as the literal script rather than as substrings, because the whole
    point is that these bytes did not move.
    """
    _, cmd = subprocess_runner()._build_strace_cmd(["curl", "https://example.com"])
    assert cmd == [
        "sh",
        "-c",
        f"strace -f -ttt -e trace=network -s {STRACE_STRING_LIMIT} "
        "-o /output/egress.strace -- sh -c 'curl https://example.com "
        "> /output/cmd_stdout 2> /output/cmd_stderr' && sync",
    ]


def test_app_args_survive_both_levels_of_sh(monkeypatch, tmp_path):
    """The install step adds a shell level, so arguments are quoted twice over."""
    calls = fake_subprocess(monkeypatch)
    app_dir = tmp_path / "myapp"
    app_dir.mkdir()
    nasty = ["--name", "two words", "semi;colon", "$(whoami)", "quo'te", "back\\slash"]

    run_python_app(
        app_path=app_dir,
        entry_point="app.py",
        app_args=nasty,
        has_requirements=True,
        image=DEFAULT_IMAGE,
        strace_output_path=tmp_path / "egress.strace",
    )

    _, traced = split_at_strace(container_script(docker_run_argv(calls)))
    assert inner_command(["sh", "-c", traced]) == ["python", "app.py"] + nasty


# --- a failed install is not a quiet capture -----------------------------------

def test_a_failed_setup_step_never_reaches_strace():
    """Real sh, not a substring check: the guard has to short-circuit.

    Runs the built script with a setup step that fails. strace is not installed
    on the host, so reaching it would show up as a 127 instead.
    """
    _, cmd = subprocess_runner()._build_strace_cmd(["true"], setup_command="false")
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert result.returncode == SETUP_FAILED_EXIT_CODE


def test_a_failed_install_reports_the_failure_instead_of_an_empty_capture(monkeypatch, tmp_path):
    """No strace file: an empty one would read as "the app made no connections"."""
    fake_subprocess(monkeypatch, exit_code=str(SETUP_FAILED_EXIT_CODE))
    app_dir = tmp_path / "myapp"
    app_dir.mkdir()
    strace_path = tmp_path / "out" / "egress.strace"

    exit_code, error = run_python_app(
        app_path=app_dir,
        entry_point="app.py",
        app_args=[],
        has_requirements=True,
        image=DEFAULT_IMAGE,
        strace_output_path=strace_path,
    )

    assert exit_code == SETUP_FAILED_EXIT_CODE
    assert error is not None
    assert "requirements.txt" in error
    assert PIP_LOG_NAME in error
    assert not strace_path.exists()


def test_the_reserved_status_only_means_install_failure_when_there_was_an_install(
    monkeypatch, tmp_path
):
    """An app that happens to exit 90 on its own was still traced."""
    fake_subprocess(monkeypatch, exit_code=str(SETUP_FAILED_EXIT_CODE))
    app_dir = tmp_path / "myapp"
    app_dir.mkdir()
    strace_path = tmp_path / "out" / "egress.strace"

    exit_code, error = run_python_app(
        app_path=app_dir,
        entry_point="app.py",
        app_args=[],
        has_requirements=False,
        image=DEFAULT_IMAGE,
        strace_output_path=strace_path,
    )

    assert (exit_code, error) == (SETUP_FAILED_EXIT_CODE, None)
    assert strace_path.exists()


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Known bug: for a __main__.py entry point the runner builds "
        "`python -m <basename of app dir>` while the working directory IS that "
        "directory, so the module is never on sys.path under that name and the "
        "run fails with ModuleNotFoundError. __main__.py is checked FIRST by "
        "discover_entry_point, so the canonical runnable-package layout is the "
        "one that breaks. Remove this marker when the command is fixed."
    ),
)
def test_main_module_entry_point_is_runnable(monkeypatch, tmp_path):
    calls = fake_subprocess(monkeypatch)
    app_dir = tmp_path / "myapp"
    app_dir.mkdir()

    run_python_app(
        app_path=app_dir,
        entry_point="__main__.py",
        app_args=[],
        has_requirements=False,
        image=DEFAULT_IMAGE,
        strace_output_path=tmp_path / "egress.strace",
    )

    argv = docker_run_argv(calls)
    traced = inner_command(argv[argv.index(DEFAULT_IMAGE) + 1:])
    # Working directory is /work, which is the app directory itself, so the
    # package name is not importable. `python .` and `python __main__.py` both
    # work; `python -m myapp` does not.
    assert traced in (["python", "."], ["python", "__main__.py"])


# --- the output directory describes this run, not the last one ----------------

def python_app(tmp_path, with_requirements=True):
    """A minimal app directory that passes validate_app_directory."""
    app_dir = tmp_path / "myapp"
    app_dir.mkdir()
    (app_dir / "app.py").write_text("print('hello')\n")
    if with_requirements:
        (app_dir / "requirements.txt").write_text("requests>=2.0\n")
    return app_dir


def seed_previous_run(output_dir):
    """A complete, apparently-successful report from an earlier run."""
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "run.json").write_text(json.dumps({"exit_code": 0}))
    (output_dir / "egress.jsonl").write_text(
        '{"ts": 1.0, "pid": 1, "event": "connect", "family": "inet", "proto": "tcp", '
        '"dst_ip": "93.184.216.34", "dst_port": 443, "result": "ok", "errno": null}\n'
    )
    (output_dir / "egress.strace").write_text(
        '1 1.0 connect(3, {sa_family=AF_INET, sin_port=htons(443), '
        'sin_addr=inet_addr("93.184.216.34")}, 16) = 0\n'
    )


def test_a_failed_install_removes_the_previous_runs_report(monkeypatch, tmp_path, capsys):
    """The worst case this guards: a CI gate reading a report of a run that never ran.

    The install fails, so nothing is written -- and if the previous run's
    artifacts survived, whatever reads the directory next sees a full report with
    exit_code 0 in it.
    """
    fake_subprocess(monkeypatch, exit_code=str(SETUP_FAILED_EXIT_CODE))
    output_dir = tmp_path / "out"
    seed_previous_run(output_dir)

    exit_code = run_app_command(
        app_path=str(python_app(tmp_path)),
        app_args=[],
        output_dir=output_dir,
        image=DEFAULT_IMAGE,
    )

    assert exit_code == SETUP_FAILED_EXIT_CODE
    assert not (output_dir / "run.json").exists()
    assert not (output_dir / "egress.jsonl").exists()
    assert not (output_dir / "egress.strace").exists()
    assert "No report was written." in capsys.readouterr().err


def test_clearing_the_output_directory_spares_files_it_did_not_write(monkeypatch, tmp_path):
    """--out is a user-supplied path; only the known artifact names are removed."""
    fake_subprocess(monkeypatch)
    output_dir = tmp_path / "out"
    seed_previous_run(output_dir)
    (output_dir / "policy.json").write_text('{"allow": ["example.com"]}')
    (output_dir / "notes.txt").write_text("keep me\n")

    run_app_command(
        app_path=str(python_app(tmp_path)),
        app_args=[],
        output_dir=output_dir,
        image=DEFAULT_IMAGE,
    )

    assert (output_dir / "policy.json").read_text() == '{"allow": ["example.com"]}'
    assert (output_dir / "notes.txt").read_text() == "keep me\n"
    # and this run's own report is there, not the seeded one
    assert json.loads((output_dir / "run.json").read_text())["counts"]["total_events"] == 0


def test_watch_does_not_report_a_previous_runs_trace(monkeypatch, tmp_path):
    """watch has no install step, but a container that never starts writes no trace."""
    fake_subprocess(monkeypatch, image_present=False)
    output_dir = tmp_path / "out"
    seed_previous_run(output_dir)

    exit_code = watch_command(
        command=["curl", "https://example.com"],
        output_dir=output_dir,
        image=DEFAULT_IMAGE,
    )

    assert exit_code == 1
    assert not (output_dir / "egress.strace").exists()
    metadata = json.loads((output_dir / "run.json").read_text())
    assert metadata["counts"]["total_events"] == 0


def main():
    raise SystemExit(subprocess.call(["pytest", "-v", __file__]))


if __name__ == "__main__":
    main()
