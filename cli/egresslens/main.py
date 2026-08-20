"""CLI entry point for EgressLens."""

import sys
from pathlib import Path
from typing import Optional

import click

from egresslens.check_command import EXIT_PASS, check_command
from egresslens.watch import watch_command
from egresslens.run_app_command import run_app_command


@click.group()
@click.version_option(version="0.1.0", prog_name="egresslens")
def cli() -> None:
    """EgressLens - Network egress monitoring tool."""
    pass


@cli.command()
@click.option(
    "--out",
    type=click.Path(path_type=Path),
    default=Path("egresslens-output"),
    help="Output directory (default: egresslens-output/)",
)
@click.option(
    "--image",
    type=str,
    default="egresslens/base:latest",
    help="Docker image with strace pre-installed (default: egresslens/base:latest)",
)
@click.option(
    "--policy",
    "policy_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Judge the capture against this allowlist afterwards (see 'check')",
)
@click.option(
    "--reverse-dns/--no-reverse-dns",
    default=False,
    help="With --policy, allow live reverse DNS lookups for unnamed IPs",
)
@click.argument("cmd", nargs=-1, required=True)
def watch(
    out: Path,
    image: str,
    policy_path: Optional[Path],
    reverse_dns: bool,
    cmd: tuple[str, ...],
) -> None:
    """Run a command and monitor network egress.

    CMD is the command to run. Use '--' to separate options from the command.

    Example:
        egresslens watch -- curl https://example.com
    """
    if not cmd:
        click.echo("Error: Command is required", err=True)
        sys.exit(1)

    # Convert tuple to list for easier manipulation
    command = list(cmd)

    # Call the watch command implementation (docker-only)
    exit_code = watch_command(
        command=command,
        output_dir=out,
        image=image,
    )

    sys.exit(_gate(exit_code, out, policy_path, reverse_dns))


@cli.command("run-app")
@click.option(
    "--out",
    type=click.Path(path_type=Path),
    default=Path("egresslens-output"),
    help="Output directory (default: egresslens-output/)",
)
@click.option(
    "--image",
    type=str,
    default="egresslens/base:latest",
    help="Docker image with strace pre-installed (default: egresslens/base:latest)",
)
@click.option(
    "--args",
    type=str,
    default="",
    help="Arguments to pass to the Python app (space-separated)",
)
@click.option(
    "--policy",
    "policy_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Judge the capture against this allowlist afterwards (see 'check')",
)
@click.option(
    "--reverse-dns/--no-reverse-dns",
    default=False,
    help="With --policy, allow live reverse DNS lookups for unnamed IPs",
)
@click.argument("app_path", type=click.Path(exists=True))
def run_app(
    out: Path,
    image: str,
    args: str,
    policy_path: Optional[Path],
    reverse_dns: bool,
    app_path: str,
) -> None:
    """Run a Python application and monitor network egress.

    This command is for Python projects only. It will automatically:
    - Discover the entry point (looks for __main__.py, main.py, or app.py)
    - Install dependencies from requirements.txt if present
    - Run the app with strace to capture network activity

    APP_PATH is the path to the Python app directory.

    Examples:
        egresslens run-app ./my_app
        egresslens run-app ./my_app --args "arg1 arg2"
        egresslens run-app ./sample_app --args "dns example.com"
    """
    # Parse app arguments
    app_args = args.split() if args else []

    # Call the run-app command implementation
    exit_code = run_app_command(
        app_path=app_path,
        app_args=app_args,
        output_dir=out,
        image=image,
    )

    sys.exit(_gate(exit_code, out, policy_path, reverse_dns))


@cli.command()
@click.option(
    "--policy",
    "policy_path",
    type=click.Path(path_type=Path),
    required=True,
    help="Allowlist to judge the capture against",
)
@click.option(
    "--events",
    "events_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Events file (default: DIRECTORY/egress.jsonl)",
)
@click.option(
    "--strace",
    "strace_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Trace to read passive DNS from (default: egress.strace beside the events file)",
)
@click.option(
    "--reverse-dns/--no-reverse-dns",
    default=False,
    help="Look up unnamed public IPs live. Off by default: it makes the gate non-reproducible",
)
@click.option(
    "--reverse-dns-timeout",
    type=float,
    default=0.5,
    show_default=True,
    help="Seconds allowed for each reverse DNS lookup",
)
@click.option(
    "--reverse-dns-max-ips",
    type=int,
    default=100,
    show_default=True,
    help="Maximum number of reverse DNS lookups",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Output format; json puts the whole verdict on stdout and nothing else",
)
@click.argument(
    "directory",
    type=click.Path(path_type=Path),
    required=False,
    default=Path("egresslens-output"),
)
def check(
    policy_path: Path,
    events_path: Optional[Path],
    strace_path: Optional[Path],
    reverse_dns: bool,
    reverse_dns_timeout: float,
    reverse_dns_max_ips: int,
    output_format: str,
    directory: Path,
) -> None:
    """Judge a capture against an egress allowlist.

    DIRECTORY is a capture output directory (default: egresslens-output/). Needs
    neither Docker nor the backend: it reads the artifacts a capture already
    wrote.

    Exit codes: 0 PASS, 1 FAIL, 2 error (unreadable artifacts or a malformed
    allowlist), 3 INCONCLUSIVE (nothing was observed, which is not a pass).

    Example:
        egresslens check egresslens-output/ --policy policy.json
    """
    sys.exit(
        check_command(
            directory=directory,
            policy_path=policy_path,
            events_path=events_path,
            strace_path=strace_path,
            reverse_dns=reverse_dns,
            reverse_dns_timeout=reverse_dns_timeout,
            reverse_dns_max_ips=reverse_dns_max_ips,
            output_format=output_format,
        )
    )


def _gate(
    exit_code: int,
    output_dir: Path,
    policy_path: Optional[Path],
    reverse_dns: bool,
) -> int:
    """Let a non-pass verdict override the traced command's own exit code.

    Without --policy the command's code is returned untouched, so nothing about
    the existing behaviour changes. With one, the verdict is the gate: FAIL or
    INCONCLUSIVE wins and PASS leaves the command's code alone. Both numbers are
    still recoverable -- run.json records the command's, and the printed verdict
    block states it -- with one residual ambiguity: a command that itself exits 3
    under a passing verdict looks like INCONCLUSIVE.
    """
    if policy_path is None:
        return exit_code

    verdict_code = check_command(
        directory=output_dir,
        policy_path=policy_path,
        reverse_dns=reverse_dns,
    )
    return exit_code if verdict_code == EXIT_PASS else verdict_code


def main() -> None:
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
