"""CLI entry point for EgressLens."""

import sys
from pathlib import Path
from typing import Optional

import click

from egresslens.watch import watch_command


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
@click.argument("cmd", nargs=-1, required=True)
def watch(
    out: Path,
    image: str,
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

    sys.exit(exit_code)


def main() -> None:
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
