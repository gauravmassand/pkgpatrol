"""Command-line entry point for pkgpatrol.

Subcommands:

``check``   Vet packages named on the command line.
``hook``    Read a Claude Code ``PreToolUse`` payload on stdin and decide.
``init``    Print (or install) the hook configuration for
            ``~/.claude/settings.json``.
``parse``   Show what the command parser extracts from a shell command.
            A debugging aid — it performs no network calls.

``parse``, ``hook``, and ``init --print`` work. ``check`` and writing to
settings.json report that they are unimplemented and exit non-zero rather than
pretending to vet anything — a security tool that appears to run but checks
nothing is worse than one that admits it is unfinished.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections.abc import Sequence

from . import __version__
from .hook import run as run_hook
from .parse import Ecosystem, parse_command

#: Exit codes. 0 success, 1 red flags found, 2 usage error (argparse's own),
#: 69 unavailable — borrowed from sysexits.h EX_UNAVAILABLE.
EXIT_OK = 0
EXIT_FLAGGED = 1
EXIT_UNIMPLEMENTED = 69


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pkgpatrol",
        description="Vet npm and PyPI packages for supply-chain red flags "
        "before they install.",
    )
    parser.add_argument(
        "--version", action="version", version=f"pkgpatrol {__version__}"
    )

    subcommands = parser.add_subparsers(dest="command", metavar="<command>")

    check = subcommands.add_parser("check", help="vet one or more named packages")
    check.add_argument("packages", nargs="+", metavar="PACKAGE")
    check.add_argument(
        "-e",
        "--ecosystem",
        choices=[item.value for item in Ecosystem],
        default=Ecosystem.NPM.value,
        help="registry to query (default: npm)",
    )

    subcommands.add_parser(
        "hook", help="run as a Claude Code PreToolUse hook (reads stdin)"
    )

    init = subcommands.add_parser(
        "init", help="print the hook config for ~/.claude/settings.json"
    )
    init.add_argument(
        "--print",
        dest="print_only",
        action="store_true",
        help="print the config snippet instead of editing settings.json",
    )

    show = subcommands.add_parser(
        "parse", help="show what the parser extracts from a shell command"
    )
    show.add_argument("shell_command", metavar="COMMAND")

    return parser


def hook_command() -> str:
    """The command string to put in settings.json.

    Resolves to an absolute path when possible. A bare ``pkgpatrol`` would
    rely on the GUI process inheriting the right ``PATH``, which is exactly
    what breaks for pipx and venv installs launched outside a shell.
    """
    resolved = shutil.which("pkgpatrol")
    return f"{resolved} hook" if resolved else "pkgpatrol hook"


def hook_settings() -> dict[str, object]:
    """The ``settings.json`` fragment that registers the hook."""
    return {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command(),
                            # Bounded so a slow registry cannot stall the
                            # tool call; `continue` means a hook failure
                            # lets the command through rather than blocking.
                            "timeout": 10,
                            "onFailure": "continue",
                            "statusMessage": "Vetting packages",
                        }
                    ],
                }
            ]
        }
    }


def _cmd_parse(shell_command: str) -> int:
    """Print the parsed installs for ``shell_command``. No network access."""
    installs = parse_command(shell_command)
    if not installs:
        print("No package installs detected.")
        return EXIT_OK

    for install in installs:
        print(f"{install.manager} ({install.ecosystem})")
        for spec in install.specs:
            print(f"  package  {spec.display}")
        if install.installs_manifest:
            print("  manifest install (package.json / requirements.txt)")
        for target in install.skipped:
            print(f"  skipped  {target}  (no registry metadata)")
    return EXIT_OK


def _cmd_init_print() -> int:
    """Print the settings.json fragment for the user to merge by hand."""
    print(json.dumps(hook_settings(), indent=2))
    print(
        "\nMerge the above into ~/.claude/settings.json.\n"
        "If a PreToolUse array already exists, add the matcher block to it "
        "rather than replacing it.",
        file=sys.stderr,
    )
    return EXIT_OK


def _unimplemented(name: str, detail: str) -> int:
    print(f"pkgpatrol {name}: {detail}", file=sys.stderr)
    return EXIT_UNIMPLEMENTED


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return EXIT_OK
    if args.command == "parse":
        return _cmd_parse(args.shell_command)
    if args.command == "hook":
        return run_hook()
    if args.command == "init":
        if args.print_only:
            return _cmd_init_print()
        return _unimplemented(
            "init",
            "editing settings.json is not implemented yet.\n"
            "Run `pkgpatrol init --print` and merge the output by hand.",
        )
    return _unimplemented(
        args.command,
        "not implemented yet. Registry lookups are still in development.",
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
