"""Command-line entry point for pkgpatrol.

Subcommands:

``check``   Vet packages named on the command line and print a report.
``hook``    Read a Claude Code ``PreToolUse`` payload on stdin and decide.
``init``    Install the hook into ``~/.claude/settings.json``.
``parse``   Show what the command parser extracts from a shell command.
            A debugging aid — it performs no network calls.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import __version__
from .analyze import DEFAULT_POLICY, Policy, Severity, decide
from .hook import run as run_hook
from .http import Deadline, HttpClient, JsonCache
from .parse import Ecosystem, PackageSpec, parse_command
from .registry import gather
from .report import Palette, render, supports_color
from .settings import hook_block, install_hook

#: Exit codes. 0 clean, 1 red flags found, 2 usage error (argparse's own),
#: 69 unavailable — borrowed from sysexits.h EX_UNAVAILABLE.
EXIT_OK = 0
EXIT_FLAGGED = 1
EXIT_UNIMPLEMENTED = 69

#: Budget for a CLI run. More generous than the hook's, because a person
#: waiting at a terminal tolerates a pause that a tool call cannot.
CLI_BUDGET_SECONDS = 20.0


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
    check.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="explain why each finding matters",
    )
    check.add_argument(
        "--no-color", action="store_true", help="disable ANSI color output"
    )
    check.add_argument(
        "--no-cache", action="store_true", help="ignore cached registry responses"
    )
    check.add_argument(
        "--json", action="store_true", help="emit machine-readable JSON instead"
    )

    subcommands.add_parser(
        "hook", help="run as a Claude Code PreToolUse hook (reads stdin)"
    )

    init = subcommands.add_parser(
        "init", help="install the hook into ~/.claude/settings.json"
    )
    init.add_argument(
        "--print",
        dest="print_only",
        action="store_true",
        help="print the config snippet instead of editing settings.json",
    )
    init.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would change without writing",
    )

    show = subcommands.add_parser(
        "parse", help="show what the parser extracts from a shell command"
    )
    show.add_argument("shell_command", metavar="COMMAND")

    return parser


# ---------------------------------------------------------------------------
# parse
# ---------------------------------------------------------------------------


def _cmd_parse(shell_command: str) -> int:
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


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


def _split_spec(raw: str, ecosystem: Ecosystem) -> PackageSpec:
    """Parse ``name@version`` / ``name==version`` as written on the CLI."""
    if ecosystem is Ecosystem.NPM:
        if raw.startswith("@"):
            at = raw.find("@", 1)
            if at != -1:
                return PackageSpec(raw[:at], ecosystem, raw[at + 1 :] or None)
            return PackageSpec(raw, ecosystem)
        name, sep, version = raw.partition("@")
        return PackageSpec(name, ecosystem, version or None if sep else None)

    for delimiter in ("===", "==", ">=", "<=", "~=", "!=", ">", "<"):
        if delimiter in raw:
            index = raw.index(delimiter)
            return PackageSpec(raw[:index].strip(), ecosystem, raw[index:].strip())
    return PackageSpec(raw.strip(), ecosystem)


def _cmd_check(args: argparse.Namespace, policy: Policy = DEFAULT_POLICY) -> int:
    ecosystem = Ecosystem(args.ecosystem)
    specs = [_split_spec(raw, ecosystem) for raw in args.packages]

    cache = JsonCache(enabled=not args.no_cache)
    client = HttpClient(cache=cache)
    results = gather(specs, client, Deadline(CLI_BUDGET_SECONDS))
    verdict = decide(results, auto_approving=False, policy=policy)

    if args.json:
        print(json.dumps(_as_json(verdict), indent=2))
    else:
        palette = Palette(False if args.no_color else supports_color())
        sys.stdout.write(render(verdict, palette, verbose=args.verbose))

    # Exit non-zero when anything needs attention, so `check` composes with
    # shell `&&` and can gate a CI step.
    return EXIT_FLAGGED if verdict.worst >= Severity.MEDIUM else EXIT_OK


def _as_json(verdict: object) -> dict:
    from .analyze import Verdict

    assert isinstance(verdict, Verdict)
    return {
        "decision": verdict.decision,
        "reason": verdict.reason,
        "packages": [
            {
                "name": facts.name,
                "ecosystem": str(facts.ecosystem),
                "requested": facts.requested,
                "resolved_version": facts.resolved_version,
                "resolution": str(facts.resolution),
                "exists": facts.exists,
                "unreachable": facts.unreachable,
                "advisories": list(facts.advisories),
                "findings": [
                    {
                        "code": finding.code,
                        "severity": finding.severity.label,
                        "summary": finding.summary,
                        "detail": finding.detail,
                    }
                    for finding in findings
                ],
            }
            for facts, findings in verdict.results
        ],
    }


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


def _cmd_init(args: argparse.Namespace) -> int:
    if args.print_only:
        print(json.dumps({"hooks": {"PreToolUse": [hook_block()]}}, indent=2))
        print(
            "\nMerge the above into ~/.claude/settings.json, or run "
            "`pkgpatrol init` to do it automatically.",
            file=sys.stderr,
        )
        return EXIT_OK

    result = install_hook(dry_run=args.dry_run)
    if not result.ok:
        print(f"pkgpatrol init: {result.message}", file=sys.stderr)
        if result.error:
            print(f"  {result.error}", file=sys.stderr)
        return EXIT_FLAGGED

    print(f"pkgpatrol init: {result.message}")
    print(f"  settings: {result.path}")
    if result.backup:
        print(f"  backup:   {result.backup}")
    if result.changed:
        print("\nStart a new Claude Code session to load the hook.")
    return EXIT_OK


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


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
    if args.command == "check":
        return _cmd_check(args)
    if args.command == "init":
        return _cmd_init(args)
    return EXIT_UNIMPLEMENTED  # pragma: no cover - argparse rejects first


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
