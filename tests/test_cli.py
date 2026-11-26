"""Tests for the command-line interface."""

from __future__ import annotations

import io

import pytest

from pkgpatrol import __version__
from pkgpatrol.cli import EXIT_OK, EXIT_UNIMPLEMENTED, main


def test_version_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    # argparse's `version` action raises SystemExit(0) after printing.
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_no_args_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == EXIT_OK
    assert "usage: pkgpatrol" in capsys.readouterr().out


def test_parse_subcommand_lists_packages(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["parse", "npm i express@4.18.0"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "express@4.18.0" in out


def test_parse_subcommand_reports_nothing_found(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["parse", "ls -la"]) == EXIT_OK
    assert "No package installs detected" in capsys.readouterr().out


def test_parse_subcommand_reports_skipped(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["parse", "npm i git+https://github.com/o/r.git"]) == EXIT_OK
    assert "skipped" in capsys.readouterr().out


@pytest.mark.parametrize("command", ["check", "init"])
def test_unimplemented_commands_fail_loudly(
    command: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """These must not exit 0 — a security tool that silently checks nothing
    is worse than one that admits it is unfinished.

    ``hook`` is deliberately absent: it is implemented, and must exit 0 even
    when it has nothing to say, or it would block the user's tool call.
    """
    argv = [command, "express"] if command == "check" else [command]
    assert main(argv) == EXIT_UNIMPLEMENTED
    assert "not implemented" in capsys.readouterr().err


def test_hook_subcommand_exits_zero_on_empty_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The opposite requirement from the test above: `hook` must never exit
    non-zero, since that becomes a blocking error in Claude Code."""
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert main(["hook"]) == EXIT_OK


def test_bad_subcommand_is_usage_error() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["nonsense"])
    assert excinfo.value.code == 2


# --------------------------------------------------------------------------
# hook / init subcommands
# --------------------------------------------------------------------------


def test_init_print_emits_valid_settings_json(
    capsys: pytest.CaptureFixture[str],
) -> None:
    import json as _json

    from pkgpatrol.cli import main as _main

    assert _main(["init", "--print"]) == EXIT_OK
    config = _json.loads(capsys.readouterr().out)
    block = config["hooks"]["PreToolUse"][0]
    assert block["matcher"] == "Bash"
    inner = block["hooks"][0]
    assert inner["type"] == "command"
    assert inner["command"].endswith("hook")
    # Bounded, and failing open — a hook failure must not block the user.
    assert inner["timeout"] == 10
    assert inner["onFailure"] == "continue"


def test_init_without_print_is_unimplemented(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Writing settings.json could break the user's Claude Code config, so it
    is deliberately deferred to its own change."""
    assert main(["init"]) == EXIT_UNIMPLEMENTED
    assert "--print" in capsys.readouterr().err


def test_hook_command_prefers_an_absolute_path() -> None:
    from pkgpatrol.cli import hook_command

    command = hook_command()
    # A bare name would rely on the GUI process inheriting the right PATH.
    assert command.endswith(" hook")
    assert "pkgpatrol" in command
