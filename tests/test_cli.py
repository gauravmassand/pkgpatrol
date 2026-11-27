"""Tests for the command-line interface."""

from __future__ import annotations

import pytest

from pkgpatrol import __version__
from pkgpatrol.cli import EXIT_FLAGGED, EXIT_OK, main


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


def test_bad_subcommand_is_usage_error() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["nonsense"])
    assert excinfo.value.code == 2


# --------------------------------------------------------------------------
# check
# --------------------------------------------------------------------------


def _stub_gather(monkeypatch: pytest.MonkeyPatch, *results) -> None:
    """Replace the registry lookup so `check` never touches the network."""
    monkeypatch.setattr("pkgpatrol.cli.gather", lambda *_a, **_k: list(results))


def _facts(name: str, **overrides: object):
    from pkgpatrol.parse import Ecosystem
    from pkgpatrol.registry import PackageFacts, Resolution

    base: dict = {
        "name": name,
        "ecosystem": Ecosystem.NPM,
        "resolved_version": "1.0.0",
        "resolution": Resolution.LATEST,
        "exists": True,
        "weekly_downloads": 9_000_000,
        "maintainers": 4,
        "repository": f"https://github.com/x/{name}",
    }
    base.update(overrides)
    return PackageFacts(**base)


def test_check_clean_package_exits_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_gather(monkeypatch, _facts("express"))
    assert main(["check", "express", "--no-color"]) == EXIT_OK
    assert "no red flags" in capsys.readouterr().out


def test_check_flagged_package_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Non-zero so `check` composes with `&&` and can gate a CI step."""
    _stub_gather(monkeypatch, _facts("evil", advisories=("GHSA-x",)))
    assert main(["check", "evil", "--no-color"]) == EXIT_FLAGGED
    assert "BLOCKED" in capsys.readouterr().out


def test_check_json_output_is_machine_readable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import json as _json

    _stub_gather(monkeypatch, _facts("evil", advisories=("GHSA-x",)))
    main(["check", "evil", "--json"])
    payload = _json.loads(capsys.readouterr().out)
    assert payload["decision"] == "deny"
    assert payload["packages"][0]["advisories"] == ["GHSA-x"]


def test_check_no_color_suppresses_escape_codes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("FORCE_COLOR", "1")
    _stub_gather(monkeypatch, _facts("express"))
    main(["check", "express", "--no-color"])
    assert "\033[" not in capsys.readouterr().out


def test_check_parses_npm_version_suffix(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list = []
    monkeypatch.setattr(
        "pkgpatrol.cli.gather",
        lambda specs, *_a, **_k: captured.extend(specs) or [_facts("express")],
    )
    main(["check", "express@4.17.1", "--no-color"])
    assert captured[0].name == "express"
    assert captured[0].version_spec == "4.17.1"


def test_check_parses_scoped_npm_name(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list = []
    monkeypatch.setattr(
        "pkgpatrol.cli.gather",
        lambda specs, *_a, **_k: captured.extend(specs) or [_facts("@types/node")],
    )
    main(["check", "@types/node@20.1.0", "--no-color"])
    assert captured[0].name == "@types/node"
    assert captured[0].version_spec == "20.1.0"


def test_check_parses_pypi_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list = []
    monkeypatch.setattr(
        "pkgpatrol.cli.gather",
        lambda specs, *_a, **_k: captured.extend(specs) or [_facts("requests")],
    )
    main(["check", "requests==2.28.0", "-e", "pypi", "--no-color"])
    assert captured[0].name == "requests"
    assert captured[0].version_spec == "==2.28.0"


# --------------------------------------------------------------------------
# init
# --------------------------------------------------------------------------


def test_init_print_emits_valid_config(capsys: pytest.CaptureFixture[str]) -> None:
    import json as _json

    assert main(["init", "--print"]) == EXIT_OK
    block = _json.loads(capsys.readouterr().out)["hooks"]["PreToolUse"][0]
    assert block["matcher"] == "Bash"
    inner = block["hooks"][0]
    assert inner["onFailure"] == "continue"
    assert inner["timeout"] == 10


def test_init_writes_settings(capsys: pytest.CaptureFixture[str]) -> None:
    """Runs against the temp HOME from conftest, never the real one."""
    import json as _json
    from pathlib import Path

    assert main(["init"]) == EXIT_OK
    written = _json.loads((Path.home() / ".claude/settings.json").read_text())
    assert written["hooks"]["PreToolUse"][0]["matcher"] == "Bash"
    assert "new Claude Code session" in capsys.readouterr().out


def test_init_is_idempotent(capsys: pytest.CaptureFixture[str]) -> None:
    main(["init"])
    capsys.readouterr()
    assert main(["init"]) == EXIT_OK
    assert "already configured" in capsys.readouterr().out


def test_init_dry_run_writes_nothing() -> None:
    from pathlib import Path

    assert main(["init", "--dry-run"]) == EXIT_OK
    assert not (Path.home() / ".claude/settings.json").exists()


def test_init_refuses_broken_settings(capsys: pytest.CaptureFixture[str]) -> None:
    from pathlib import Path

    target = Path.home() / ".claude/settings.json"
    target.write_text('{"broken":', encoding="utf-8")
    assert main(["init"]) == EXIT_FLAGGED
    assert "not valid JSON" in capsys.readouterr().err
    assert target.read_text(encoding="utf-8") == '{"broken":'
