"""Tests for installing the hook into settings.json.

This module writes to a file the user did not create and cannot easily
rebuild, so the tests are weighted towards *refusing* to act: unparseable
input, unexpected shapes, and failed backups must all leave the file alone.

Every test uses a temporary path. The ``isolate_home`` fixture in conftest
redirects ``Path.home()`` as a second line of defence, after a stale test
once rewrote a real developer's configuration.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from pkgpatrol.settings import (
    default_settings_path,
    hook_block,
    hook_command,
    install_hook,
)


def write(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def settings(tmp_path: Path) -> Path:
    return tmp_path / "settings.json"


# ---------------------------------------------------------------------------
# Creating and merging
# ---------------------------------------------------------------------------


def test_creates_the_file_when_absent(settings: Path) -> None:
    result = install_hook(settings)
    assert result.ok and result.changed
    assert read(settings)["hooks"]["PreToolUse"][0]["matcher"] == "Bash"


def test_preserves_unrelated_settings(settings: Path) -> None:
    """Their model, theme, and anything else must survive untouched."""
    write(settings, {"model": "opus", "theme": "dark", "effortLevel": "high"})
    install_hook(settings)
    data = read(settings)
    assert data["model"] == "opus"
    assert data["theme"] == "dark"
    assert data["effortLevel"] == "high"
    assert "hooks" in data


def test_preserves_other_hooks(settings: Path) -> None:
    other = {"matcher": "Write", "hooks": [{"type": "command", "command": "other"}]}
    write(settings, {"hooks": {"PreToolUse": [other]}})
    install_hook(settings)
    entries = read(settings)["hooks"]["PreToolUse"]
    assert other in entries
    assert len(entries) == 2


def test_preserves_other_hook_events(settings: Path) -> None:
    write(settings, {"hooks": {"PostToolUse": [{"matcher": "Bash", "hooks": []}]}})
    install_hook(settings)
    assert "PostToolUse" in read(settings)["hooks"]


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def test_running_twice_does_not_duplicate(settings: Path) -> None:
    """A second copy would run every check twice."""
    install_hook(settings)
    second = install_hook(settings)
    assert second.changed is False
    assert "already configured" in second.message
    assert len(read(settings)["hooks"]["PreToolUse"]) == 1


def test_existing_entry_is_updated_not_appended(settings: Path) -> None:
    install_hook(settings, executable="/old/path/pkgpatrol")
    install_hook(settings, executable="/new/path/pkgpatrol")
    entries = read(settings)["hooks"]["PreToolUse"]
    assert len(entries) == 1
    assert "/new/path/pkgpatrol" in entries[0]["hooks"][0]["command"]


def test_duplicate_entries_are_collapsed(settings: Path) -> None:
    block = hook_block("/x/pkgpatrol")
    write(settings, {"hooks": {"PreToolUse": [block, block, block]}})
    install_hook(settings)
    assert len(read(settings)["hooks"]["PreToolUse"]) == 1


# ---------------------------------------------------------------------------
# Refusing to act
# ---------------------------------------------------------------------------


def test_refuses_to_overwrite_invalid_json(settings: Path) -> None:
    """The user may be mid-edit. Destroying that work would be unforgivable,
    and indistinguishable from a bug in our writer."""
    settings.write_text('{"model": "opus",', encoding="utf-8")
    result = install_hook(settings)
    assert result.ok is False
    assert result.changed is False
    assert "not valid JSON" in result.message
    assert settings.read_text(encoding="utf-8") == '{"model": "opus",'


def test_refuses_a_non_object_top_level(settings: Path) -> None:
    write(settings, ["not", "an", "object"])
    result = install_hook(settings)
    assert result.ok is False
    assert read(settings) == ["not", "an", "object"]


def test_refuses_when_hooks_is_the_wrong_type(settings: Path) -> None:
    write(settings, {"hooks": "not an object"})
    result = install_hook(settings)
    assert result.ok is False
    assert "not an object" in result.message


def test_refuses_when_pretooluse_is_the_wrong_type(settings: Path) -> None:
    write(settings, {"hooks": {"PreToolUse": {"not": "a list"}}})
    result = install_hook(settings)
    assert result.ok is False
    assert "not a list" in result.message


def test_empty_file_is_treated_as_empty_settings(settings: Path) -> None:
    settings.write_text("", encoding="utf-8")
    result = install_hook(settings)
    assert result.ok and result.changed


# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------


def test_backup_is_written_before_changing(settings: Path) -> None:
    write(settings, {"model": "opus"})
    original = settings.read_text(encoding="utf-8")
    result = install_hook(settings)
    assert result.backup is not None
    assert result.backup.exists()
    assert result.backup.read_text(encoding="utf-8") == original


def test_no_backup_when_creating_a_new_file(settings: Path) -> None:
    result = install_hook(settings)
    assert result.backup is None


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------


def test_dry_run_changes_nothing(settings: Path) -> None:
    write(settings, {"model": "opus"})
    before = settings.read_text(encoding="utf-8")
    result = install_hook(settings, dry_run=True)
    assert result.changed is False
    assert "would have" in result.message
    assert settings.read_text(encoding="utf-8") == before


def test_dry_run_on_a_missing_file_creates_nothing(settings: Path) -> None:
    install_hook(settings, dry_run=True)
    assert not settings.exists()


# ---------------------------------------------------------------------------
# The command itself
# ---------------------------------------------------------------------------


def test_hook_command_is_absolute() -> None:
    r"""A bare name relies on a GUI-launched editor inheriting the right
    PATH, which is exactly what breaks for pipx and venv installs.

    Absoluteness is checked with ``os.path.isabs`` rather than a leading
    "/" — on Windows the resolved path is ``C:\...\pkgpatrol.EXE``, which
    an earlier Unix-shaped assertion rejected even though the code was
    behaving correctly.
    """
    command = hook_command()
    assert command.endswith(" hook")
    executable = command[: -len(" hook")]
    assert os.path.isabs(executable.split(" -m ")[0]), executable


def test_explicit_executable_is_used() -> None:
    assert hook_command("/opt/bin/pkgpatrol") == "/opt/bin/pkgpatrol hook"


def test_block_fails_open_and_is_bounded() -> None:
    inner = hook_block()["hooks"][0]
    assert inner["onFailure"] == "continue"
    assert inner["timeout"] == 10


def test_written_file_is_valid_json_with_trailing_newline(settings: Path) -> None:
    install_hook(settings)
    text = settings.read_text(encoding="utf-8")
    assert text.endswith("\n")
    json.loads(text)


def test_default_path_is_under_claude_config() -> None:
    path = default_settings_path()
    assert path.name == "settings.json"
    assert path.parent.name == ".claude"
