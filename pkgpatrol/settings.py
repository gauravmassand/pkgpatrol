"""Install the hook into ``~/.claude/settings.json``.

This writes to a file the user did not create and cannot easily reconstruct.
Corrupting it would break their Claude Code setup, so the rules here are
stricter than anywhere else in the project:

**Never write over something unparseable.** If the file is not valid JSON we
stop. The user may have a half-finished edit open; overwriting it would
destroy work and the mistake would look like ours regardless.

**Always back up first**, with a timestamp, and tell the user the path.

**Merge, never replace.** Other hooks and unrelated settings are preserved.
A ``PreToolUse`` array that already holds entries keeps them.

**Be idempotent.** Running ``init`` twice must not produce two copies of the
same hook, which would double every check.
"""

from __future__ import annotations

import json
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

__all__ = [
    "SettingsResult",
    "default_settings_path",
    "hook_command",
    "hook_block",
    "install_hook",
]

WATCHED_TOOL = "Bash"
HOOK_TIMEOUT_SECONDS = 10


def default_settings_path() -> Path:
    return Path.home() / ".claude" / "settings.json"


def hook_command(executable: str | None = None) -> str:
    """The command string to register.

    Resolves to an absolute path. A bare ``pkgpatrol`` depends on the editor
    process inheriting a ``PATH`` that includes the install location, which
    is exactly what fails for pipx and venv installs launched from a GUI.
    """
    if executable:
        return f"{executable} hook"
    resolved = shutil.which("pkgpatrol")
    if resolved:
        return f"{resolved} hook"
    # Running from a venv without it on PATH: use this interpreter.
    return f"{sys.executable} -m pkgpatrol hook"


def hook_block(executable: str | None = None) -> dict[str, Any]:
    """The single ``PreToolUse`` matcher block pkgpatrol owns."""
    return {
        "matcher": WATCHED_TOOL,
        "hooks": [
            {
                "type": "command",
                "command": hook_command(executable),
                "timeout": HOOK_TIMEOUT_SECONDS,
                # A hook failure must let the command through. Fail open.
                "onFailure": "continue",
                "statusMessage": "Vetting packages",
            }
        ],
    }


@dataclass(frozen=True)
class SettingsResult:
    """What :func:`install_hook` did, or would have done."""

    changed: bool
    message: str
    path: Path
    backup: Path | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def _is_ours(entry: Any) -> bool:
    """True when a PreToolUse block was installed by us.

    Matched on the command containing ``pkgpatrol`` rather than on exact
    equality, so an entry survives being re-pointed at a different install
    path and does not get duplicated.
    """
    if not isinstance(entry, dict):
        return False
    for inner in entry.get("hooks", []) or []:
        if isinstance(inner, dict) and "pkgpatrol" in str(inner.get("command", "")):
            return True
    return False


def install_hook(
    path: Path | None = None,
    executable: str | None = None,
    dry_run: bool = False,
) -> SettingsResult:
    """Add (or update) the pkgpatrol hook in ``settings.json``.

    Returns a :class:`SettingsResult` rather than raising: this is called
    from a CLI where a clear message beats a traceback.
    """
    path = path or default_settings_path()

    existing: dict[str, Any] = {}
    if path.exists():
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            return SettingsResult(
                False, "could not read settings", path, error=str(exc)
            )
        if raw.strip():
            try:
                loaded = json.loads(raw)
            except ValueError as exc:
                # Refuse rather than clobber. The user may be mid-edit, and
                # their other settings are not ours to lose.
                return SettingsResult(
                    False,
                    "settings.json is not valid JSON — fix it first, "
                    "nothing was written",
                    path,
                    error=str(exc),
                )
            if not isinstance(loaded, dict):
                return SettingsResult(
                    False,
                    "settings.json does not contain a JSON object",
                    path,
                    error="unexpected top-level type",
                )
            existing = loaded

    updated = json.loads(json.dumps(existing))  # deep copy, JSON-safe by construction
    hooks = updated.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        return SettingsResult(
            False, "the 'hooks' key is not an object", path, error="unexpected type"
        )
    pre = hooks.setdefault("PreToolUse", [])
    if not isinstance(pre, list):
        return SettingsResult(
            False,
            "the 'hooks.PreToolUse' key is not a list",
            path,
            error="unexpected type",
        )

    block = hook_block(executable)
    ours = [index for index, entry in enumerate(pre) if _is_ours(entry)]

    if ours:
        # Idempotent: replace our entry in place rather than appending a
        # second copy, which would double every check.
        if all(pre[index] == block for index in ours) and len(ours) == 1:
            return SettingsResult(False, "already configured; nothing to do", path)
        for index in reversed(ours[1:]):
            del pre[index]
        pre[ours[0]] = block
        action = "updated the existing pkgpatrol hook"
    else:
        pre.append(block)
        action = "added the pkgpatrol hook"

    if dry_run:
        return SettingsResult(False, f"would have {action}", path)

    backup: Path | None = None
    if path.exists():
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = path.with_name(f"{path.name}.bak-{stamp}")
        try:
            backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        except OSError as exc:
            return SettingsResult(
                False, "could not write a backup; nothing changed", path, error=str(exc)
            )

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Write to a sibling then rename, so an interrupted write cannot
        # leave a truncated settings.json behind.
        temporary = path.with_name(f"{path.name}.tmp")
        temporary.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)
    except OSError as exc:
        return SettingsResult(
            False, "could not write settings", path, backup=backup, error=str(exc)
        )

    return SettingsResult(True, action, path, backup=backup)
