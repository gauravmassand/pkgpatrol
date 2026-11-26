"""Claude Code ``PreToolUse`` hook protocol.

Claude Code runs this with a JSON payload on stdin before a tool call. We read
it, look for package installs in the ``Bash`` command, and answer with a
permission decision on stdout.

The contract (from Claude Code's hook documentation):

*Input* — JSON on stdin, with the fields we care about::

    {
      "hook_event_name": "PreToolUse",
      "tool_name": "Bash",
      "tool_input": {"command": "npm install express"},
      "permission_mode": "default",
      "cwd": "/path/to/project"
    }

*Output* — exit 0 and JSON on stdout::

    {
      "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": "...",
        "additionalContext": "..."
      }
    }

``permissionDecision`` is one of ``allow`` / ``deny`` / ``ask`` / ``defer``.

Two rules govern everything here:

**Never crash.** A traceback on stderr with a non-zero exit becomes a blocking
error, which would stop the user's work because *our* code broke. Every path
is wrapped; on internal error we emit nothing and exit 0, letting the tool call
proceed exactly as if we were not installed.

**Default to ``defer``, not ``allow``.** ``allow`` overrides the user's own
permission rules; ``defer`` lets their configured rules decide. We only speak
up when we have something to say.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from typing import IO, Any

from .parse import InstallCommand, parse_command

__all__ = [
    "Decision",
    "HookInput",
    "decide",
    "run",
]

#: Permission-mode values where the user has waived per-call prompts. In these
#: modes an `ask` decision is useless — nothing will prompt — so a genuine
#: finding has to escalate to `deny` to have any effect. This is what "work
#: even in auto-approve/yolo mode" means in practice.
#:
#: `auto` was found by logging real payloads, not from documentation: a live
#: session reported `permission_mode: "auto"`, which this set originally
#: missed. Since the list is discovered rather than specified, treat any
#: unrecognized mode conservatively via :func:`is_auto_approving` instead of
#: assuming prompts will reach the user.
AUTO_APPROVE_MODES = frozenset(
    {"auto", "bypassPermissions", "acceptEdits", "dangerouslySkipPermissions"}
)

#: Modes known to still prompt the user, where `ask` is meaningful.
INTERACTIVE_MODES = frozenset({"default", "plan", "ask", ""})

#: We only inspect Bash commands; every other tool is irrelevant to us.
WATCHED_TOOL = "Bash"
WATCHED_EVENT = "PreToolUse"


# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HookInput:
    """The subset of the hook payload pkgpatrol uses.

    Parsed leniently on purpose: an unknown field, a missing field, or a
    changed field type must not break the hook. Anything we cannot read
    becomes a default, and a payload we do not recognize is simply ignored.
    """

    event: str = ""
    tool_name: str = ""
    command: str = ""
    permission_mode: str = "default"
    cwd: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, payload: Any) -> HookInput:
        if not isinstance(payload, dict):
            return cls()
        tool_input = payload.get("tool_input")
        if not isinstance(tool_input, dict):
            tool_input = {}
        command = tool_input.get("command")
        return cls(
            event=_as_str(payload.get("hook_event_name")),
            tool_name=_as_str(payload.get("tool_name")),
            command=_as_str(command),
            permission_mode=_as_str(payload.get("permission_mode")) or "default",
            cwd=_as_str(payload.get("cwd")),
            raw=payload,
        )

    @property
    def is_relevant(self) -> bool:
        """True when this is a Bash PreToolUse call with a command to read."""
        return (
            self.event == WATCHED_EVENT
            and self.tool_name == WATCHED_TOOL
            and bool(self.command.strip())
        )

    @property
    def is_auto_approving(self) -> bool:
        """True when per-call prompts are suppressed, so `ask` would be a no-op.

        Unknown modes count as auto-approving. The mode vocabulary is not
        something we control, and the two mistakes are not symmetrical: if we
        wrongly assume a prompt will reach the user, a real finding gets
        swallowed and the install proceeds unchallenged. Assuming the opposite
        only costs a `deny` the user can override.
        """
        return self.permission_mode not in INTERACTIVE_MODES


def _as_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    """What we tell Claude Code to do.

    ``decision=None`` means "say nothing" — we emit no JSON at all and the
    tool call proceeds under the user's normal permission rules. That is the
    right answer for the overwhelming majority of commands, which contain no
    package install.
    """

    decision: str | None = None
    reason: str = ""
    context: str = ""

    def to_payload(self) -> dict[str, Any] | None:
        """Render as the ``hookSpecificOutput`` envelope, or None if silent."""
        if self.decision is None and not self.context:
            return None
        inner: dict[str, Any] = {"hookEventName": WATCHED_EVENT}
        if self.decision is not None:
            inner["permissionDecision"] = self.decision
            if self.reason:
                inner["permissionDecisionReason"] = self.reason
        if self.context:
            inner["additionalContext"] = self.context
        return {"hookSpecificOutput": inner}


#: The silent decision — used for irrelevant commands and internal errors.
SILENT = Decision()


# ---------------------------------------------------------------------------
# Decision logic
# ---------------------------------------------------------------------------


def _describe(installs: list[InstallCommand]) -> str:
    """One-line-per-install summary of what was detected."""
    lines: list[str] = []
    for install in installs:
        if install.specs:
            names = ", ".join(spec.display for spec in install.specs)
            lines.append(f"{install.manager} ({install.ecosystem}): {names}")
        if install.installs_manifest:
            lines.append(f"{install.manager} ({install.ecosystem}): manifest install")
        for target in install.skipped:
            lines.append(f"{install.manager}: {target} (not vettable)")
    return "\n".join(lines)


def decide(payload: Any) -> Decision:
    """Turn a hook payload into a decision.

    Pure: no I/O, no network. This is where registry lookups and red-flag
    analysis will plug in once the registry clients exist. For now it reports
    what it found and defers, so the hook can be installed and observed
    without being able to block anything.
    """
    hook_input = HookInput.from_json(payload)
    if not hook_input.is_relevant:
        return SILENT

    installs = parse_command(hook_input.command)
    if not installs:
        return SILENT

    vettable = [spec for install in installs for spec in install.specs]
    summary = _describe(installs)

    # TODO(registry): resolve versions, fetch advisories, and return `deny`
    # for known CVEs — escalating past `ask` when is_auto_approving is True.
    note = (
        f"pkgpatrol detected a package install:\n{summary}\n\n"
        f"Registry checks are not implemented yet, so this install was not "
        f"vetted."
    )
    if not vettable:
        note = (
            f"pkgpatrol detected a package install with nothing it can vet:\n{summary}"
        )

    return Decision(decision="defer", context=note)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run(stdin: IO[str] | None = None, stdout: IO[str] | None = None) -> int:
    """Read a payload, write a decision, and return an exit code.

    Always returns 0. Exit code 2 would block the tool call and exit 1 would
    surface an error notice — neither is appropriate for an internal failure
    on our side, because the user's install should not depend on our
    correctness.
    """
    source = stdin if stdin is not None else sys.stdin
    sink = stdout if stdout is not None else sys.stdout

    try:
        raw = source.read()
    except (OSError, UnicodeDecodeError):
        return 0

    if not raw.strip():
        return 0

    try:
        payload = json.loads(raw)
    except ValueError:
        # Malformed payload: not ours to fix, and not worth blocking over.
        return 0

    try:
        decision = decide(payload)
    except Exception:  # noqa: BLE001 - a bug here must not block the user
        return 0

    body = decision.to_payload()
    if body is None:
        return 0

    try:
        json.dump(body, sink)
        sink.write("\n")
        sink.flush()
    except (OSError, ValueError, TypeError):
        return 0

    return 0
