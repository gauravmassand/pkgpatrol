"""Tests for the Claude Code PreToolUse hook protocol.

The governing requirement is that **the hook must never break the user's
workflow**. A non-zero exit or a traceback becomes a blocking error in Claude
Code, so every malformed, hostile, or surprising input below must still exit 0.
"""

from __future__ import annotations

import io
import json

import pytest

from pkgpatrol.analyze import Severity
from pkgpatrol.hook import (
    AUTO_APPROVE_MODES,
    SILENT,
    Decision,
    HookInput,
    decide,
    run,
)
from pkgpatrol.parse import Ecosystem
from pkgpatrol.registry import PackageFacts, Resolution


def clean_facts(name: str, **overrides: object) -> PackageFacts:
    """A healthy package, so the baseline decision is `defer`."""
    base: dict = {
        "name": name,
        "ecosystem": Ecosystem.NPM,
        "resolved_version": "1.0.0",
        "resolution": Resolution.LATEST,
        "exists": True,
        "weekly_downloads": 5_000_000,
        "maintainers": 4,
        "repository": f"https://github.com/x/{name}",
    }
    base.update(overrides)
    return PackageFacts(**base)  # type: ignore[arg-type]


def stub_lookup(**per_name: object):
    """Build a lookup that answers from canned facts — never the network.

    Tests must not depend on npm being reachable, and must not be slowed by
    real HTTP. `test_registry.py` covers the real fetch path.
    """

    def _lookup(specs, _deadline):
        return [
            per_name.get(spec.name) or clean_facts(spec.name)  # type: ignore[misc]
            for spec in specs
        ]

    return _lookup


OFFLINE = stub_lookup()


def payload(
    command: str,
    *,
    event: str = "PreToolUse",
    tool: str = "Bash",
    mode: str = "default",
) -> dict:
    return {
        "hook_event_name": event,
        "tool_name": tool,
        "permission_mode": mode,
        "cwd": "/tmp/project",
        "tool_input": {"command": command},
    }


def invoke(data: object, lookup=None) -> tuple[int, dict | None]:
    """Run the hook end-to-end over stdin/stdout, as Claude Code does.

    Defaults to an offline lookup: these tests exercise the protocol, not the
    registries, and a test suite that needs the internet is a flaky one.
    """
    text = data if isinstance(data, str) else json.dumps(data)
    out = io.StringIO()
    code = run(stdin=io.StringIO(text), stdout=out, lookup=lookup or OFFLINE)
    written = out.getvalue().strip()
    return code, (json.loads(written) if written else None)


# ---------------------------------------------------------------------------
# Relevance filtering
# ---------------------------------------------------------------------------


def test_install_command_produces_a_decision() -> None:
    code, body = invoke(payload("npm install express"))
    assert code == 0
    assert body is not None
    inner = body["hookSpecificOutput"]
    assert inner["hookEventName"] == "PreToolUse"
    assert "express" in inner["additionalContext"]


def test_non_install_command_is_silent() -> None:
    """The common case. Staying silent keeps the hook cheap and invisible."""
    code, body = invoke(payload("git status"))
    assert code == 0
    assert body is None


@pytest.mark.parametrize(
    "command", ["ls -la", "npm run build", "pytest", "echo hi", "cd /tmp"]
)
def test_ordinary_commands_are_silent(command: str) -> None:
    code, body = invoke(payload(command))
    assert (code, body) == (0, None)


def test_other_tools_are_ignored() -> None:
    code, body = invoke(payload("npm install express", tool="Read"))
    assert (code, body) == (0, None)


def test_other_events_are_ignored() -> None:
    code, body = invoke(payload("npm install express", event="PostToolUse"))
    assert (code, body) == (0, None)


def test_empty_command_is_ignored() -> None:
    code, body = invoke(payload("   "))
    assert (code, body) == (0, None)


# ---------------------------------------------------------------------------
# Malformed input — all must exit 0 and never raise
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "not json at all",
        "{broken",
        "[]",
        "null",
        "42",
        '"a string"',
        "{}",
        '{"tool_input": "not a dict"}',
        '{"tool_input": {"command": null}}',
        '{"tool_name": 42, "hook_event_name": []}',
        '{"hook_event_name": "PreToolUse", "tool_name": "Bash"}',
    ],
)
def test_malformed_payloads_exit_zero(raw: str) -> None:
    code, body = invoke(raw)
    assert code == 0, f"{raw!r} must not produce a non-zero exit"
    assert body is None


def test_deeply_nested_payload_does_not_crash() -> None:
    nested: dict = {"a": {}}
    cursor = nested["a"]
    for _ in range(200):
        cursor["a"] = {}
        cursor = cursor["a"]
    code, _ = invoke(nested)
    assert code == 0


def test_unicode_command_is_handled() -> None:
    code, _ = invoke(payload("npm install café-pkg 🎉"))
    assert code == 0


def test_very_long_command_is_handled() -> None:
    code, body = invoke(
        payload("npm install " + " ".join(f"pkg{i}" for i in range(500)))
    )
    assert code == 0
    assert body is not None


def test_internal_error_still_exits_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    """If our own logic throws, the user's command must proceed anyway."""
    import pkgpatrol.hook as hook_module

    def boom(_payload: object) -> Decision:
        raise RuntimeError("simulated bug")

    monkeypatch.setattr(hook_module, "decide", boom)
    code, body = invoke(payload("npm install express"))
    assert code == 0
    assert body is None


def test_unreadable_stdin_exits_zero() -> None:
    class Hostile(io.StringIO):
        def read(self, *_args: object) -> str:
            raise OSError("pipe closed")

    assert run(stdin=Hostile(), stdout=io.StringIO()) == 0


def test_unwritable_stdout_exits_zero() -> None:
    class Hostile(io.StringIO):
        def write(self, _s: str) -> int:
            raise OSError("broken pipe")

    code = run(
        stdin=io.StringIO(json.dumps(payload("npm i express"))), stdout=Hostile()
    )
    assert code == 0


# ---------------------------------------------------------------------------
# Decision semantics
# ---------------------------------------------------------------------------


def test_defers_rather_than_allowing() -> None:
    """`allow` would override the user's own permission rules; `defer` lets
    them decide. We must not silently widen permissions."""
    decision = decide(payload("npm install express"), lookup=OFFLINE)
    assert decision.decision == "defer"


def test_reports_every_detected_package() -> None:
    decision = decide(
        payload("npm i react react-dom && pip install httpx"), lookup=OFFLINE
    )
    for name in ("react", "react-dom", "httpx"):
        assert name in decision.context


def test_reports_unvettable_targets() -> None:
    decision = decide(payload("npm i git+https://github.com/o/r.git"), lookup=OFFLINE)
    assert "not vettable" in decision.context


def test_reports_what_it_actually_checked() -> None:
    """Honesty requirement, now in the other direction: having really checked,
    the hook must name the exact version it checked — the resolved version may
    differ from what installs moments later."""
    decision = decide(payload("npm install express"), lookup=OFFLINE)
    assert "express@1.0.0" in decision.context


def test_manifest_install_is_reported() -> None:
    decision = decide(payload("npm ci"), lookup=OFFLINE)
    assert "manifest" in decision.context


# ---------------------------------------------------------------------------
# HookInput parsing
# ---------------------------------------------------------------------------


def test_hook_input_reads_the_fields_we_need() -> None:
    parsed = HookInput.from_json(payload("npm i express", mode="bypassPermissions"))
    assert parsed.event == "PreToolUse"
    assert parsed.tool_name == "Bash"
    assert parsed.command == "npm i express"
    assert parsed.permission_mode == "bypassPermissions"
    assert parsed.cwd == "/tmp/project"
    assert parsed.is_relevant is True


def test_hook_input_tolerates_wrong_types() -> None:
    parsed = HookInput.from_json({"tool_name": 7, "tool_input": ["nope"]})
    assert parsed.tool_name == ""
    assert parsed.command == ""
    assert parsed.is_relevant is False


def test_hook_input_from_non_dict() -> None:
    assert HookInput.from_json("string").is_relevant is False
    assert HookInput.from_json(None).is_relevant is False


def test_permission_mode_defaults_to_default() -> None:
    assert HookInput.from_json({}).permission_mode == "default"


@pytest.mark.parametrize("mode", sorted(AUTO_APPROVE_MODES))
def test_auto_approve_modes_are_detected(mode: str) -> None:
    """In these modes `ask` is a no-op, so a real finding must escalate to
    `deny` — this flag is how that gets decided."""
    assert HookInput.from_json(payload("npm i x", mode=mode)).is_auto_approving


@pytest.mark.parametrize("mode", ["default", "plan", "", "ask"])
def test_interactive_modes_are_not_auto_approving(mode: str) -> None:
    assert not HookInput.from_json(payload("npm i x", mode=mode)).is_auto_approving


def test_auto_mode_is_auto_approving() -> None:
    """Regression: a live session reported `permission_mode: "auto"`, which the
    original hard-coded set missed. In auto mode nothing prompts, so an `ask`
    decision would be silently discarded and a real finding lost."""
    assert HookInput.from_json(payload("npm i x", mode="auto")).is_auto_approving


@pytest.mark.parametrize("mode", ["yolo", "someFutureMode", "AUTO", "bypass"])
def test_unknown_modes_are_treated_as_auto_approving(mode: str) -> None:
    """The mode vocabulary is not ours to control, and the two errors are not
    symmetrical: wrongly assuming a prompt reaches the user swallows a real
    finding, while the opposite only costs a `deny` the user can override."""
    assert HookInput.from_json(payload("npm i x", mode=mode)).is_auto_approving


# ---------------------------------------------------------------------------
# Decision payload shape
# ---------------------------------------------------------------------------


def test_silent_decision_renders_nothing() -> None:
    assert SILENT.to_payload() is None


def test_decision_includes_reason_when_present() -> None:
    body = Decision(decision="deny", reason="CVE-2024-1").to_payload()
    assert body is not None
    inner = body["hookSpecificOutput"]
    assert inner["permissionDecision"] == "deny"
    assert inner["permissionDecisionReason"] == "CVE-2024-1"


def test_decision_omits_empty_reason() -> None:
    body = Decision(decision="defer").to_payload()
    assert body is not None
    assert "permissionDecisionReason" not in body["hookSpecificOutput"]


def test_context_only_decision_is_emitted() -> None:
    body = Decision(context="just so you know").to_payload()
    assert body is not None
    assert body["hookSpecificOutput"]["additionalContext"] == "just so you know"
    assert "permissionDecision" not in body["hookSpecificOutput"]


def test_output_is_valid_json_on_one_line() -> None:
    out = io.StringIO()
    run(stdin=io.StringIO(json.dumps(payload("npm i express"))), stdout=out)
    text = out.getvalue()
    assert text.endswith("\n")
    json.loads(text)  # must parse


# ---------------------------------------------------------------------------
# Blocking: the point of the whole tool
# ---------------------------------------------------------------------------


def test_advisory_produces_a_deny() -> None:
    lookup = stub_lookup(evil=clean_facts("evil", advisories=("GHSA-xxxx",)))
    decision = decide(payload("npm install evil"), lookup=lookup)
    assert decision.decision == "deny"
    assert "GHSA-xxxx" in decision.context or "advisor" in decision.reason


def test_advisory_denies_in_auto_approve_mode() -> None:
    """The explicit requirement: a CVE blocks even when nothing would prompt."""
    lookup = stub_lookup(evil=clean_facts("evil", advisories=("GHSA-xxxx",)))
    decision = decide(payload("npm install evil", mode="auto"), lookup=lookup)
    assert decision.decision == "deny"


def test_nonexistent_package_denies() -> None:
    lookup = stub_lookup(typo=clean_facts("typo", exists=False, resolved_version=None))
    decision = decide(payload("npm install typo"), lookup=lookup)
    assert decision.decision == "deny"


def test_high_severity_asks_when_prompts_work() -> None:
    lookup = stub_lookup(odd=clean_facts("odd", yanked=True))
    decision = decide(payload("npm install odd", mode="default"), lookup=lookup)
    assert decision.decision == "ask"


def test_high_severity_escalates_to_deny_under_auto_approve() -> None:
    """`ask` is discarded when prompts are suppressed, so the finding would be
    lost exactly when the user cannot catch it themselves."""
    lookup = stub_lookup(odd=clean_facts("odd", yanked=True))
    decision = decide(payload("npm install odd", mode="auto"), lookup=lookup)
    assert decision.decision == "deny"
    assert "auto-approve" in decision.reason


def test_clean_package_defers_with_a_summary() -> None:
    decision = decide(payload("npm install express"), lookup=OFFLINE)
    assert decision.decision == "defer"
    assert "nothing of concern" in decision.context


def test_deny_reaches_claude_code_as_json() -> None:
    lookup = stub_lookup(evil=clean_facts("evil", advisories=("GHSA-x",)))
    code, body = invoke(payload("npm install evil"), lookup=lookup)
    assert code == 0, "a deny is still exit 0; the JSON carries the decision"
    assert body is not None
    inner = body["hookSpecificOutput"]
    assert inner["permissionDecision"] == "deny"
    assert inner["permissionDecisionReason"]


# ---------------------------------------------------------------------------
# Failing open
# ---------------------------------------------------------------------------


def test_lookup_exception_does_not_block() -> None:
    """Our bug must never stop the user's install."""

    def broken(_specs, _deadline):
        raise RuntimeError("registry client exploded")

    decision = decide(payload("npm install express"), lookup=broken)
    assert decision.decision == "defer"
    assert "could not check" in decision.context


def test_unreachable_registry_does_not_block() -> None:
    lookup = stub_lookup(express=clean_facts("express", unreachable=True))
    decision = decide(payload("npm install express"), lookup=lookup)
    assert decision.decision == "defer"


def test_unreachable_registry_does_not_block_in_auto_approve() -> None:
    """Ignorance is not grounds for blocking, in any mode."""
    lookup = stub_lookup(express=clean_facts("express", unreachable=True))
    decision = decide(payload("npm install express", mode="auto"), lookup=lookup)
    assert decision.decision == "defer"


def test_manifest_install_needs_no_lookup() -> None:
    """`npm ci` names no packages, so there is nothing to resolve."""

    def must_not_be_called(_specs, _deadline):
        raise AssertionError("no lookup should happen for a manifest install")

    decision = decide(payload("npm ci"), lookup=must_not_be_called)
    assert decision.decision == "defer"


def test_unvettable_targets_need_no_lookup() -> None:
    def must_not_be_called(_specs, _deadline):
        raise AssertionError("git URLs cannot be looked up")

    decision = decide(
        payload("npm i git+https://github.com/o/r.git"), lookup=must_not_be_called
    )
    assert decision.decision == "defer"
    assert "cannot vet" in decision.context


def test_findings_are_rendered_with_severity() -> None:
    lookup = stub_lookup(old=clean_facts("old", deprecated="unmaintained"))
    decision = decide(payload("npm install old"), lookup=lookup)
    assert f"[{Severity.MEDIUM.label}]" in decision.context
