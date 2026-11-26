"""Tests for the terminal report.

The colour rules get the most attention here. Escape codes written into a
pipe or a CI log are worse than no colour at all, and this output is piped
far more often than people expect.
"""

from __future__ import annotations

import datetime as dt
import io

import pytest

from pkgpatrol.analyze import decide
from pkgpatrol.parse import Ecosystem
from pkgpatrol.registry import PackageFacts, Resolution
from pkgpatrol.report import Palette, render, supports_color

PLAIN = Palette(False)
COLOR = Palette(True)


def facts(**overrides: object) -> PackageFacts:
    base: dict = {
        "name": "express",
        "ecosystem": Ecosystem.NPM,
        "resolved_version": "4.18.0",
        "resolution": Resolution.LATEST,
        "exists": True,
        "published_at": dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=400),
        "weekly_downloads": 30_000_000,
        "maintainers": 5,
        "repository": "https://github.com/expressjs/express",
        "license": "MIT",
    }
    base.update(overrides)
    return PackageFacts(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Content
# ---------------------------------------------------------------------------


def test_clean_package_reports_ok() -> None:
    out = render(decide([facts()]), PLAIN)
    assert "express@4.18.0" in out
    assert "no red flags" in out
    assert "OK" in out


def test_findings_are_listed() -> None:
    out = render(decide([facts(deprecated="unmaintained")]), PLAIN)
    assert "deprecated" in out


def test_blocked_verdict_is_announced() -> None:
    out = render(decide([facts(advisories=("GHSA-x",))]), PLAIN)
    assert "BLOCKED" in out


def test_ask_verdict_is_announced() -> None:
    out = render(decide([facts(yanked=True)]), PLAIN)
    assert "NEEDS REVIEW" in out


def test_missing_package_is_marked() -> None:
    out = render(decide([facts(exists=False, resolved_version=None)]), PLAIN)
    assert "not found" in out


def test_unreachable_is_marked_without_claiming_safety() -> None:
    out = render(decide([facts(unreachable=True)]), PLAIN)
    assert "unreachable" in out
    assert "no red flags" not in out


def test_verbose_adds_explanations() -> None:
    verdict = decide([facts(install_scripts=("postinstall",))])
    terse = render(verdict, PLAIN, verbose=False)
    wordy = render(verdict, PLAIN, verbose=True)
    assert len(wordy) > len(terse)
    assert "privileges" in wordy


def test_requested_range_is_shown() -> None:
    """The user asked for one thing; we checked another. Say so."""
    out = render(
        decide([facts(resolution=Resolution.RANGE, requested="^4.0.0")]), PLAIN
    )
    assert "^4.0.0" in out


def test_downloads_are_humanised() -> None:
    assert "30.0M" in render(decide([facts()]), PLAIN)
    assert "5k" in render(decide([facts(weekly_downloads=5_000)]), PLAIN)
    assert "12" in render(decide([facts(weekly_downloads=12)]), PLAIN)


def test_every_package_appears() -> None:
    out = render(decide([facts(name="a"), facts(name="b")]), PLAIN)
    assert "a@4.18.0" in out and "b@4.18.0" in out


def test_summary_counts_findings() -> None:
    out = render(decide([facts(advisories=("GHSA-x",))]), PLAIN)
    assert "1 critical" in out


def test_empty_verdict() -> None:
    assert "No packages" in render(decide([]), PLAIN)


def test_output_ends_with_newline() -> None:
    assert render(decide([facts()]), PLAIN).endswith("\n")


# ---------------------------------------------------------------------------
# Colour
# ---------------------------------------------------------------------------


def test_plain_palette_emits_no_escape_codes() -> None:
    out = render(decide([facts(advisories=("GHSA-x",))]), PLAIN)
    assert "\033[" not in out


def test_color_palette_emits_escape_codes() -> None:
    out = render(decide([facts(advisories=("GHSA-x",))]), COLOR)
    assert "\033[" in out


def test_no_color_env_disables_color(monkeypatch: pytest.MonkeyPatch) -> None:
    """NO_COLOR is the de-facto standard and must win."""
    monkeypatch.setenv("NO_COLOR", "1")
    assert supports_color(io.StringIO()) is False


def test_force_color_env_enables_color(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert supports_color(io.StringIO()) is True


def test_no_color_beats_force_color(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert supports_color(io.StringIO()) is False


def test_non_tty_disables_color(monkeypatch: pytest.MonkeyPatch) -> None:
    """Escape codes in a piped log are worse than no colour."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    assert supports_color(io.StringIO()) is False


def test_dumb_terminal_disables_color(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.setenv("TERM", "dumb")

    class FakeTty(io.StringIO):
        def isatty(self) -> bool:
            return True

    assert supports_color(FakeTty()) is False


def test_stream_without_isatty_is_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)

    class Odd:
        pass

    assert supports_color(Odd()) is False  # type: ignore[arg-type]


def test_severity_colors_differ() -> None:
    from pkgpatrol.analyze import Severity

    rendered = {
        level: COLOR.severity(level, "x")
        for level in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
    }
    assert len(set(rendered.values())) == len(rendered)
