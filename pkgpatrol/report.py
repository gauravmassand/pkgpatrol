"""Colored terminal output for ``pkgpatrol check``.

This is the *human* surface. The hook speaks to Claude through JSON; this
speaks to a person reading a terminal, and the two want different things —
which is why the report lives here rather than being shared with the hook.

Color is applied only when it will survive: a TTY, no ``NO_COLOR``, and not
a dumb terminal. Everything degrades to plain text, because output is piped
into files and CI logs far more often than people expect, and escape codes
in a log are worse than no color at all.
"""

from __future__ import annotations

import os
import sys
from typing import IO

from .analyze import Finding, Severity, Verdict
from .registry import PackageFacts, Resolution

__all__ = ["render", "supports_color", "Palette"]


class Palette:
    """ANSI codes, or empty strings when color is not wanted."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def blue(self, text: str) -> str:
        return self._wrap("34", text)

    def severity(self, level: Severity, text: str) -> str:
        if level >= Severity.CRITICAL:
            return self.bold(self.red(text))
        if level is Severity.HIGH:
            return self.red(text)
        if level is Severity.MEDIUM:
            return self.yellow(text)
        if level is Severity.LOW:
            return self.blue(text)
        return self.dim(text)


def supports_color(stream: IO[str] | None = None) -> bool:
    """True when ANSI codes will render rather than appear as noise.

    Honours ``NO_COLOR`` (the de-facto standard) and ``FORCE_COLOR``, and
    refuses on a non-TTY so piped output stays clean.
    """
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    stream = stream or sys.stdout
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


#: Marker shown beside each finding. Chosen from ASCII so the report is
#: readable in terminals and CI logs with no font for box-drawing or emoji.
_MARKERS = {
    Severity.CRITICAL: "XX",
    Severity.HIGH: " !",
    Severity.MEDIUM: " *",
    Severity.LOW: " -",
    Severity.INFO: " .",
}


def _format_downloads(count: int | None) -> str:
    if count is None:
        return "unknown"
    if count >= 1_000_000:
        return f"{count / 1_000_000:.1f}M"
    if count >= 1_000:
        return f"{count / 1_000:.0f}k"
    return str(count)


def _package_header(facts: PackageFacts, palette: Palette) -> str:
    name = palette.bold(facts.display)
    if not facts.exists:
        return f"{name} {palette.red('(not found)')}"
    if facts.unreachable:
        return f"{name} {palette.dim('(registry unreachable)')}"

    bits: list[str] = []
    if facts.resolution is Resolution.RANGE and facts.requested:
        bits.append(palette.dim(f"requested {facts.requested}"))
    if facts.weekly_downloads is not None:
        bits.append(palette.dim(f"{_format_downloads(facts.weekly_downloads)}/wk"))
    if facts.license:
        bits.append(palette.dim(facts.license))
    suffix = f"  {'  '.join(bits)}" if bits else ""
    return f"{name}{suffix}"


def _format_finding(finding: Finding, palette: Palette, verbose: bool) -> list[str]:
    marker = _MARKERS.get(finding.severity, " ?")
    head = palette.severity(finding.severity, f"  {marker} {finding.summary}")
    lines = [head]
    if verbose and finding.detail:
        lines.append(palette.dim(f"       {finding.detail}"))
    return lines


def render(
    verdict: Verdict,
    palette: Palette | None = None,
    verbose: bool = False,
) -> str:
    """Render a verdict as a terminal report.

    Returns the text rather than printing it, so the caller controls the
    stream and tests need no capture plumbing.
    """
    palette = palette or Palette(supports_color())
    lines: list[str] = []

    for facts, findings in verdict.results:
        lines.append(_package_header(facts, palette))
        if not findings:
            lines.append(palette.green("   ok  no red flags"))
        for finding in findings:
            lines.extend(_format_finding(finding, palette, verbose))
        lines.append("")

    if not verdict.results:
        return "No packages to check.\n"

    lines.append(_summary_line(verdict, palette))
    return "\n".join(lines) + "\n"


def _summary_line(verdict: Verdict, palette: Palette) -> str:
    total = len(verdict.results)
    noun = "package" if total == 1 else "packages"
    counts: dict[Severity, int] = {}
    for _, findings in verdict.results:
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1

    if verdict.decision == "deny":
        verdict_text = palette.bold(palette.red("BLOCKED"))
    elif verdict.decision == "ask":
        verdict_text = palette.bold(palette.yellow("NEEDS REVIEW"))
    elif counts:
        verdict_text = palette.yellow("OK with notes")
    else:
        verdict_text = palette.green("OK")

    breakdown = ", ".join(
        f"{count} {level.label}"
        for level, count in sorted(counts.items(), reverse=True)
    )
    tail = f" — {breakdown}" if breakdown else ""
    return f"{verdict_text}: checked {total} {noun}{tail}"
