"""Turn registry facts into findings, and findings into a decision.

This is the policy layer. :mod:`registry` reports what is true; this module
decides what is *alarming*, and how alarming.

Two principles shape the thresholds:

**Blocking has a cost.** Every false positive teaches the user to ignore us,
and an ignored security tool is worse than none — it provides the feeling of
safety without the fact of it. So only genuinely decisive evidence blocks: a
known advisory, or a package that does not exist. Everything else informs.

**Ignorance is not safety.** When a lookup fails we say so and step aside. A
registry outage must never be reported as "looks fine", because the user
would reasonably read that as "checked and clean".

The one asymmetry is auto-approve mode. When per-call prompts are suppressed,
an ``ask`` is silently discarded, so a finding that deserved a prompt has to
escalate to ``deny`` or it is lost entirely. See :func:`decide`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from .registry import PackageFacts, Resolution

__all__ = [
    "Severity",
    "Finding",
    "Policy",
    "Verdict",
    "analyze",
    "decide",
    "DEFAULT_POLICY",
]


class Severity(IntEnum):
    """How much a finding should worry you.

    Ordered so the worst finding in a set is simply ``max(...)``.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    """One thing worth telling the user about one package."""

    code: str
    severity: Severity
    summary: str
    detail: str = ""

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"[{self.severity.label}] {self.summary}"


@dataclass(frozen=True)
class Policy:
    """Tunable thresholds.

    Defaults are deliberately conservative: each one was chosen so that a
    *normal* package does not trip it, because the cost of crying wolf is
    that real warnings stop being read.
    """

    #: A version published within this many days is "fresh". Compromised
    #: releases are typically caught within days, so recency is the window
    #: in which you are most exposed, not evidence of wrongdoing by itself.
    new_version_days: float = 14.0

    #: Weekly downloads below this are unusual for a package an agent picks
    #: unprompted. npm only — PyPI publishes no first-party download data.
    low_downloads: int = 1_000
    very_low_downloads: int = 50

    #: Below this many maintainers, a single account compromise is enough to
    #: push a malicious release. Common and not alarming alone.
    few_maintainers: int = 1

    #: Advisories always block, regardless of mode. This is the one case the
    #: tool exists for, and the one the user explicitly asked to deny.
    advisories_block: bool = True

    #: A package the registry has never heard of blocks too: it is either a
    #: typo or a name the agent invented, and installing it is how
    #: dependency-confusion attacks land.
    missing_blocks: bool = True


DEFAULT_POLICY = Policy()


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def _advisory_finding(facts: PackageFacts) -> Finding | None:
    if not facts.advisories:
        return None
    ids = ", ".join(facts.advisories)
    count = len(facts.advisories)
    plural = "advisory" if count == 1 else "advisories"
    return Finding(
        code="advisory",
        severity=Severity.CRITICAL,
        summary=f"{count} known security {plural} for {facts.display}",
        detail=ids,
    )


def _missing_finding(facts: PackageFacts) -> Finding | None:
    if facts.exists:
        return None
    return Finding(
        code="not-found",
        severity=Severity.CRITICAL,
        summary=f"{facts.name} does not exist on {facts.ecosystem}",
        detail=(
            "A name the registry has never seen is either a typo or invented. "
            "Installing it is how typosquatting and dependency-confusion "
            "attacks succeed."
        ),
    )


def _unreachable_finding(facts: PackageFacts) -> Finding | None:
    if not facts.unreachable:
        return None
    return Finding(
        code="unreachable",
        severity=Severity.INFO,
        summary=f"could not reach the registry for {facts.name}",
        detail=(
            "Nothing was verified. This is not evidence that the package is "
            "safe, only that we could not look."
        ),
    )


def _yanked_finding(facts: PackageFacts) -> Finding | None:
    if not facts.yanked:
        return None
    return Finding(
        code="yanked",
        severity=Severity.HIGH,
        summary=f"{facts.display} was withdrawn after publication",
        detail="Maintainers yank releases for brokenness or security problems.",
    )


def _deprecated_finding(facts: PackageFacts) -> Finding | None:
    if not facts.deprecated:
        return None
    return Finding(
        code="deprecated",
        severity=Severity.MEDIUM,
        summary=f"{facts.display} is deprecated",
        detail=facts.deprecated,
    )


def _install_script_finding(facts: PackageFacts) -> Finding | None:
    if not facts.install_scripts:
        return None
    names = ", ".join(facts.install_scripts)
    return Finding(
        code="install-scripts",
        severity=Severity.MEDIUM,
        summary=f"{facts.display} runs code at install time ({names})",
        detail=(
            "Install hooks execute automatically with your user's privileges. "
            "Legitimate for native builds, and the most direct path for "
            "malicious packages."
        ),
    )


def _freshness_finding(facts: PackageFacts, policy: Policy) -> Finding | None:
    age = facts.age_days
    if age is None or age >= policy.new_version_days:
        return None
    when = "today" if age < 1 else f"{age:.0f} days ago"
    return Finding(
        code="new-version",
        severity=Severity.MEDIUM,
        summary=f"{facts.display} was published {when}",
        detail=(
            "Compromised releases are usually caught within days, so a very "
            "recent version is the window of maximum exposure."
        ),
    )


def _downloads_finding(facts: PackageFacts, policy: Policy) -> Finding | None:
    count = facts.weekly_downloads
    if count is None or count >= policy.low_downloads:
        return None
    severity = Severity.HIGH if count < policy.very_low_downloads else Severity.MEDIUM
    return Finding(
        code="low-downloads",
        severity=severity,
        summary=f"{facts.name} has only {count:,} weekly downloads",
        detail=(
            "Few users means few eyes. Unusual for a package chosen "
            "unprompted, and typical of typosquats."
        ),
    )


def _maintainer_finding(facts: PackageFacts, policy: Policy) -> Finding | None:
    count = facts.maintainers
    if count is None or count > policy.few_maintainers:
        return None
    return Finding(
        code="single-maintainer",
        severity=Severity.LOW,
        summary=f"{facts.name} has {count} maintainer",
        detail=(
            "One compromised account is enough to publish a malicious "
            "release. Extremely common; informational only."
        ),
    )


def _repository_finding(facts: PackageFacts) -> Finding | None:
    if facts.repository:
        return None
    return Finding(
        code="no-repository",
        severity=Severity.LOW,
        summary=f"{facts.name} declares no source repository",
        detail="Nobody can review code they cannot find.",
    )


def _resolution_finding(facts: PackageFacts) -> Finding | None:
    if facts.resolution is not Resolution.RANGE:
        return None
    return Finding(
        code="range-approximated",
        severity=Severity.INFO,
        summary=(
            f"checked {facts.display}, but the command requested {facts.requested!r}"
        ),
        detail=(
            "Version ranges are not evaluated, so the version installed may "
            "differ from the one checked."
        ),
    )


def analyze(facts: PackageFacts, policy: Policy = DEFAULT_POLICY) -> list[Finding]:
    """Apply every rule to one package, worst finding first.

    An unreachable registry short-circuits: with no data, every other rule
    would be reasoning about absent fields and would produce findings that
    say more about our outage than about the package.
    """
    if facts.unreachable:
        found = _unreachable_finding(facts)
        return [found] if found else []

    if not facts.exists:
        # Every other rule would be describing fields a nonexistent package
        # cannot have. "Declares no source repository" is true but vacuous,
        # and padding a critical finding with noise weakens it.
        missing = _missing_finding(facts)
        return [missing] if missing else []

    candidates = [
        _missing_finding(facts),
        _advisory_finding(facts),
        _yanked_finding(facts),
        _deprecated_finding(facts),
        _install_script_finding(facts),
        _freshness_finding(facts, policy),
        _downloads_finding(facts, policy),
        _maintainer_finding(facts, policy),
        _repository_finding(facts),
        _resolution_finding(facts),
    ]
    findings = [item for item in candidates if item is not None]
    findings.sort(key=lambda f: f.severity, reverse=True)
    return findings


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Verdict:
    """The combined judgement across every package in one command."""

    #: ``deny`` / ``ask`` / ``defer``. Never ``allow``: widening the user's
    #: own permission rules is not ours to do.
    decision: str
    reason: str
    #: Findings paired with the package they came from, worst first.
    results: tuple[tuple[PackageFacts, tuple[Finding, ...]], ...] = ()
    escalated: bool = False

    @property
    def worst(self) -> Severity:
        severities = [
            finding.severity for _, findings in self.results for finding in findings
        ]
        return max(severities) if severities else Severity.INFO

    @property
    def blocking_findings(self) -> tuple[Finding, ...]:
        return tuple(
            finding
            for _, findings in self.results
            for finding in findings
            if finding.severity >= Severity.CRITICAL
        )


def decide(
    all_facts: list[PackageFacts],
    auto_approving: bool = False,
    policy: Policy = DEFAULT_POLICY,
) -> Verdict:
    """Combine per-package findings into one decision for the command.

    The mapping:

    ``CRITICAL`` (advisory, nonexistent package)
        ``deny``, always. This is the case the tool exists for, and the one
        the user asked to block even in auto-approve mode.

    ``HIGH``
        ``ask`` normally. Under auto-approve, ``ask`` is silently discarded,
        so it escalates to ``deny`` — otherwise the finding evaporates
        precisely when the user is least able to catch it themselves.

    Anything lower
        ``defer``. Reported as context, but the user's own permission rules
        stay in charge.
    """
    results = tuple((facts, tuple(analyze(facts, policy))) for facts in all_facts)
    verdict = Verdict(decision="defer", reason="", results=results)

    worst = verdict.worst
    blocking = verdict.blocking_findings

    if blocking and (policy.advisories_block or policy.missing_blocks):
        relevant = [
            finding
            for finding in blocking
            if (finding.code == "advisory" and policy.advisories_block)
            or (finding.code == "not-found" and policy.missing_blocks)
        ]
        if relevant:
            summary = "; ".join(finding.summary for finding in relevant)
            return Verdict(
                decision="deny",
                reason=f"pkgpatrol blocked this install: {summary}",
                results=results,
            )

    if worst >= Severity.HIGH:
        summary = "; ".join(
            finding.summary
            for _, findings in results
            for finding in findings
            if finding.severity >= Severity.HIGH
        )
        if auto_approving:
            # `ask` would be discarded here, taking the finding with it.
            return Verdict(
                decision="deny",
                reason=(
                    f"pkgpatrol blocked this install (auto-approve mode, so "
                    f"this could not be a prompt): {summary}"
                ),
                results=results,
                escalated=True,
            )
        return Verdict(
            decision="ask",
            reason=f"pkgpatrol found something worth a look: {summary}",
            results=results,
        )

    return verdict
