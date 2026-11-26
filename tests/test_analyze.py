"""Tests for the policy layer: facts in, findings and a decision out.

Two behaviours carry most of the weight here, and both are about *not* being
wrong in the dangerous direction:

1. A known advisory blocks in every mode, including auto-approve.
2. An unreachable registry never reads as "looks fine" — ignorance is
   reported as ignorance, and the install proceeds.
"""

from __future__ import annotations

import dataclasses
import datetime as dt

import pytest

from pkgpatrol.analyze import (
    DEFAULT_POLICY,
    Policy,
    Severity,
    analyze,
    decide,
)
from pkgpatrol.parse import Ecosystem
from pkgpatrol.registry import PackageFacts, Resolution


def facts(**overrides: object) -> PackageFacts:
    """A healthy, unremarkable package — the baseline that must stay quiet."""
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


def codes(findings) -> set[str]:
    return {f.code for f in findings}


# ---------------------------------------------------------------------------
# The quiet baseline
# ---------------------------------------------------------------------------


def test_healthy_package_produces_no_findings() -> None:
    """If a normal package trips a rule, every warning becomes noise and the
    tool stops being read. This is the most important test here."""
    assert analyze(facts()) == []


def test_healthy_package_defers() -> None:
    verdict = decide([facts()])
    assert verdict.decision == "defer"
    assert verdict.reason == ""


# ---------------------------------------------------------------------------
# Advisories — the reason this tool exists
# ---------------------------------------------------------------------------


def test_advisory_is_critical() -> None:
    found = analyze(facts(advisories=("GHSA-aaaa",)))
    assert "advisory" in codes(found)
    assert found[0].severity is Severity.CRITICAL


def test_advisory_denies() -> None:
    verdict = decide([facts(advisories=("GHSA-aaaa",))])
    assert verdict.decision == "deny"
    assert "GHSA-aaaa" in str(verdict.blocking_findings[0].detail)


def test_advisory_denies_even_in_auto_approve_mode() -> None:
    """The explicit requirement: CVEs must block in yolo mode."""
    verdict = decide([facts(advisories=("GHSA-aaaa",))], auto_approving=True)
    assert verdict.decision == "deny"


def test_multiple_advisories_are_all_reported() -> None:
    found = analyze(facts(advisories=("GHSA-a", "GHSA-b", "GHSA-c")))
    advisory = next(f for f in found if f.code == "advisory")
    assert "3" in advisory.summary
    for ident in ("GHSA-a", "GHSA-b", "GHSA-c"):
        assert ident in advisory.detail


def test_advisory_blocking_can_be_disabled_by_policy() -> None:
    verdict = decide(
        [facts(advisories=("GHSA-a",))],
        policy=Policy(advisories_block=False, missing_blocks=False),
    )
    assert verdict.decision != "deny"


# ---------------------------------------------------------------------------
# Nonexistent packages
# ---------------------------------------------------------------------------


def test_missing_package_is_critical_and_denies() -> None:
    """A name the registry never saw is a typo or an invention — the shape of
    typosquatting and dependency confusion."""
    bad = facts(exists=False, resolved_version=None)
    assert "not-found" in codes(analyze(bad))
    assert decide([bad]).decision == "deny"


def test_missing_package_reports_nothing_else() -> None:
    """Padding a critical finding with vacuous ones ("declares no source
    repository" — of course it does not, it does not exist) dilutes it."""
    bad = facts(exists=False, resolved_version=None, repository=None, maintainers=None)
    assert codes(analyze(bad)) == {"not-found"}


# ---------------------------------------------------------------------------
# Unreachable — must fail open, and must not claim safety
# ---------------------------------------------------------------------------


def test_unreachable_does_not_block() -> None:
    verdict = decide([facts(unreachable=True)])
    assert verdict.decision == "defer"


def test_unreachable_does_not_block_even_in_auto_approve() -> None:
    verdict = decide([facts(unreachable=True)], auto_approving=True)
    assert verdict.decision == "defer"


def test_unreachable_says_nothing_was_verified() -> None:
    """It must not read as 'checked and clean'."""
    found = analyze(facts(unreachable=True))
    assert len(found) == 1
    assert found[0].code == "unreachable"
    assert "not evidence" in found[0].detail


def test_unreachable_suppresses_other_rules() -> None:
    """With no data, other rules would describe our outage, not the package."""
    found = analyze(
        facts(
            unreachable=True, weekly_downloads=None, repository=None, maintainers=None
        )
    )
    assert codes(found) == {"unreachable"}


# ---------------------------------------------------------------------------
# Individual signals
# ---------------------------------------------------------------------------


def test_yanked_release_is_high() -> None:
    found = analyze(facts(yanked=True))
    assert next(f for f in found if f.code == "yanked").severity is Severity.HIGH


def test_deprecated_is_medium() -> None:
    found = analyze(facts(deprecated="use foo"))
    item = next(f for f in found if f.code == "deprecated")
    assert item.severity is Severity.MEDIUM
    assert item.detail == "use foo"


def test_install_scripts_flagged() -> None:
    found = analyze(facts(install_scripts=("postinstall",)))
    item = next(f for f in found if f.code == "install-scripts")
    assert item.severity is Severity.MEDIUM
    assert "postinstall" in item.summary


def test_freshly_published_version_flagged() -> None:
    recent = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=6)
    found = analyze(facts(published_at=recent))
    assert "new-version" in codes(found)


def test_old_version_not_flagged_as_fresh() -> None:
    assert "new-version" not in codes(analyze(facts()))


def test_unknown_age_is_not_flagged() -> None:
    """Missing data is not a finding."""
    assert "new-version" not in codes(analyze(facts(published_at=None)))


@pytest.mark.parametrize(
    ("downloads", "severity"),
    [(10, Severity.HIGH), (500, Severity.MEDIUM)],
)
def test_low_downloads_severity_scales(downloads: int, severity: Severity) -> None:
    found = analyze(facts(weekly_downloads=downloads))
    assert next(f for f in found if f.code == "low-downloads").severity is severity


def test_popular_package_not_flagged_for_downloads() -> None:
    assert "low-downloads" not in codes(analyze(facts()))


def test_missing_download_data_is_not_a_finding() -> None:
    """PyPI publishes no download counts; absence must not look suspicious."""
    pypi = facts(ecosystem=Ecosystem.PYPI, weekly_downloads=None)
    assert "low-downloads" not in codes(analyze(pypi))


def test_single_maintainer_is_low_only() -> None:
    found = analyze(facts(maintainers=1))
    assert (
        next(f for f in found if f.code == "single-maintainer").severity is Severity.LOW
    )


def test_missing_repository_is_low() -> None:
    found = analyze(facts(repository=None))
    assert next(f for f in found if f.code == "no-repository").severity is Severity.LOW


def test_range_approximation_is_disclosed() -> None:
    """We checked a different version than the command requested; the user
    needs to know that rather than assume the constraint was evaluated."""
    found = analyze(facts(resolution=Resolution.RANGE, requested="^4.0.0"))
    item = next(f for f in found if f.code == "range-approximated")
    assert item.severity is Severity.INFO
    assert "^4.0.0" in item.summary


# ---------------------------------------------------------------------------
# Escalation under auto-approve
# ---------------------------------------------------------------------------


def test_high_severity_asks_when_prompts_work() -> None:
    verdict = decide([facts(yanked=True)], auto_approving=False)
    assert verdict.decision == "ask"
    assert verdict.escalated is False


def test_high_severity_escalates_to_deny_under_auto_approve() -> None:
    """An `ask` is discarded in auto-approve mode, so the finding would simply
    vanish — precisely when the user is least able to catch it themselves."""
    verdict = decide([facts(yanked=True)], auto_approving=True)
    assert verdict.decision == "deny"
    assert verdict.escalated is True
    assert "auto-approve" in verdict.reason


def test_medium_severity_does_not_escalate() -> None:
    verdict = decide([facts(deprecated="old")], auto_approving=True)
    assert verdict.decision == "defer"


def test_low_severity_defers() -> None:
    assert decide([facts(maintainers=1)]).decision == "defer"


# ---------------------------------------------------------------------------
# Combining packages
# ---------------------------------------------------------------------------


def test_worst_package_drives_the_decision() -> None:
    verdict = decide([facts(name="good"), facts(name="bad", advisories=("GHSA-x",))])
    assert verdict.decision == "deny"


def test_all_packages_are_reported() -> None:
    verdict = decide([facts(name="a"), facts(name="b", deprecated="old")])
    assert len(verdict.results) == 2
    assert {f.name for f, _ in verdict.results} == {"a", "b"}


def test_empty_input_defers() -> None:
    verdict = decide([])
    assert verdict.decision == "defer"
    assert verdict.worst is Severity.INFO


def test_findings_sorted_worst_first() -> None:
    found = analyze(
        facts(advisories=("GHSA-x",), maintainers=1, repository=None, yanked=True)
    )
    severities = [f.severity for f in found]
    assert severities == sorted(severities, reverse=True)


def test_reason_names_the_package() -> None:
    verdict = decide([facts(name="sketchy", advisories=("GHSA-x",))])
    assert "sketchy" in verdict.reason


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


def test_thresholds_are_tunable() -> None:
    strict = Policy(low_downloads=100_000_000)
    assert "low-downloads" in codes(analyze(facts(), strict))


def test_default_policy_is_shared_and_frozen() -> None:
    assert DEFAULT_POLICY.advisories_block is True
    # Frozen so a caller cannot mutate the shared default and silently change
    # thresholds for every other caller in the process.
    with pytest.raises(dataclasses.FrozenInstanceError):
        DEFAULT_POLICY.new_version_days = 1  # type: ignore[misc]


def test_unresolved_version_is_never_silent() -> None:
    """Regression: a registry that answered but yielded no version left every
    other rule reading absent fields, so the report said "declares no source
    repository" — which reads as "checked and basically fine"."""
    found = analyze(facts(resolved_version=None, repository=None, errors=("HTTP 500",)))
    assert codes(found) == {"unresolved"}
    assert found[0].severity is Severity.MEDIUM
    assert "nothing about this package was verified" in found[0].detail


def test_unresolved_mentions_the_underlying_error() -> None:
    found = analyze(facts(resolved_version=None, errors=("HTTP 500",)))
    assert "HTTP 500" in found[0].detail
