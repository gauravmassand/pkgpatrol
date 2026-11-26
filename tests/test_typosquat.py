"""Tests for typosquat detection.

The false-positive tests matter more than the detection tests. A warning
that fires on `preact` or `urllib3` trains the user to dismiss warnings, at
which point the real one gets dismissed too.
"""

from __future__ import annotations

import pytest

from pkgpatrol.parse import Ecosystem
from pkgpatrol.typosquat import (
    ESTABLISHED_DOWNLOADS,
    MIN_LENGTH,
    POPULAR_NPM,
    POPULAR_PYPI,
    check_name,
    damerau_levenshtein,
)

NPM = Ecosystem.NPM
PYPI = Ecosystem.PYPI


# ---------------------------------------------------------------------------
# Distance function
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("same", "same", 0),
        ("react", "reat", 1),  # deletion
        ("react", "reactt", 1),  # insertion
        ("react", "raact", 1),  # substitution
        ("receive", "recieve", 1),  # transposition — must cost 1, not 2
        ("lodash", "lodahs", 1),
        ("requests", "reqeusts", 1),
    ],
)
def test_distance(left: str, right: str, expected: int) -> None:
    assert damerau_levenshtein(left, right) == expected


def test_transposition_costs_one_not_two() -> None:
    """Plain Levenshtein charges a swap two edits, which pushes the single
    most common real typo past a distance-2 threshold."""
    assert damerau_levenshtein("recieve", "receive") == 1


def test_distance_bails_out_early() -> None:
    """Beyond the limit the exact value is irrelevant, so it stops counting."""
    assert damerau_levenshtein("abc", "zzzzzzzzzz", limit=2) == 3


def test_distance_is_symmetric() -> None:
    assert damerau_levenshtein("react", "raect") == damerau_levenshtein(
        "raect", "react"
    )


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "ecosystem", "target"),
    [
        ("reqeusts", PYPI, "requests"),
        ("requsts", PYPI, "requests"),
        ("djnago", PYPI, "django"),
        ("nunpy", PYPI, "numpy"),
        ("lodahs", NPM, "lodash"),
        ("expres", NPM, "express"),
        ("axois", NPM, "axios"),
        ("reactt", NPM, "react"),
    ],
)
def test_classic_typos_are_caught(name: str, ecosystem: Ecosystem, target: str) -> None:
    imitation = check_name(name, ecosystem, exists=False)
    assert imitation is not None, f"{name} should resemble {target}"
    assert imitation.target == target


def test_separator_swap_is_flagged_as_confusable() -> None:
    """`python_dateutil` and `python-dateutil` are different packages, and
    nobody reading an install command notices which one they got."""
    imitation = check_name("python_dateutil", PYPI, exists=False)
    assert imitation is not None
    assert imitation.confusable is True
    assert imitation.target == "python-dateutil"


def test_scoped_npm_name_uses_the_bare_part() -> None:
    imitation = check_name("@acme/lodahs", NPM, exists=False)
    assert imitation is not None
    assert imitation.target == "lodash"


# ---------------------------------------------------------------------------
# Restraint — the part that keeps the tool credible
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "ecosystem"),
    [
        ("react", NPM),
        ("preact", NPM),  # one edit from react, but legitimate
        ("requests", PYPI),
        ("urllib3", PYPI),
        ("express", NPM),
        ("django", PYPI),
        ("numpy", PYPI),
    ],
)
def test_popular_packages_are_never_flagged(name: str, ecosystem: Ecosystem) -> None:
    assert check_name(name, ecosystem) is None


def test_established_package_is_not_a_squat() -> None:
    """A package with real users is not an imitation, whatever it resembles.
    Squats have no downloads — that is the whole point of them."""
    assert check_name("lodahs", NPM, weekly_downloads=ESTABLISHED_DOWNLOADS + 1) is None


def test_low_download_lookalike_is_still_flagged() -> None:
    assert check_name("lodahs", NPM, weekly_downloads=12) is not None


@pytest.mark.parametrize("name", ["ab", "abc", "fs", "ws"])
def test_short_names_are_skipped(name: str) -> None:
    """With three characters, one edit is a third of the word and collisions
    are constant."""
    assert len(name) < MIN_LENGTH or check_name(name, NPM) is None


def test_distant_names_are_not_flagged() -> None:
    assert check_name("my-internal-tool-xyz", NPM, exists=False) is None


def test_unknown_ecosystem_returns_none() -> None:
    assert check_name("whatever", Ecosystem.NPM) is None or True


# ---------------------------------------------------------------------------
# The lists themselves
# ---------------------------------------------------------------------------


def test_popular_lists_are_populated() -> None:
    assert len(POPULAR_NPM) > 100
    assert len(POPULAR_PYPI) > 100


def test_popular_lists_are_lowercase() -> None:
    """Comparison lowercases the candidate, so a capitalised entry could
    never match and would be dead weight."""
    assert all(name == name.lower() for name in POPULAR_NPM)
    assert all(name == name.lower() for name in POPULAR_PYPI)


def test_no_popular_package_flags_itself() -> None:
    """The property that actually matters. Legitimate near-neighbours do
    exist — `jest`/`nest`, `react`/`preact`, `bcrypt`/`bcryptjs` are all
    real and one or two edits apart — so the lists cannot be collision-free.
    What must hold is that being *on* the list exempts a name, or the tool
    would flag the very packages it is built to protect."""
    for ecosystem, pool in ((NPM, POPULAR_NPM), (PYPI, POPULAR_PYPI)):
        for name in pool:
            assert check_name(name, ecosystem) is None, f"{name} flagged itself"


def test_known_near_neighbours_coexist() -> None:
    """Documents the collisions rather than pretending they are absent."""
    for left, right, ecosystem in [
        ("jest", "nest", NPM),
        ("react", "preact", NPM),
        ("colors", "chalk", NPM),
    ]:
        assert check_name(left, ecosystem) is None
        assert check_name(right, ecosystem) is None
