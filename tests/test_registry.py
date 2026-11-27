"""Tests for registry lookups and version resolution.

These stub the HTTP layer rather than hitting the network: ``test_http.py``
already exercises real urllib against a local server, so what matters here is
URL choice, response interpretation, and partial-failure behaviour.

The recurring theme is that **no single lookup failing may discard the
others**. deps.dev going down must not erase npm's metadata, and a missing
downloads count must not look like a missing package.
"""

from __future__ import annotations

import datetime as dt

import pytest

from pkgpatrol.http import Deadline, Response
from pkgpatrol.parse import Ecosystem, PackageSpec
from pkgpatrol.registry import (
    PackageFacts,
    Resolution,
    fetch_facts,
    gather,
)


class StubClient:
    """An HttpClient stand-in that answers from a canned URL map.

    Unmatched URLs return 404, so a test only declares the endpoints it cares
    about and anything else behaves like a missing resource.
    """

    def __init__(self, routes: dict[str, Response] | None = None) -> None:
        self.routes = routes or {}
        self.requested: list[str] = []

    def get_json(self, url: str, _deadline: Deadline | None = None, **_kw: object):
        self.requested.append(url)
        for pattern, response in self.routes.items():
            if pattern in url:
                return response
        return Response(url=url, status=404, error="HTTP 404")

    def asked_for(self, fragment: str) -> bool:
        return any(fragment in url for url in self.requested)


def ok(data: object) -> Response:
    return Response(url="x", status=200, data=data)


def npm_doc(**overrides: object) -> dict:
    doc = {
        "name": "express",
        "version": "4.18.0",
        "license": "MIT",
        "maintainers": [{"name": "a"}, {"name": "b"}],
        "repository": {"url": "git+https://github.com/expressjs/express.git"},
        "scripts": {"test": "mocha"},
    }
    doc.update(overrides)
    return doc


def pypi_doc(**overrides: object) -> dict:
    info = {
        "version": "2.31.0",
        "license": "Apache-2.0",
        "project_urls": {"Source": "https://github.com/psf/requests"},
    }
    info.update(overrides.pop("info", {}))  # type: ignore[arg-type]
    doc = {
        "info": info,
        "urls": [{"yanked": False, "upload_time_iso_8601": "2023-05-22T15:12:00Z"}],
    }
    doc.update(overrides)
    return doc


def npm(name: str = "express", spec: str | None = None) -> PackageSpec:
    return PackageSpec(name=name, ecosystem=Ecosystem.NPM, version_spec=spec)


def pypi(name: str = "requests", spec: str | None = None) -> PackageSpec:
    return PackageSpec(name=name, ecosystem=Ecosystem.PYPI, version_spec=spec)


# ---------------------------------------------------------------------------
# Version resolution — the subtle part
# ---------------------------------------------------------------------------


def test_bare_npm_install_resolves_latest() -> None:
    """`npm install express` names no version; npm picks the latest dist-tag,
    so we must resolve it before asking whether it is vulnerable."""
    client = StubClient({"/express/latest": ok(npm_doc())})
    facts = fetch_facts(npm(), client)
    assert facts.resolution is Resolution.LATEST
    assert facts.resolved_version == "4.18.0"
    assert client.asked_for("/express/latest")


def test_exact_npm_pin_fetches_that_version() -> None:
    client = StubClient({"/express/4.17.1": ok(npm_doc(version="4.17.1"))})
    facts = fetch_facts(npm(spec="4.17.1"), client)
    assert facts.resolution is Resolution.EXACT
    assert facts.resolved_version == "4.17.1"
    assert client.asked_for("/express/4.17.1")


def test_dist_tag_is_fetched_directly() -> None:
    client = StubClient({"/express/next": ok(npm_doc(version="5.0.0-beta"))})
    facts = fetch_facts(npm(spec="next"), client)
    assert facts.resolved_version == "5.0.0-beta"


@pytest.mark.parametrize("spec", ["^4.18.0", "~4.18", ">=4.0 <5", "4.x", "*"])
def test_range_falls_back_to_latest_and_says_so(spec: str) -> None:
    """Evaluating a range needs the full version list, which is megabytes for
    big packages. We check latest instead and flag the approximation, rather
    than silently implying we verified the constraint."""
    client = StubClient({"/express/latest": ok(npm_doc())})
    facts = fetch_facts(npm(spec=spec), client)
    assert facts.resolution is Resolution.RANGE
    assert facts.resolved_version == "4.18.0"


def test_pypi_bare_install_resolves_latest() -> None:
    client = StubClient({"/requests/json": ok(pypi_doc())})
    facts = fetch_facts(pypi(), client)
    assert facts.resolution is Resolution.LATEST
    assert facts.resolved_version == "2.31.0"


def test_pypi_exact_pin_fetches_that_version() -> None:
    client = StubClient(
        {"/requests/2.28.0/json": ok(pypi_doc(info={"version": "2.28.0"}))}
    )
    facts = fetch_facts(pypi(spec="==2.28.0"), client)
    assert facts.resolution is Resolution.EXACT
    assert facts.resolved_version == "2.28.0"


@pytest.mark.parametrize("spec", [">=2.0", "~=2.1", "==2.*", ">=2,<3"])
def test_pypi_range_falls_back_to_latest(spec: str) -> None:
    client = StubClient({"/requests/json": ok(pypi_doc())})
    facts = fetch_facts(pypi(spec=spec), client)
    assert facts.resolution is Resolution.RANGE


@pytest.mark.parametrize("spec", ["4.x", "4", "4.18", "1.x.x", "v4"])
def test_partial_and_wildcard_versions_are_ranges_not_pins(spec: str) -> None:
    """Regression. `4.x` has no "range character" and starts with a digit, so
    character-exclusion mistook it for a pin, fetched a nonexistent version,
    got a 404, and reported a real package as missing — which the analysis
    layer reads as a typosquat signal. Semver is now matched positively."""
    client = StubClient({"/express/latest": ok(npm_doc())})
    facts = fetch_facts(npm(spec=spec), client)
    assert facts.exists is True, f"{spec} must not look like a missing package"
    assert facts.resolved_version == "4.18.0"


@pytest.mark.parametrize(
    "spec", ["1.2.3", "0.0.1", "5.0.0-beta.1", "1.2.3+build.5", "2.0.0-rc.1+ci"]
)
def test_full_semver_is_treated_as_a_pin(spec: str) -> None:
    client = StubClient({f"/express/{spec}": ok(npm_doc(version=spec))})
    facts = fetch_facts(npm(spec=spec), client)
    assert facts.resolution is Resolution.EXACT
    assert facts.resolved_version == spec


def test_scoped_npm_name_is_url_encoded() -> None:
    client = StubClient({"latest": ok(npm_doc(name="@types/node"))})
    fetch_facts(npm(name="@types/node"), client)
    assert any("%2F" in u or "@types/node" in u for u in client.requested)


# ---------------------------------------------------------------------------
# Advisories — the signal that matters most
# ---------------------------------------------------------------------------


def test_advisories_are_collected() -> None:
    client = StubClient(
        {
            "/express/4.17.1": ok(npm_doc(version="4.17.1")),
            "deps.dev": ok(
                {
                    "advisoryKeys": [
                        {"id": "GHSA-qw6h-vgh9-j6wx"},
                        {"id": "GHSA-rv95-896h-c2vc"},
                    ],
                    "publishedAt": "2019-05-26T04:25:34Z",
                }
            ),
        }
    )
    facts = fetch_facts(npm(spec="4.17.1"), client)
    assert facts.advisories == ("GHSA-qw6h-vgh9-j6wx", "GHSA-rv95-896h-c2vc")


def test_advisories_queried_against_the_resolved_version() -> None:
    """A package is not vulnerable; a *version* is. The advisory lookup must
    use the version we resolved, not the name alone."""
    client = StubClient({"/express/latest": ok(npm_doc(version="4.18.0"))})
    fetch_facts(npm(), client)
    assert client.asked_for("/versions/4.18.0")


def test_no_advisories_is_not_an_error() -> None:
    client = StubClient(
        {"/express/latest": ok(npm_doc()), "deps.dev": ok({"advisoryKeys": []})}
    )
    facts = fetch_facts(npm(), client)
    assert facts.advisories == ()
    assert facts.ok


def test_malformed_advisory_entries_are_skipped() -> None:
    client = StubClient(
        {
            "/express/latest": ok(npm_doc()),
            "deps.dev": ok({"advisoryKeys": ["not-a-dict", {}, {"id": "GHSA-ok"}]}),
        }
    )
    assert fetch_facts(npm(), client).advisories == ("GHSA-ok",)


def test_depsdev_outage_does_not_discard_npm_metadata() -> None:
    """A secondary source failing must degrade the report, not erase it."""
    client = StubClient(
        {
            "/express/latest": ok(npm_doc()),
            "deps.dev": Response(url="d", error="unreachable: timed out"),
        }
    )
    facts = fetch_facts(npm(), client)
    assert facts.resolved_version == "4.18.0"
    assert facts.license == "MIT"
    assert facts.advisories == ()
    assert any("deps.dev" in e for e in facts.errors)


# ---------------------------------------------------------------------------
# Missing vs unreachable — opposite policies
# ---------------------------------------------------------------------------


def test_missing_package_is_recorded_as_not_existing() -> None:
    """A 404 is a strong typosquat signal, not a transport failure."""
    facts = fetch_facts(npm(name="defintely-not-real"), StubClient())
    assert facts.exists is False
    assert facts.unreachable is False
    assert facts.ok is False


def test_unreachable_registry_is_distinct_from_missing() -> None:
    """This case must fail open: we know nothing, so blocking would punish
    the user for the registry's outage."""
    client = StubClient({"/express/latest": Response(url="x", error="unreachable")})
    facts = fetch_facts(npm(), client)
    assert facts.unreachable is True
    assert facts.exists is True
    assert facts.ok is False


def test_missing_package_skips_downstream_lookups() -> None:
    client = StubClient()
    fetch_facts(npm(name="nope"), client)
    assert not client.asked_for("deps.dev")
    assert not client.asked_for("downloads")


# ---------------------------------------------------------------------------
# npm signals
# ---------------------------------------------------------------------------


def test_install_scripts_are_detected() -> None:
    """Arbitrary code at install time is the most direct attack path."""
    client = StubClient(
        {
            "/express/latest": ok(
                npm_doc(scripts={"postinstall": "node evil.js", "test": "mocha"})
            )
        }
    )
    assert fetch_facts(npm(), client).install_scripts == ("postinstall",)


def test_ordinary_scripts_are_not_flagged() -> None:
    client = StubClient({"/express/latest": ok(npm_doc(scripts={"build": "tsc"}))})
    assert fetch_facts(npm(), client).install_scripts == ()


def test_maintainer_count_is_read() -> None:
    client = StubClient({"/express/latest": ok(npm_doc())})
    assert fetch_facts(npm(), client).maintainers == 2


def test_deprecation_is_surfaced() -> None:
    client = StubClient({"/express/latest": ok(npm_doc(deprecated="use foo instead"))})
    assert fetch_facts(npm(), client).deprecated == "use foo instead"


def test_legacy_license_object_is_handled() -> None:
    """Old npm packages expressed license as an object, not a string."""
    client = StubClient({"/express/latest": ok(npm_doc(license={"type": "BSD"}))})
    assert fetch_facts(npm(), client).license == "BSD"


def test_repository_as_plain_string() -> None:
    client = StubClient({"/express/latest": ok(npm_doc(repository="https://g/r"))})
    assert fetch_facts(npm(), client).repository == "https://g/r"


def test_download_count_is_read() -> None:
    client = StubClient(
        {"/express/latest": ok(npm_doc()), "downloads": ok({"downloads": 12345})}
    )
    assert fetch_facts(npm(), client).weekly_downloads == 12345


def test_missing_downloads_is_not_an_error() -> None:
    client = StubClient({"/express/latest": ok(npm_doc())})
    facts = fetch_facts(npm(), client)
    assert facts.weekly_downloads is None
    assert facts.ok


# ---------------------------------------------------------------------------
# PyPI signals
# ---------------------------------------------------------------------------


def test_yanked_release_is_flagged() -> None:
    doc = pypi_doc()
    doc["urls"][0]["yanked"] = True
    client = StubClient({"/requests/json": ok(doc)})
    assert fetch_facts(pypi(), client).yanked is True


def test_pypi_repository_from_project_urls() -> None:
    client = StubClient({"/requests/json": ok(pypi_doc())})
    assert fetch_facts(pypi(), client).repository == "https://github.com/psf/requests"


def test_pypi_license_expression_preferred() -> None:
    client = StubClient(
        {"/requests/json": ok(pypi_doc(info={"license_expression": "MIT"}))}
    )
    assert fetch_facts(pypi(), client).license == "MIT"


def test_pypi_upload_time_becomes_published_at() -> None:
    client = StubClient({"/requests/json": ok(pypi_doc())})
    published = fetch_facts(pypi(), client).published_at
    assert published is not None
    assert published.year == 2023


# ---------------------------------------------------------------------------
# Malformed responses must not crash
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("body", ["a string", 42, [], None, {"unexpected": True}])
def test_unexpected_npm_body_is_handled(body: object) -> None:
    facts = fetch_facts(npm(), StubClient({"/express/latest": ok(body)}))
    assert isinstance(facts, PackageFacts)
    assert facts.ok is False or facts.resolved_version is None


@pytest.mark.parametrize("body", ["a string", 42, [], {"no_info": 1}])
def test_unexpected_pypi_body_is_handled(body: object) -> None:
    facts = fetch_facts(pypi(), StubClient({"/requests/json": ok(body)}))
    assert isinstance(facts, PackageFacts)
    assert facts.resolved_version is None


def test_bad_timestamp_is_ignored() -> None:
    client = StubClient(
        {
            "/express/latest": ok(npm_doc()),
            "deps.dev": ok({"publishedAt": "not a date", "advisoryKeys": []}),
        }
    )
    assert fetch_facts(npm(), client).published_at is None


# ---------------------------------------------------------------------------
# age_days
# ---------------------------------------------------------------------------


def test_age_days_computed_from_publish_date() -> None:
    week_ago = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=7)
    facts = PackageFacts(name="x", ecosystem=Ecosystem.NPM, published_at=week_ago)
    assert facts.age_days is not None
    assert 6.9 < facts.age_days < 7.1


def test_age_days_handles_naive_timestamp() -> None:
    naive = dt.datetime.now() - dt.timedelta(days=3)
    facts = PackageFacts(name="x", ecosystem=Ecosystem.NPM, published_at=naive)
    assert facts.age_days is not None


def test_age_days_none_without_publish_date() -> None:
    assert PackageFacts(name="x", ecosystem=Ecosystem.NPM).age_days is None


# ---------------------------------------------------------------------------
# gather
# ---------------------------------------------------------------------------


def test_gather_preserves_input_order() -> None:
    client = StubClient(
        {
            "/a/latest": ok(npm_doc(name="a", version="1.0.0")),
            "/b/latest": ok(npm_doc(name="b", version="2.0.0")),
            "/c/latest": ok(npm_doc(name="c", version="3.0.0")),
        }
    )
    specs = [npm("a"), npm("b"), npm("c")]
    assert [f.name for f in gather(specs, client)] == ["a", "b", "c"]


def test_gather_empty_input() -> None:
    assert gather([], StubClient()) == []


def test_gather_single_package_skips_the_pool() -> None:
    client = StubClient({"/express/latest": ok(npm_doc())})
    results = gather([npm()], client)
    assert len(results) == 1
    assert results[0].resolved_version == "4.18.0"


def test_gather_mixes_ecosystems() -> None:
    client = StubClient(
        {"/express/latest": ok(npm_doc()), "/requests/json": ok(pypi_doc())}
    )
    results = gather([npm(), pypi()], client)
    assert [f.ecosystem for f in results] == [Ecosystem.NPM, Ecosystem.PYPI]


def test_gather_survives_one_package_failing() -> None:
    client = StubClient({"/good/latest": ok(npm_doc(name="good"))})
    results = gather([npm("good"), npm("missing")], client)
    assert results[0].ok
    assert results[1].exists is False


# ---------------------------------------------------------------------------
# display
# ---------------------------------------------------------------------------


def test_display_includes_resolved_version() -> None:
    client = StubClient({"/express/latest": ok(npm_doc())})
    assert fetch_facts(npm(), client).display == "express@4.18.0"


def test_display_falls_back_to_name() -> None:
    assert PackageFacts(name="x", ecosystem=Ecosystem.NPM).display == "x"


@pytest.mark.parametrize("status", [400, 404, 405])
def test_registry_rejecting_the_name_means_it_does_not_exist(status: int) -> None:
    """Regression: npm answers 405 for a malformed name, not 404. Checking
    only for 404 left `exists=True` with no version, and the package was
    reported as merely lacking a source repository."""
    client = StubClient(
        {"/express/latest": Response(url="x", status=status, error=f"HTTP {status}")}
    )
    facts = fetch_facts(npm(), client)
    assert facts.exists is False
    assert facts.unreachable is False


@pytest.mark.parametrize("status", [400, 404, 405])
def test_pypi_rejecting_the_name_means_it_does_not_exist(status: int) -> None:
    client = StubClient(
        {"/requests/json": Response(url="x", status=status, error=f"HTTP {status}")}
    )
    assert fetch_facts(pypi(), client).exists is False
