"""Registry clients: resolve a package to a version and gather its signals.

Three sources, chosen by measurement rather than convenience:

``registry.npmjs.org/<name>/latest`` (~4 KB)
    Version, maintainer count, repository, license, deprecation, and the
    ``scripts`` block — install hooks are a prime malware vector. The *full*
    npm document is not an option: ``@types/node`` is 11 MB and ``react`` is
    7 MB, which no hook running under a ten-second budget can afford.

``api.npmjs.org/downloads/point/last-week/<name>`` (~80 B)
    Weekly downloads. npm only; PyPI has no first-party equivalent.

``api.deps.dev/v3/.../versions/<version>`` (~900 B)
    Security advisories and the publish date of that exact version. This is
    the one that matters most — it is where a CVE actually turns up.

About five kilobytes per package in total.

**Resolution is the subtle part.** When Claude runs ``npm install express``,
no version is named: npm picks the ``latest`` dist-tag at that moment. So we
must resolve the version ourselves before asking whether it is vulnerable —
``express`` is not vulnerable, ``express < 4.19.2`` is. :class:`PackageFacts`
always records which version was actually checked, because there is an
unavoidable race: we resolve ``latest``, then the package manager resolves it
again moments later. Naming the version makes a mismatch visible instead of
silent.
"""

from __future__ import annotations

import datetime as dt
import re
import urllib.parse
from dataclasses import dataclass, replace
from enum import Enum

from .http import Deadline, HttpClient, Response
from .parse import Ecosystem, PackageSpec

__all__ = [
    "Resolution",
    "PackageFacts",
    "gather",
    "fetch_facts",
]

NPM_REGISTRY = "https://registry.npmjs.org"
NPM_DOWNLOADS = "https://api.npmjs.org/downloads/point/last-week"
PYPI_REGISTRY = "https://pypi.org/pypi"
DEPSDEV = "https://api.deps.dev/v3/systems"

#: npm lifecycle scripts that execute automatically on install. Arbitrary code
#: running at install time is the single most direct supply-chain attack path,
#: so their presence is worth surfacing even for a reputable package.
INSTALL_SCRIPT_HOOKS = ("preinstall", "install", "postinstall", "prepare")

#: deps.dev names ecosystems in upper case.
_DEPSDEV_SYSTEM = {Ecosystem.NPM: "npm", Ecosystem.PYPI: "pypi"}


class Resolution(str, Enum):
    """How the checked version was arrived at.

    This is reported to the user because the three cases carry very different
    confidence. An ``EXACT`` pin is what will install; ``LATEST`` is what will
    install *if nothing is published in the next few seconds*; ``RANGE`` means
    we could not evaluate the constraint and fell back to latest, so the
    version we checked may not be the one that installs.
    """

    EXACT = "exact"
    LATEST = "latest"
    RANGE = "range-approximated"
    UNRESOLVED = "unresolved"

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.value


#: A complete semver version: MAJOR.MINOR.PATCH with optional prerelease and
#: build metadata. Matched positively rather than excluding "range
#: characters" — that approach mistook `4.x` for a pin, fetched a version
#: that does not exist, and reported a real package as missing, which is a
#: typosquat signal. A partial version (`4`, `4.18`) is a range in npm too.
_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")

#: A dist-tag: starts with a letter, but never `v` followed by a digit —
#: npm reads `v4` as a version range, not as a tag named "v4".
_DIST_TAG = re.compile(r"^(?!v\d)[A-Za-z][0-9A-Za-z._-]*$")


def _normalize_version(spec: str) -> str:
    """Strip a leading ``v``; the registry keys versions without it."""
    return spec[1:] if len(spec) > 1 and spec[0] == "v" and spec[1].isdigit() else spec


def _is_exact_npm_version(spec: str | None) -> bool:
    """True when ``spec`` names one npm version rather than a range or tag."""
    return bool(spec) and bool(_SEMVER.match(_normalize_version(spec)))


def _is_dist_tag(spec: str | None) -> bool:
    """True when ``spec`` is a dist-tag such as ``next`` or ``beta``."""
    return bool(spec) and bool(_DIST_TAG.match(spec))


def _is_exact_pypi_version(spec: str | None) -> bool:
    """True when ``spec`` pins one PyPI version (``==1.2.3``)."""
    if not spec:
        return False
    stripped = spec.strip()
    if not stripped.startswith("=="):
        return False
    return "," not in stripped and "*" not in stripped


def _parse_timestamp(value: object) -> dt.datetime | None:
    """Parse an ISO-8601 timestamp, tolerating the trailing ``Z``."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass(frozen=True)
class PackageFacts:
    """Everything we learned about one requested package.

    Deliberately flat and optional-heavy: any individual lookup may fail
    without invalidating the others, and the analysis layer must be able to
    reason about partial information rather than demanding all of it.
    """

    name: str
    ecosystem: Ecosystem
    #: The version spec written in the command, if any (``^4.18.0``).
    requested: str | None = None
    #: The version we actually checked.
    resolved_version: str | None = None
    resolution: Resolution = Resolution.UNRESOLVED

    #: False when the registry said 404 — a strong typosquat/typo signal.
    exists: bool = True
    #: True when we could not reach the registry at all. Must fail open.
    unreachable: bool = False
    errors: tuple[str, ...] = ()

    #: Security advisory identifiers (GHSA/CVE) affecting resolved_version.
    advisories: tuple[str, ...] = ()
    #: When resolved_version was published.
    published_at: dt.datetime | None = None
    #: Deprecation message, if the package or version is deprecated.
    deprecated: str | None = None
    #: PyPI only: the release was withdrawn after publication.
    yanked: bool = False

    license: str | None = None
    repository: str | None = None
    maintainers: int | None = None
    #: npm only; PyPI has no first-party download API.
    weekly_downloads: int | None = None
    #: npm lifecycle scripts that run automatically at install time.
    install_scripts: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        """True when we resolved a version and can say something useful."""
        return (
            self.exists and not self.unreachable and self.resolved_version is not None
        )

    @property
    def age_days(self) -> float | None:
        """Days since ``resolved_version`` was published."""
        if self.published_at is None:
            return None
        now = dt.datetime.now(dt.timezone.utc)
        published = self.published_at
        if published.tzinfo is None:
            published = published.replace(tzinfo=dt.timezone.utc)
        return (now - published).total_seconds() / 86400.0

    @property
    def display(self) -> str:
        if self.resolved_version:
            return f"{self.name}@{self.resolved_version}"
        return self.name

    def with_error(self, message: str) -> PackageFacts:
        return replace(self, errors=(*self.errors, message))


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------


def _npm_quote(name: str) -> str:
    """URL-encode a package name; scoped names need the slash escaped."""
    return urllib.parse.quote(name, safe="@")


def _npm_metadata_url(name: str, spec: str | None) -> tuple[str, Resolution]:
    """Pick the cheapest npm endpoint that answers the question.

    npm serves ``/<name>/<version-or-tag>`` as a small document, so an exact
    pin and a dist-tag both cost a few kilobytes. A *range* has no endpoint —
    evaluating it needs the full version list, which can be megabytes — so we
    check ``latest`` instead and say so.
    """
    quoted = _npm_quote(name)
    if _is_exact_npm_version(spec):
        assert spec is not None
        version = _normalize_version(spec)
        return f"{NPM_REGISTRY}/{quoted}/{version}", Resolution.EXACT
    if _is_dist_tag(spec):
        assert spec is not None
        return f"{NPM_REGISTRY}/{quoted}/{urllib.parse.quote(spec)}", Resolution.EXACT
    if spec:
        return f"{NPM_REGISTRY}/{quoted}/latest", Resolution.RANGE
    return f"{NPM_REGISTRY}/{quoted}/latest", Resolution.LATEST


def _apply_npm_metadata(facts: PackageFacts, response: Response) -> PackageFacts:
    if response.missing:
        return replace(facts, exists=False, resolution=Resolution.UNRESOLVED)
    if not response.ok:
        if response.unreachable:
            return replace(facts, unreachable=True).with_error(
                response.error or "npm unreachable"
            )
        return facts.with_error(response.error or "npm lookup failed")

    data = response.data
    if not isinstance(data, dict):
        return facts.with_error("npm returned an unexpected document")

    scripts = data.get("scripts")
    hooks: tuple[str, ...] = ()
    if isinstance(scripts, dict):
        hooks = tuple(h for h in INSTALL_SCRIPT_HOOKS if h in scripts)

    repository = data.get("repository")
    repo_url = None
    if isinstance(repository, dict):
        repo_url = repository.get("url")
    elif isinstance(repository, str):
        repo_url = repository

    maintainers = data.get("maintainers")
    deprecated = data.get("deprecated")
    license_value = data.get("license")
    if isinstance(license_value, dict):  # legacy npm packages used an object
        license_value = license_value.get("type")

    return replace(
        facts,
        resolved_version=data.get("version") or facts.resolved_version,
        license=license_value if isinstance(license_value, str) else None,
        repository=repo_url if isinstance(repo_url, str) else None,
        maintainers=len(maintainers) if isinstance(maintainers, list) else None,
        deprecated=deprecated if isinstance(deprecated, str) else None,
        install_scripts=hooks,
    )


def _apply_npm_downloads(facts: PackageFacts, response: Response) -> PackageFacts:
    if not response.ok or not isinstance(response.data, dict):
        return facts  # downloads are a nice-to-have, never an error
    count = response.data.get("downloads")
    if isinstance(count, int):
        return replace(facts, weekly_downloads=count)
    return facts


# ---------------------------------------------------------------------------
# PyPI
# ---------------------------------------------------------------------------


def _pypi_metadata_url(name: str, spec: str | None) -> tuple[str, Resolution]:
    quoted = urllib.parse.quote(name, safe="")
    if _is_exact_pypi_version(spec):
        version = spec.strip()[2:]
        return f"{PYPI_REGISTRY}/{quoted}/{urllib.parse.quote(version)}/json", (
            Resolution.EXACT
        )
    if spec:
        return f"{PYPI_REGISTRY}/{quoted}/json", Resolution.RANGE
    return f"{PYPI_REGISTRY}/{quoted}/json", Resolution.LATEST


def _apply_pypi_metadata(facts: PackageFacts, response: Response) -> PackageFacts:
    if response.missing:
        return replace(facts, exists=False, resolution=Resolution.UNRESOLVED)
    if not response.ok:
        if response.unreachable:
            return replace(facts, unreachable=True).with_error(
                response.error or "PyPI unreachable"
            )
        return facts.with_error(response.error or "PyPI lookup failed")

    data = response.data
    if not isinstance(data, dict):
        return facts.with_error("PyPI returned an unexpected document")

    info = data.get("info")
    if not isinstance(info, dict):
        return facts.with_error("PyPI response had no info block")

    urls = data.get("urls")
    yanked = False
    published = None
    if isinstance(urls, list) and urls and isinstance(urls[0], dict):
        yanked = bool(urls[0].get("yanked"))
        published = _parse_timestamp(urls[0].get("upload_time_iso_8601"))

    project_urls = info.get("project_urls")
    repository = None
    if isinstance(project_urls, dict):
        for key in ("Source", "Repository", "Source Code", "Homepage", "Code"):
            candidate = project_urls.get(key)
            if isinstance(candidate, str):
                repository = candidate
                break

    license_value = info.get("license_expression") or info.get("license")

    return replace(
        facts,
        resolved_version=info.get("version") or facts.resolved_version,
        license=license_value if isinstance(license_value, str) else None,
        repository=repository,
        yanked=yanked,
        published_at=published or facts.published_at,
    )


# ---------------------------------------------------------------------------
# deps.dev — advisories and publish dates
# ---------------------------------------------------------------------------


def _depsdev_url(name: str, ecosystem: Ecosystem, version: str) -> str:
    system = _DEPSDEV_SYSTEM[ecosystem]
    return (
        f"{DEPSDEV}/{system}/packages/{urllib.parse.quote(name, safe='')}"
        f"/versions/{urllib.parse.quote(version, safe='')}"
    )


def _apply_depsdev(facts: PackageFacts, response: Response) -> PackageFacts:
    if not response.ok or not isinstance(response.data, dict):
        # deps.dev is a secondary source. Its absence degrades the report but
        # is not itself a finding, so it is recorded and not escalated.
        if response.unreachable:
            return facts.with_error("deps.dev unreachable (advisories unchecked)")
        if response.missing:
            return facts.with_error("deps.dev has no record of this version")
        return facts

    data = response.data
    keys = data.get("advisoryKeys")
    advisories: tuple[str, ...] = ()
    if isinstance(keys, list):
        advisories = tuple(
            str(entry["id"])
            for entry in keys
            if isinstance(entry, dict) and entry.get("id")
        )

    published = _parse_timestamp(data.get("publishedAt"))
    deprecated = facts.deprecated
    if data.get("isDeprecated") and not deprecated:
        reason = data.get("deprecatedReason")
        deprecated = reason if isinstance(reason, str) and reason else "deprecated"

    return replace(
        facts,
        advisories=advisories,
        published_at=published or facts.published_at,
        deprecated=deprecated,
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def fetch_facts(
    spec: PackageSpec,
    client: HttpClient,
    deadline: Deadline | None = None,
) -> PackageFacts:
    """Resolve one package and collect its signals.

    Two round trips minimum: registry metadata to learn the version, then
    deps.dev for advisories against that version. The second cannot be issued
    until the first answers, since the version is part of its URL.
    """
    deadline = deadline or Deadline()
    facts = PackageFacts(
        name=spec.name, ecosystem=spec.ecosystem, requested=spec.version_spec
    )

    if spec.ecosystem is Ecosystem.NPM:
        url, resolution = _npm_metadata_url(spec.name, spec.version_spec)
        facts = replace(facts, resolution=resolution)
        facts = _apply_npm_metadata(facts, client.get_json(url, deadline))
        if facts.exists and not facts.unreachable:
            downloads_url = f"{NPM_DOWNLOADS}/{_npm_quote(spec.name)}"
            facts = _apply_npm_downloads(
                facts, client.get_json(downloads_url, deadline)
            )
    else:
        url, resolution = _pypi_metadata_url(spec.name, spec.version_spec)
        facts = replace(facts, resolution=resolution)
        facts = _apply_pypi_metadata(facts, client.get_json(url, deadline))

    if facts.resolved_version and facts.exists and not facts.unreachable:
        facts = _apply_depsdev(
            facts,
            client.get_json(
                _depsdev_url(facts.name, facts.ecosystem, facts.resolved_version),
                deadline,
            ),
        )
    elif not facts.resolved_version and facts.exists and not facts.unreachable:
        facts = replace(facts, resolution=Resolution.UNRESOLVED)

    return facts


def gather(
    specs: list[PackageSpec],
    client: HttpClient | None = None,
    deadline: Deadline | None = None,
    max_workers: int = 4,
) -> list[PackageFacts]:
    """Resolve several packages under one shared deadline.

    Each package needs two sequential round trips, so the parallelism is
    across packages rather than within one. Results keep the input order,
    which is the order the user wrote them.
    """
    if not specs:
        return []

    client = client or HttpClient()
    deadline = deadline or Deadline()

    # Imported lazily: the thread pool is only worth its cost for >1 package,
    # and a single install is the common case.
    if len(specs) == 1:
        return [fetch_facts(specs[0], client, deadline)]

    from concurrent.futures import ThreadPoolExecutor

    workers = max(1, min(max_workers, len(specs)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(fetch_facts, spec, client, deadline) for spec in specs]
        results: list[PackageFacts] = []
        for spec, future in zip(specs, futures, strict=True):
            try:
                results.append(future.result())
            except Exception as exc:  # pragma: no cover - defensive
                results.append(
                    PackageFacts(
                        name=spec.name,
                        ecosystem=spec.ecosystem,
                        requested=spec.version_spec,
                    ).with_error(f"{type(exc).__name__}: {exc}")
                )
    return results
