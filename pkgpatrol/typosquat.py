"""Detect names that imitate popular packages.

Typosquatting works because a single wrong keystroke installs someone else's
code: ``reqeusts`` instead of ``requests``, ``lodahs`` instead of ``lodash``.
The attack needs no vulnerability — only a plausible misspelling and a
distracted human, or an agent that hallucinated a package name.

**The hard part is not detection, it is restraint.** Real ecosystems are full
of legitimate neighbours: ``preact`` is one edit from ``react``, ``urllib3``
from ``urllib``. Flagging those would be worse than flagging nothing, because
a warning that fires on real packages stops being read. So three guards apply
before anything is reported:

1. A name on the popular list is never suspected of imitating the list.
2. A widely-downloaded package is never a typosquat — squats have no users.
3. Only *small* edit distances count, and only for names long enough that a
   single edit is not most of the word.

Stdlib only: the distance function is a few lines, and a dependency here
would undermine the point of the project.
"""

from __future__ import annotations

from dataclasses import dataclass

from .parse import Ecosystem

__all__ = [
    "Imitation",
    "check_name",
    "POPULAR_NPM",
    "POPULAR_PYPI",
]

#: Maximum edit distance still considered an imitation.
MAX_DISTANCE = 2

#: Names shorter than this are skipped: with four characters, one edit is a
#: quarter of the word, and short names collide by coincidence constantly.
MIN_LENGTH = 4

#: Weekly downloads above which a package is established enough that
#: resembling a popular name is coincidence, not imitation.
ESTABLISHED_DOWNLOADS = 50_000


# Popular packages, as imitation targets. Curated rather than fetched: a
# network call here would be one more thing to fail inside a hook, and the
# list of worthwhile targets changes slowly.
POPULAR_NPM = frozenset(
    # fmt: off
    {
        "react",
        "react-dom",
        "vue",
        "angular",
        "svelte",
        "preact",
        "next",
        "nuxt",
        "express",
        "koa",
        "fastify",
        "nest",
        "axios",
        "node-fetch",
        "got",
        "superagent",
        "request",
        "lodash",
        "underscore",
        "ramda",
        "moment",
        "dayjs",
        "date-fns",
        "luxon",
        "chalk",
        "colors",
        "commander",
        "yargs",
        "inquirer",
        "ora",
        "debug",
        "winston",
        "pino",
        "bunyan",
        "dotenv",
        "config",
        "convict",
        "jest",
        "mocha",
        "chai",
        "sinon",
        "vitest",
        "cypress",
        "playwright",
        "puppeteer",
        "selenium-webdriver",
        "webpack",
        "rollup",
        "vite",
        "parcel",
        "esbuild",
        "babel",
        "typescript",
        "ts-node",
        "tsx",
        "eslint",
        "prettier",
        "standard",
        "husky",
        "lint-staged",
        "nodemon",
        "pm2",
        "concurrently",
        "cross-env",
        "rimraf",
        "mkdirp",
        "glob",
        "minimatch",
        "chokidar",
        "fs-extra",
        "graceful-fs",
        "uuid",
        "nanoid",
        "shortid",
        "bcrypt",
        "bcryptjs",
        "jsonwebtoken",
        "passport",
        "helmet",
        "cors",
        "body-parser",
        "cookie-parser",
        "multer",
        "morgan",
        "compression",
        "socket.io",
        "ws",
        "mongoose",
        "sequelize",
        "prisma",
        "typeorm",
        "knex",
        "pg",
        "mysql",
        "mysql2",
        "sqlite3",
        "redis",
        "ioredis",
        "mongodb",
        "graphql",
        "apollo-server",
        "yup",
        "joi",
        "zod",
        "ajv",
        "classnames",
        "clsx",
        "styled-components",
        "emotion",
        "tailwindcss",
        "postcss",
        "autoprefixer",
        "sass",
        "less",
        "redux",
        "mobx",
        "zustand",
        "recoil",
        "immer",
        "rxjs",
        "three",
        "d3",
        "chart.js",
        "leaflet",
        "marked",
        "highlight.js",
        "prismjs",
        "cheerio",
        "jsdom",
        "semver",
        "async",
        "bluebird",
        "node-sass",
        "core-js",
        "regenerator-runtime",
        "tslib",
        "left-pad",
        "is-odd",
        "is-even",
        "qs",
        "form-data",
        "mime",
        "mime-types",
        "content-type",
        "raw-body",
        "on-finished",
        "statuses",
        "depd",
    }
    # fmt: on
)

POPULAR_PYPI = frozenset(
    # fmt: off
    {
        "requests",
        "urllib3",
        "httpx",
        "aiohttp",
        "httplib2",
        "certifi",
        "charset-normalizer",
        "idna",
        "numpy",
        "pandas",
        "scipy",
        "matplotlib",
        "seaborn",
        "plotly",
        "bokeh",
        "scikit-learn",
        "tensorflow",
        "torch",
        "keras",
        "transformers",
        "datasets",
        "nltk",
        "spacy",
        "gensim",
        "opencv-python",
        "pillow",
        "imageio",
        "django",
        "flask",
        "fastapi",
        "starlette",
        "uvicorn",
        "gunicorn",
        "tornado",
        "bottle",
        "pyramid",
        "sanic",
        "celery",
        "redis",
        "sqlalchemy",
        "alembic",
        "psycopg2",
        "psycopg2-binary",
        "pymysql",
        "pymongo",
        "elasticsearch",
        "boto3",
        "botocore",
        "awscli",
        "google-cloud-storage",
        "azure-storage-blob",
        "pytest",
        "unittest2",
        "nose",
        "tox",
        "coverage",
        "hypothesis",
        "faker",
        "factory-boy",
        "mock",
        "responses",
        "freezegun",
        "black",
        "flake8",
        "pylint",
        "mypy",
        "ruff",
        "isort",
        "autopep8",
        "bandit",
        "pre-commit",
        "click",
        "typer",
        "rich",
        "colorama",
        "tqdm",
        "tabulate",
        "prompt-toolkit",
        "pyyaml",
        "toml",
        "tomli",
        "configparser",
        "python-dotenv",
        "jinja2",
        "markupsafe",
        "markdown",
        "docutils",
        "sphinx",
        "mkdocs",
        "beautifulsoup4",
        "lxml",
        "html5lib",
        "scrapy",
        "selenium",
        "pydantic",
        "marshmallow",
        "attrs",
        "cattrs",
        "dataclasses-json",
        "setuptools",
        "wheel",
        "pip",
        "build",
        "twine",
        "hatchling",
        "poetry",
        "virtualenv",
        "cryptography",
        "pyjwt",
        "passlib",
        "bcrypt",
        "paramiko",
        "pyopenssl",
        "six",
        "future",
        "python-dateutil",
        "pytz",
        "arrow",
        "pendulum",
        "more-itertools",
        "typing-extensions",
        "packaging",
        "importlib-metadata",
        "protobuf",
        "grpcio",
        "openai",
        "anthropic",
        "langchain",
        "tiktoken",
    }
    # fmt: on
)

_POPULAR = {Ecosystem.NPM: POPULAR_NPM, Ecosystem.PYPI: POPULAR_PYPI}

#: Separators that mean the same thing to a human but not to a registry.
#: `python-dateutil` and `python_dateutil` are different packages; a human
#: reading an install command will not notice which one they got.
_SEPARATORS = str.maketrans({"-": "", "_": "", ".": ""})


@dataclass(frozen=True)
class Imitation:
    """A popular name that the examined name closely resembles."""

    candidate: str
    target: str
    distance: int
    #: True when the names differ only in separators or case — the most
    #: deceptive case, since the two are visually near-identical.
    confusable: bool = False

    @property
    def summary(self) -> str:
        if self.confusable:
            return (
                f"{self.candidate!r} differs from {self.target!r} only in punctuation"
            )
        return (
            f"{self.candidate!r} is {self.distance} character(s) from {self.target!r}"
        )


def damerau_levenshtein(left: str, right: str, limit: int = MAX_DISTANCE) -> int:
    """Edit distance counting insert, delete, substitute, and transpose.

    Transposition matters more than the other operations here: ``recieve``
    for ``receive`` is the archetypal typo, and plain Levenshtein charges it
    two edits, which would push real typosquats past the threshold.

    Returns ``limit + 1`` as soon as the distance is known to exceed
    ``limit`` — the exact value is irrelevant once it is too large, and
    bailing early keeps this cheap across a few hundred candidates.
    """
    if left == right:
        return 0
    if abs(len(left) - len(right)) > limit:
        return limit + 1

    previous_previous: list[int] = []
    previous = list(range(len(right) + 1))

    for i, left_char in enumerate(left, start=1):
        current = [i] + [0] * len(right)
        best = current[0]
        for j, right_char in enumerate(right, start=1):
            cost = 0 if left_char == right_char else 1
            current[j] = min(
                previous[j] + 1,  # deletion
                current[j - 1] + 1,  # insertion
                previous[j - 1] + cost,  # substitution
            )
            if (
                i > 1
                and j > 1
                and left_char == right[j - 2]
                and left[i - 2] == right_char
            ):
                current[j] = min(current[j], previous_previous[j - 2] + cost)
            best = min(best, current[j])
        if best > limit:
            return limit + 1
        previous_previous, previous = previous, current

    return previous[-1]


def _normalize(name: str) -> str:
    """Strip separators and case, so visually similar names collide."""
    return name.lower().translate(_SEPARATORS)


def _strip_scope(name: str) -> str:
    """``@scope/pkg`` → ``pkg``; the bare name is what gets misread."""
    return name.split("/", 1)[1] if name.startswith("@") and "/" in name else name


def check_name(
    name: str,
    ecosystem: Ecosystem,
    weekly_downloads: int | None = None,
    exists: bool = True,
) -> Imitation | None:
    """Return the popular name ``name`` appears to imitate, if any.

    ``weekly_downloads`` suppresses the check for established packages — a
    package with real users is not a squat, whatever it is spelled like.
    ``exists=False`` *strengthens* the signal: a nonexistent name one edit
    from a popular one is the classic typo.
    """
    popular = _POPULAR.get(ecosystem)
    if not popular:
        return None

    bare = _strip_scope(name).lower()
    if len(bare) < MIN_LENGTH:
        return None

    # Rule 1: a popular package cannot be imitating the popular list.
    if bare in popular:
        return None

    # Rule 2: real users mean it is not a squat.
    if (
        exists
        and weekly_downloads is not None
        and weekly_downloads >= ESTABLISHED_DOWNLOADS
    ):
        return None

    normalized = _normalize(bare)

    # The most deceptive case first: identical once punctuation is removed.
    for target in popular:
        if _normalize(target) == normalized and target != bare:
            return Imitation(candidate=name, target=target, distance=0, confusable=True)

    best: Imitation | None = None
    for target in popular:
        distance = damerau_levenshtein(bare, target)
        if 0 < distance <= MAX_DISTANCE and (best is None or distance < best.distance):
            best = Imitation(candidate=name, target=target, distance=distance)
            if distance == 1:
                break  # cannot do better

    return best
