# pkgpatrol

Vet npm and PyPI packages for supply-chain red flags **before** they install.

pkgpatrol hooks into Claude Code's `PreToolUse` event, watches for package
installs in `Bash` commands, and checks each package against the npm registry,
PyPI, and [deps.dev](https://deps.dev) — surfacing known advisories,
suspiciously new or unpopular packages, and likely typosquats. Installs with
known CVEs are denied **even when Claude Code is running in auto-approve
mode**, where an ordinary permission prompt would be silently skipped.

It also works as a plain CLI, so you can check a package by hand.

```console
$ pkgpatrol check requests==2.28.0 --ecosystem pypi
requests@2.28.0  Apache-2.0
  XX 8 known security advisories for requests@2.28.0

BLOCKED: checked 1 package — 1 critical
```

## Install

```sh
pip install pkgpatrol
```

Requires Python 3.10 or newer. **Zero runtime dependencies** — standard
library only, asserted in CI on every run.

## Use it as a Claude Code hook

```sh
pkgpatrol init
```

That merges the hook into `~/.claude/settings.json`, backing the file up
first and leaving your other settings alone. Start a new Claude Code session
afterwards — hooks load at startup.

Prefer to edit by hand? `pkgpatrol init --print` emits the snippet, and
`pkgpatrol init --dry-run` reports what would change without writing.

Once installed, every `Bash` command Claude runs is inspected for package
installs. Nothing happens for commands that install nothing.

## What it checks

| Signal | Severity | Effect |
| --- | --- | --- |
| Known security advisory (CVE/GHSA) | critical | **blocks**, in every mode |
| Package does not exist in the registry | critical | **blocks** |
| Name resembles a popular package | high | prompts, or blocks under auto-approve |
| Release yanked after publication | high | prompts |
| Fewer than 50 weekly downloads | high | prompts |
| Runs code at install time (`postinstall`) | medium | reported |
| Published within the last 14 days | medium | reported |
| Deprecated | medium | reported |
| Fewer than 1,000 weekly downloads | medium | reported |
| Single maintainer, no source repository | low | reported |

Thresholds live in `Policy` and are tunable.

## Commands

| Command | What it does |
| --- | --- |
| `pkgpatrol check <pkg>…` | Vet packages and print a report. Exits non-zero if anything is flagged, so it composes with `&&` and gates CI. |
| `pkgpatrol init` | Install the hook into `~/.claude/settings.json`. |
| `pkgpatrol hook` | Run as a `PreToolUse` hook, reading a payload on stdin. |
| `pkgpatrol parse '<cmd>'` | Show what the parser extracts from a shell command. No network calls. |

`check` takes `--json` for machine-readable output, `-v` to explain why each
finding matters, `--no-color`, and `--no-cache`.

## Design notes

- **Zero runtime dependencies.** A security tool that installs a dependency
  tree to check your dependency tree is self-defeating, and a hook that
  fails to import is a hook that silently stops guarding you.
- **Fail open, loudly.** Network timeouts and registry outages let the
  install proceed, and say plainly that nothing was verified — never that
  the package looked fine. Known CVEs are the deliberate exception.
- **`defer`, not `allow`.** When there is nothing to report, the hook stays
  out of the way rather than overriding your own permission rules.
- **Escalate rather than lose a finding.** In auto-approve mode an `ask` is
  silently discarded, so a high-severity finding becomes a `deny` — you can
  always override it, but you cannot override a warning you never saw.
- **Restraint over recall.** A warning that fires on `preact` or `urllib3`
  trains you to dismiss warnings, so the typosquat check exempts popular
  packages and anything with real download numbers.

## Known limitations

- **Version ranges are approximated.** `npm i express@^4.18.0` cannot be
  resolved without the full version list — megabytes for large packages — so
  the latest version is checked instead and the report says so.
- **There is a resolve-then-install race.** We resolve `latest`, then the
  package manager resolves it again moments later. The exact version checked
  is always named so a mismatch is visible.
- **PyPI download counts are unavailable.** No first-party API exists, so
  download-based signals are npm-only.
- **Manifest installs are not inspected.** `npm ci` and `pip install -r`
  install from a lockfile; their contents are not yet read.

## Development

```sh
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m pytest tests/ -q
.venv/bin/python -m ruff check . && .venv/bin/python -m ruff format --check .
```

Tests never touch the network or your real home directory — a conftest
fixture redirects `Path.home()` for every test.

## License

MIT — see [LICENSE](LICENSE).
