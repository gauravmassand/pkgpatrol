# pkgpatrol

Vet npm and PyPI packages for supply-chain red flags **before** they install.

pkgpatrol hooks into Claude Code's `PreToolUse` event, watches for package
installs in `Bash` commands, and checks each package against the npm registry,
PyPI, and [deps.dev](https://deps.dev) — surfacing known advisories,
suspiciously new or unpopular packages, and likely typosquats. The intent is
that installs with known CVEs are denied even when Claude Code is running in
auto-approve mode.

It also works as a plain CLI, so you can check a package by hand.

## Status

**Early development.** The command parser and the hook protocol work. The
registry clients are not built, so **nothing is actually vetted yet** — the
hook detects installs and reports them, but cannot block anything.

| Command | What it does | State |
| --- | --- | --- |
| `pkgpatrol parse '<cmd>'` | Show what the parser extracts from a shell command. No network calls. | **Working** |
| `pkgpatrol hook` | Read a `PreToolUse` payload on stdin and answer. Detects and reports; returns `defer`. | **Working** |
| `pkgpatrol init --print` | Print the `settings.json` snippet to merge by hand. | **Working** |
| `pkgpatrol check <pkg>` | Vet named packages against the registries. | Not implemented |
| `pkgpatrol init` (no flag) | Edit `~/.claude/settings.json` in place. | Not implemented |

Unimplemented subcommands exit non-zero with a clear message, and the hook
says in its own output that it has not vetted anything. They do not silently
succeed — a security tool that appears to run but checks nothing is worse than
one that admits it is unfinished.

## Install

Not on PyPI yet. From a clone:

```sh
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

Requires Python 3.10 or newer.

## Try the parser

```console
$ pkgpatrol parse 'cd app && npm i -D @types/node@20 lodash && pip install -r reqs.txt httpx'
npm (npm)
  package  @types/node@20
  package  lodash
pip (pypi)
  package  httpx
  manifest install (package.json / requirements.txt)
```

It understands npm/yarn/pnpm/bun, pip/pip3/uv/poetry/pipx, the one-shot
runners (`npx`, `uvx`, `pnpm dlx`), `python -m pip` delegation, `sudo` and
`VAR=x` prefixes, `&&`/`;`/`|` chains, redirections, and scoped or pinned
names. Targets with no registry metadata — local paths, git URLs, tarballs —
are reported as skipped rather than silently dropped.

## Development

```sh
.venv/bin/python -m pytest tests/ -q
```

## Use it as a Claude Code hook

```sh
pkgpatrol init --print
```

Merge the printed block into `~/.claude/settings.json`, then start a new Claude
Code session — hooks are loaded at startup. The snippet uses the absolute path
to the binary rather than a bare name, because a GUI-launched editor does not
reliably inherit the `PATH` that a pipx or venv install depends on.

It is configured with `onFailure: "continue"` and a 10 second timeout, so a
hook failure or a slow registry lets the command through instead of blocking
it.

Today the hook returns `defer`, which leaves your own permission rules in
charge. Once registry checks land, a known CVE will return `deny` — including
when Claude Code is running in an auto-approve mode, where an `ask` would
otherwise be silently ignored.

## Design notes

- **Zero runtime dependencies.** Standard library only. A security tool that
  installs a dependency tree to check your dependency tree is self-defeating,
  and a hook that fails to import is a hook that silently stops guarding you.
  CI asserts this on every run.
- **Fail open, not closed.** Network timeouts and registry outages should let
  the install proceed with a warning. A broken check must never wedge your
  workflow. Known CVEs are the intended exception.
- **Over-detect rather than under-detect.** Where a command token is
  ambiguous, treat it as a package and let the registry decide. A false
  positive costs one wasted lookup; a false negative means an unvetted package
  on disk.
- **Per-ecosystem flag tables.** `-f` is `--find-links` for pip but `--force`
  for npm. Sharing one table across ecosystems made `npm i -f lodash` report
  zero packages — a failure that passes silently. The parser keeps them
  separate, with regression tests.

## License

MIT — see [LICENSE](LICENSE).
