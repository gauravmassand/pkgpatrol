"""Shared test fixtures and safety rails.

The autouse fixtures here exist because two of this project's modules write
to, and read from, the user's real home directory: ``settings.py`` edits
``~/.claude/settings.json`` and ``http.py`` caches under ``~/.cache``.

A test that forgets to pass a temporary path would otherwise touch the
developer's actual Claude Code configuration. That is not hypothetical — it
happened during development, when a stale test calling ``main(["init"])``
rewrote a real settings file the moment ``init`` became implemented.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolate_home(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """Point ``Path.home()`` and the cache at a temporary directory.

    Applied to every test. A test that genuinely needs the real home has to
    undo this deliberately, which is the right amount of friction for
    something that can clobber a developer's configuration.
    """
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))  # Windows
    monkeypatch.setenv("PKGPATROL_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr("pathlib.Path.home", lambda: home)
    return home
