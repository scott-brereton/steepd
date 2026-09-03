"""This project will be lifted into its own repository. These tests fail if that would break."""

from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Design documents legitimately record where the ported code came from.
# Documents allowed to name the originating project as history rather than as a live
# dependency, by path relative to the project root (not bare basename, so a same-named
# file elsewhere is still scanned). Empty since the build plans left the repository.
DESIGN_DOCS: set[Path] = set()

# This file necessarily contains the needle strings literally (as parametrize
# values and assertion checks), so scanning it against itself would always fail.
SELF_REFERENCE = "test_portability.py"

# Every pattern is recursive. This list has been wrong three times, each time the
# same way: a pattern that matched where someone looked but not where the file
# would actually live. Root-anchored "*.yml" scanned nothing in .github/workflows,
# which is precisely where a CI file carrying an absolute path would sit. Prefer
# adding an extension here over narrowing a path.
SEARCH_PATTERNS = (
    "**/*.py",
    "**/*.toml",
    "**/*.md",
    "**/*.html",
    "**/*.yml",
    "**/*.yaml",
    "**/*.sh",
    "**/*.json",
    "**/*.txt",
    "**/*.cfg",
    "**/*.ini",
    "**/Dockerfile",
)


def _searchable(root=PROJECT_ROOT):
    return [
        path
        for pattern in SEARCH_PATTERNS
        for path in root.glob(pattern)
        if ".venv" not in path.parts and "__pycache__" not in path.parts
    ]


def _offenders(needle, searchable, root=PROJECT_ROOT):
    return [
        path.relative_to(root)
        for path in searchable
        if needle in path.read_text(encoding="utf-8")
        and path.relative_to(root) not in DESIGN_DOCS
        and path.name != SELF_REFERENCE
    ]


SEARCHABLE = _searchable()


def test_there_are_files_to_check():
    assert SEARCHABLE, "glob found nothing - the portability check would vacuously pass"


@pytest.mark.parametrize("needle", ["x4_books", "x4-books"])
def test_no_reference_to_the_originating_project(needle):
    offenders = _offenders(needle, SEARCHABLE)
    assert offenders == [], f"{needle!r} would dangle once this folder moves: {offenders}"


def test_no_absolute_paths_into_the_current_checkout():
    offenders = _offenders("/Users/", SEARCHABLE)
    assert offenders == [], f"absolute paths break on move: {offenders}"


def test_the_scanner_catches_a_planted_violation_in_html():
    """Proves the guard is not vacuous: an HTML file was the exact blind spot that let
    proposal.html's `src/x4_books/` reference through undetected. Plant a matching
    violation in a scanned HTML location and confirm the scanner flags it."""
    probe = PROJECT_ROOT / "docs" / "_portability_probe.html"
    probe.write_text("<p>src/x4_books/ and /Users/someone/repo</p>", encoding="utf-8")
    try:
        searchable = _searchable()
        assert probe in searchable, "probe file was not even picked up by the glob"
        assert _offenders("x4_books", searchable) == [Path("docs/_portability_probe.html")]
        assert _offenders("/Users/", searchable) == [Path("docs/_portability_probe.html")]
    finally:
        probe.unlink()


def test_the_scanner_catches_a_planted_violation_in_yml():
    """Plants in .github/workflows deliberately, not at the project root.

    An earlier version of this test planted at root and passed while
    .github/workflows/ci.yml, scripts/deploy.sh and deploy/Dockerfile were all
    silently unscanned - it proved the extension was listed, not that the glob
    reached anywhere real. A CI workflow is the most likely future carrier of an
    absolute path, so that is where the probe belongs."""
    probe = PROJECT_ROOT / ".github" / "workflows" / "_portability_probe.yml"
    probe.parent.mkdir(parents=True, exist_ok=True)
    probe.write_text("path: src/x4_books/ # /Users/someone/repo\n", encoding="utf-8")
    expected = Path(".github/workflows/_portability_probe.yml")
    try:
        searchable = _searchable()
        assert probe in searchable, "probe file was not even picked up by the glob"
        assert _offenders("x4_books", searchable) == [expected]
        assert _offenders("/Users/", searchable) == [expected]
    finally:
        probe.unlink(missing_ok=True)
        # Remove only directories this test created, and only if empty.
        for directory in (probe.parent, probe.parent.parent):
            if directory.is_dir() and not any(directory.iterdir()):
                directory.rmdir()


def test_design_doc_exclusion_is_path_relative_not_bare_basename():
    """A same-named file outside the recorded design-doc paths must still be scanned -
    exclusion by bare basename would let e.g. any `proposal.html` anywhere escape."""
    probe = PROJECT_ROOT / "docs" / "proposal.html"
    probe.write_text("<p>src/x4_books/</p>", encoding="utf-8")
    try:
        searchable = _searchable()
        assert probe in searchable, "probe file was not even picked up by the glob"
        assert _offenders("x4_books", searchable) == [Path("docs/proposal.html")]
    finally:
        probe.unlink()


def test_no_source_file_escapes_the_project_root():
    offenders = [
        path.relative_to(PROJECT_ROOT)
        for path in PROJECT_ROOT.glob("src/**/*.py")
        if "../" in path.read_text(encoding="utf-8")
    ]
    assert offenders == [], f"parent-relative paths break on move: {offenders}"


def test_project_is_self_describing():
    for required in ("pyproject.toml", "LICENSE", "README.md", ".gitignore"):
        assert (PROJECT_ROOT / required).is_file(), f"{required} must ship with the project"
