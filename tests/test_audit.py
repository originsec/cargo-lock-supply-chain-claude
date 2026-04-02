"""Unit tests for audit-supply-chain.py."""

from __future__ import annotations

import json
import re
import sys
import textwrap
from pathlib import Path

import pytest

# Add scripts/ to path so we can import the module
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import importlib

audit = importlib.import_module("audit-supply-chain")

# Re-export for convenience
parse_lockfile = audit.parse_lockfile
parse_semver = audit.parse_semver
compute_changes = audit.compute_changes
Change = audit.Change
Verdict = audit.Verdict
is_binary = audit.is_binary
collect_files = audit.collect_files
diff_crates = audit.diff_crates
format_comment = audit.format_comment
extract_crate = audit.extract_crate


# ---------------------------------------------------------------------------
# parse_lockfile
# ---------------------------------------------------------------------------


class TestParseLockfile:
    def test_empty_string(self):
        assert parse_lockfile("") == {}

    def test_whitespace_only(self):
        assert parse_lockfile("   \n\n  ") == {}

    def test_single_registry_package(self):
        text = textwrap.dedent("""\
            version = 4

            [[package]]
            name = "serde"
            version = "1.0.200"
            source = "registry+https://github.com/rust-lang/crates.io-index"
            checksum = "abc123"
        """)
        result = parse_lockfile(text)
        assert result == {"serde": {"1.0.200": "abc123"}}

    def test_multiple_versions_same_package(self):
        text = textwrap.dedent("""\
            version = 4

            [[package]]
            name = "ahash"
            version = "0.7.8"
            source = "registry+https://github.com/rust-lang/crates.io-index"
            checksum = "aaa"

            [[package]]
            name = "ahash"
            version = "0.8.12"
            source = "registry+https://github.com/rust-lang/crates.io-index"
            checksum = "bbb"
        """)
        result = parse_lockfile(text)
        assert result == {"ahash": {"0.7.8": "aaa", "0.8.12": "bbb"}}

    def test_skips_path_dependencies(self):
        text = textwrap.dedent("""\
            version = 4

            [[package]]
            name = "my-local-crate"
            version = "0.1.0"

            [[package]]
            name = "serde"
            version = "1.0.200"
            source = "registry+https://github.com/rust-lang/crates.io-index"
            checksum = "abc"
        """)
        result = parse_lockfile(text)
        assert "my-local-crate" not in result
        assert "serde" in result

    def test_skips_git_dependencies(self):
        text = textwrap.dedent("""\
            version = 4

            [[package]]
            name = "git-dep"
            version = "0.1.0"
            source = "git+https://github.com/example/repo.git#abc123"

            [[package]]
            name = "serde"
            version = "1.0.200"
            source = "registry+https://github.com/rust-lang/crates.io-index"
            checksum = "abc"
        """)
        result = parse_lockfile(text)
        assert "git-dep" not in result
        assert "serde" in result

    def test_package_without_checksum(self):
        text = textwrap.dedent("""\
            version = 4

            [[package]]
            name = "foo"
            version = "1.0.0"
            source = "registry+https://github.com/rust-lang/crates.io-index"
        """)
        result = parse_lockfile(text)
        assert result == {"foo": {"1.0.0": None}}

    def test_package_with_dependencies_field(self):
        text = textwrap.dedent("""\
            version = 4

            [[package]]
            name = "tokio"
            version = "1.40.0"
            source = "registry+https://github.com/rust-lang/crates.io-index"
            checksum = "tok123"
            dependencies = [
             "bytes",
             "pin-project-lite",
            ]
        """)
        result = parse_lockfile(text)
        assert result == {"tokio": {"1.40.0": "tok123"}}

    def test_multiple_packages(self):
        text = textwrap.dedent("""\
            version = 4

            [[package]]
            name = "serde"
            version = "1.0.200"
            source = "registry+https://github.com/rust-lang/crates.io-index"
            checksum = "aaa"

            [[package]]
            name = "tokio"
            version = "1.40.0"
            source = "registry+https://github.com/rust-lang/crates.io-index"
            checksum = "bbb"

            [[package]]
            name = "local-crate"
            version = "0.1.0"
        """)
        result = parse_lockfile(text)
        assert len(result) == 2
        assert "serde" in result
        assert "tokio" in result
        assert "local-crate" not in result


# ---------------------------------------------------------------------------
# parse_semver
# ---------------------------------------------------------------------------


class TestParseSemver:
    def test_normal_version(self):
        assert parse_semver("1.2.3") == (1, 2, 3)

    def test_zero_version(self):
        assert parse_semver("0.0.0") == (0, 0, 0)

    def test_large_numbers(self):
        assert parse_semver("100.200.300") == (100, 200, 300)

    def test_prerelease_suffix_ignored(self):
        assert parse_semver("1.2.3-alpha.1") == (1, 2, 3)

    def test_invalid_version(self):
        assert parse_semver("not-a-version") == (0, 0, 0)

    def test_ordering(self):
        assert parse_semver("1.0.0") < parse_semver("2.0.0")
        assert parse_semver("1.0.0") < parse_semver("1.1.0")
        assert parse_semver("1.0.0") < parse_semver("1.0.1")
        assert parse_semver("0.9.9") < parse_semver("1.0.0")


# ---------------------------------------------------------------------------
# compute_changes
# ---------------------------------------------------------------------------


class TestComputeChanges:
    def test_no_changes(self):
        pkgs = {"serde": {"1.0.200": "abc"}}
        assert compute_changes(pkgs, pkgs) == []

    def test_new_dependency(self):
        base = {}
        head = {"serde": {"1.0.200": "abc"}}
        changes = compute_changes(base, head)
        assert len(changes) == 1
        assert changes[0] == Change("serde", None, "1.0.200", "added")

    def test_removed_dependency_skipped(self):
        base = {"serde": {"1.0.200": "abc"}}
        head = {}
        changes = compute_changes(base, head)
        assert changes == []

    def test_upgrade(self):
        base = {"serde": {"1.0.200": "aaa"}}
        head = {"serde": {"1.0.201": "bbb"}}
        changes = compute_changes(base, head)
        assert len(changes) == 1
        assert changes[0] == Change("serde", "1.0.200", "1.0.201", "upgraded")

    def test_downgrade(self):
        base = {"serde": {"1.0.201": "bbb"}}
        head = {"serde": {"1.0.200": "aaa"}}
        changes = compute_changes(base, head)
        assert len(changes) == 1
        assert changes[0] == Change("serde", "1.0.201", "1.0.200", "downgraded")

    def test_major_upgrade(self):
        base = {"tokio": {"0.2.25": "aaa"}}
        head = {"tokio": {"1.0.0": "bbb"}}
        changes = compute_changes(base, head)
        assert len(changes) == 1
        assert changes[0].change_type == "upgraded"

    def test_multiple_deps_changed(self):
        base = {"serde": {"1.0.200": "a"}, "tokio": {"1.39.0": "b"}}
        head = {"serde": {"1.0.201": "c"}, "tokio": {"1.40.0": "d"}}
        changes = compute_changes(base, head)
        assert len(changes) == 2
        names = {c.name for c in changes}
        assert names == {"serde", "tokio"}

    def test_unchanged_deps_excluded(self):
        base = {"serde": {"1.0.200": "a"}, "tokio": {"1.40.0": "b"}}
        head = {"serde": {"1.0.201": "c"}, "tokio": {"1.40.0": "b"}}
        changes = compute_changes(base, head)
        assert len(changes) == 1
        assert changes[0].name == "serde"

    def test_multiple_versions_added(self):
        base = {}
        head = {"ahash": {"0.7.8": "a", "0.8.12": "b"}}
        changes = compute_changes(base, head)
        assert len(changes) == 2
        assert all(c.change_type == "added" for c in changes)

    def test_version_slot_swap(self):
        """One version removed and a different one added (multi-version crate)."""
        base = {"ahash": {"0.7.8": "a", "0.8.11": "b"}}
        head = {"ahash": {"0.7.8": "a", "0.8.12": "c"}}
        changes = compute_changes(base, head)
        assert len(changes) == 1
        assert changes[0] == Change("ahash", "0.8.11", "0.8.12", "upgraded")

    def test_sorted_output(self):
        base = {}
        head = {"zebra": {"1.0.0": "z"}, "alpha": {"1.0.0": "a"}, "mid": {"1.0.0": "m"}}
        changes = compute_changes(base, head)
        names = [c.name for c in changes]
        assert names == ["alpha", "mid", "zebra"]


# ---------------------------------------------------------------------------
# is_binary
# ---------------------------------------------------------------------------


class TestIsBinary:
    def test_text_file(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello world\n")
        assert is_binary(f) is False

    def test_binary_file(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00\x01\x02\x03")
        assert is_binary(f) is True

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty"
        f.write_bytes(b"")
        assert is_binary(f) is False

    def test_nonexistent_file(self, tmp_path):
        f = tmp_path / "nope"
        assert is_binary(f) is True

    def test_rust_source(self, tmp_path):
        f = tmp_path / "lib.rs"
        f.write_text('fn main() { println!("hello"); }\n')
        assert is_binary(f) is False


# ---------------------------------------------------------------------------
# collect_files
# ---------------------------------------------------------------------------


class TestCollectFiles:
    def test_empty_directory(self, tmp_path):
        assert collect_files(tmp_path) == {}

    def test_flat_files(self, tmp_path):
        (tmp_path / "a.txt").write_text("a")
        (tmp_path / "b.txt").write_text("b")
        result = collect_files(tmp_path)
        assert set(result.keys()) == {"a.txt", "b.txt"}

    def test_nested_files(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "lib.rs").write_text("fn foo() {}")
        result = collect_files(tmp_path)
        assert "src/lib.rs" in result

    def test_skips_directories(self, tmp_path):
        (tmp_path / "subdir").mkdir()
        result = collect_files(tmp_path)
        assert result == {}

    def test_uses_forward_slashes(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "b").mkdir()
        (tmp_path / "a" / "b" / "c.txt").write_text("c")
        result = collect_files(tmp_path)
        assert "a/b/c.txt" in result


# ---------------------------------------------------------------------------
# diff_crates
# ---------------------------------------------------------------------------


class TestDiffCrates:
    def test_identical_directories(self, tmp_path):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        (old / "lib.rs").write_text("fn foo() {}\n")
        (new / "lib.rs").write_text("fn foo() {}\n")
        result = diff_crates(old, new)
        assert result.strip() == ""

    def test_modified_file(self, tmp_path):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        (old / "lib.rs").write_text("fn foo() {}\n")
        (new / "lib.rs").write_text("fn bar() {}\n")
        result = diff_crates(old, new)
        assert "-fn foo() {}" in result
        assert "+fn bar() {}" in result

    def test_new_file(self, tmp_path):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        (new / "new_file.rs").write_text("fn new() {}\n")
        result = diff_crates(old, new)
        assert "+fn new() {}" in result
        assert "/dev/null" in result

    def test_deleted_file(self, tmp_path):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        (old / "removed.rs").write_text("fn old() {}\n")
        result = diff_crates(old, new)
        assert "-fn old() {}" in result
        assert "/dev/null" in result

    def test_new_dep_none_old_dir(self, tmp_path):
        new = tmp_path / "new"
        new.mkdir()
        (new / "lib.rs").write_text("fn hello() {}\n")
        result = diff_crates(None, new)
        assert "+fn hello() {}" in result

    def test_binary_file_change(self, tmp_path):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        (old / "data.bin").write_bytes(b"\x00" * 100)
        (new / "data.bin").write_bytes(b"\x00" * 200)
        result = diff_crates(old, new)
        assert "Binary file data.bin changed (100 -> 200 bytes)" in result

    def test_binary_file_added(self, tmp_path):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        (new / "data.bin").write_bytes(b"\x00" * 50)
        result = diff_crates(old, new)
        assert "Binary file data.bin added (50 bytes)" in result

    def test_binary_file_same_size_no_output(self, tmp_path):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        (old / "data.bin").write_bytes(b"\x00" * 100)
        (new / "data.bin").write_bytes(b"\x00" * 100)
        result = diff_crates(old, new)
        assert "data.bin" not in result


# ---------------------------------------------------------------------------
# extract_crate
# ---------------------------------------------------------------------------


class TestExtractCrate:
    def test_valid_tarball(self, tmp_path):
        import tarfile as tf

        # Create a fake crate tarball
        crate_dir = tmp_path / "build"
        crate_dir.mkdir()
        inner = crate_dir / "foo-1.0.0"
        inner.mkdir()
        (inner / "Cargo.toml").write_text('[package]\nname = "foo"\n')
        (inner / "src").mkdir()
        (inner / "src" / "lib.rs").write_text("pub fn foo() {}\n")

        tarball = tmp_path / "foo-1.0.0.crate"
        with tf.open(tarball, "w:gz") as tar:
            tar.add(inner, arcname="foo-1.0.0")

        dest = tmp_path / "extract"
        dest.mkdir()
        result = extract_crate(tarball, dest)
        assert result is not None
        assert result.name == "foo-1.0.0"
        assert (result / "Cargo.toml").exists()
        assert (result / "src" / "lib.rs").exists()

    def test_invalid_tarball(self, tmp_path):
        tarball = tmp_path / "bad.crate"
        tarball.write_bytes(b"this is not a tarball")
        dest = tmp_path / "extract"
        dest.mkdir()
        result = extract_crate(tarball, dest)
        assert result is None


# ---------------------------------------------------------------------------
# format_comment
# ---------------------------------------------------------------------------


class TestFormatComment:
    def _make_verdict(self, name, old, new, risk, summary="Test.", findings=None):
        change_type = "added" if old is None else "upgraded"
        change = Change(name, old, new, change_type)
        return Verdict(change, risk, summary, findings or [])

    def test_no_high_risk(self):
        verdicts = [self._make_verdict("serde", "1.0.0", "1.0.1", "none")]
        comment = format_comment(verdicts)
        assert "## Supply Chain Audit" in comment
        assert "No high-risk findings" in comment
        assert "`serde`" in comment

    def test_high_risk_expanded(self):
        verdicts = [
            self._make_verdict(
                "evil-crate",
                "1.0.0",
                "1.0.1",
                "critical",
                "Suspicious obfuscated code found.",
                [{"severity": "critical", "description": "Base64 payload", "evidence": "let x = decode(...)"}],
            )
        ]
        comment = format_comment(verdicts)
        assert "1** of **1" in comment
        assert "### " in comment  # expanded, not in <details>
        assert "Base64 payload" in comment

    def test_low_risk_collapsed(self):
        verdicts = [self._make_verdict("serde", "1.0.0", "1.0.1", "low")]
        comment = format_comment(verdicts)
        assert "<details>" in comment
        assert "</details>" in comment

    def test_new_dep_formatting(self):
        verdicts = [self._make_verdict("new-crate", None, "1.0.0", "none")]
        comment = format_comment(verdicts)
        assert "`1.0.0` (new)" in comment

    def test_sorted_by_risk(self):
        verdicts = [
            self._make_verdict("safe", "1.0.0", "1.0.1", "none"),
            self._make_verdict("danger", "1.0.0", "1.0.1", "critical"),
            self._make_verdict("maybe", "1.0.0", "1.0.1", "medium"),
        ]
        comment = format_comment(verdicts)
        # critical should appear before medium, which appears before none
        crit_pos = comment.index("danger")
        med_pos = comment.index("maybe")
        none_pos = comment.index("safe")
        assert crit_pos < med_pos < none_pos

    def test_truncation(self):
        # Create a verdict with a very long summary to trigger truncation
        long_summary = "x" * 70_000
        verdicts = [self._make_verdict("big", "1.0.0", "1.0.1", "low", long_summary)]
        comment = format_comment(verdicts)
        assert len(comment) <= audit.MAX_COMMENT_CHARS
        assert "truncated" in comment

    def test_multiple_findings(self):
        findings = [
            {"severity": "medium", "description": "Network call", "evidence": "reqwest::get(url)"},
            {"severity": "low", "description": "Env var read", "evidence": "std::env::var(\"KEY\")"},
        ]
        verdicts = [self._make_verdict("crate", "1.0.0", "1.0.1", "medium", "Suspicious.", findings)]
        comment = format_comment(verdicts)
        assert "Network call" in comment
        assert "Env var read" in comment

    def test_footer_present(self):
        verdicts = [self._make_verdict("serde", "1.0.0", "1.0.1", "none")]
        comment = format_comment(verdicts)
        assert "cargo-lock-supply-chain-claude" in comment


# ---------------------------------------------------------------------------
# call_claude (response parsing)
# ---------------------------------------------------------------------------


class TestCallClaudeResponseParsing:
    """Test the response parsing logic without making real API calls."""

    def test_strips_markdown_fences(self):
        raw = '```json\n{"risk": "none", "summary": "OK", "findings": []}\n```'
        text = raw.strip()
        if text.startswith("```"):
            text = re.sub(r"^```\w*\n?", "", text)
            text = re.sub(r"\n?```$", "", text)
            text = text.strip()
        result = json.loads(text)
        assert result["risk"] == "none"

    def test_plain_json(self):
        raw = '{"risk": "low", "summary": "Minor.", "findings": []}'
        result = json.loads(raw.strip())
        assert result["risk"] == "low"

    def test_fences_without_language(self):
        raw = '```\n{"risk": "medium", "summary": "Check.", "findings": []}\n```'
        text = raw.strip()
        if text.startswith("```"):
            text = re.sub(r"^```\w*\n?", "", text)
            text = re.sub(r"\n?```$", "", text)
            text = text.strip()
        result = json.loads(text)
        assert result["risk"] == "medium"
