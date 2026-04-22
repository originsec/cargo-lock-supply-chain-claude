"""Audit changed Cargo.lock dependencies for supply chain attacks.

Downloads old and new crate tarballs from crates.io, diffs them locally,
and feeds each diff to Claude for security analysis. Outputs a Markdown
PR comment to stdout.

Usage:
    python3 scripts/audit-supply-chain.py [base-ref]

base-ref defaults to origin/main.
Requires ANTHROPIC_API_KEY in the environment.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CRATES_IO_CDN = "https://static.crates.io/crates"
CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-sonnet-4-20250514"
ANTHROPIC_API_VERSION = "2023-06-01"
USER_AGENT = "cargo-lock-supply-chain-audit/1.0 (github.com/originsec/cargo-lock-supply-chain-claude)"
CRATE_DOWNLOAD_DELAY = 0.25  # courtesy delay between crate.io downloads (seconds)
MAX_COMMENT_CHARS = 60_000  # GitHub comment limit is 65536; leave headroom
# Cap the diff payload sent to Claude to fit within Sonnet's 200k-token input.
MAX_DIFF_CHARS = 150_000
SUPPRESS_MARKER = "[supply-chain-audit-ok]"

SYSTEM_PROMPT = """\
You are a supply chain security auditor for Rust crates published on crates.io. \
You analyze diffs between versions of crate dependencies to detect signs of supply \
chain attacks, malicious code injection, or suspicious changes.

Evaluate the diff and produce a JSON verdict with these fields:
- "risk": one of "none", "low", "medium", "high", "critical"
- "summary": a 1-2 sentence summary of your findings
- "findings": an array of objects, each with:
    - "severity": "low", "medium", "high", or "critical"
    - "description": what you found and why it is suspicious
    - "evidence": the relevant code snippet, file path, or pattern

Signals to look for (non-exhaustive):
1. build.rs changes that download or execute external code, or access the network at build time
2. Proc macro crates that run arbitrary code at compile time with side effects (network, FS, env)
3. Obfuscated code: base64 decoding, XOR operations, hex-encoded strings, string reversal, \
   character-by-character string building, unusual encoding schemes, or intentionally confusing \
   variable names hiding malicious logic
4. Network calls to unfamiliar or suspicious domains, especially in non-networking crates
5. File system access outside the crate's own directory, especially writes to well-known \
   credential locations (~/.ssh, ~/.aws, ~/.gnupg, ~/.config, browser profile directories, \
   keychain/credential stores)
6. New unexpected dependencies added in Cargo.toml (dependency injection within the crate itself)
7. Binary blobs, encoded payloads, or large opaque data literals that could contain executables
8. Environment variable reading for sensitive values (API keys, tokens, credentials, SSH keys)
9. Use of std::process::Command or similar to execute shell commands, especially with \
   dynamically constructed command strings
10. Changes that look like dependency confusion (name squatting, typosquatting)
11. Conditional logic that behaves differently in CI environments vs local builds \
    (checking CI, GITHUB_ACTIONS, TRAVIS, JENKINS, etc.)
12. Code that collects and exfiltrates system information (hostname, username, IP, \
    installed software, running processes)
13. Postinstall-style hooks: any mechanism that runs code automatically on install/build \
    without the user's explicit knowledge
14. Significant functionality changes that don't match the crate's stated purpose \
    (e.g., a JSON parser suddenly including HTTP client code)
15. Removal or weakening of security checks, cryptographic operations, or input validation

For "none" risk: the changes look routine (version bumps, docs, bug fixes, new features \
consistent with the crate's purpose).
For "low" risk: minor concerns worth noting but likely benign.
For "medium" risk: unusual patterns that warrant manual review.
For "high" risk: strong indicators of potentially malicious behavior.
For "critical" risk: clear evidence of malicious code or supply chain attack techniques.

Respond ONLY with the JSON object. No markdown fences, no commentary.\
"""

# ---------------------------------------------------------------------------
# Cargo.lock parsing
# ---------------------------------------------------------------------------


def parse_lockfile(text: str) -> dict[str, dict[str, str | None]]:
    """Parse a Cargo.lock into {name: {version: checksum}} for registry packages.

    Uses tomllib for correct TOML parsing. Only includes packages sourced from
    a registry (path and git dependencies are excluded).
    """
    if not text.strip():
        return {}

    data = tomllib.loads(text)
    packages: dict[str, dict[str, str | None]] = {}

    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        source = pkg.get("source", "")
        if not name or not version:
            continue
        # Only include registry deps (path deps have no source, git deps use git+)
        if "registry" not in source:
            continue
        checksum = pkg.get("checksum")
        packages.setdefault(name, {})[version] = checksum

    return packages


def parse_semver(v: str) -> tuple[int, int, int]:
    """Parse a version string into a comparable (major, minor, patch) tuple."""
    parts = re.match(r"(\d+)\.(\d+)\.(\d+)", v)
    if not parts:
        return (0, 0, 0)
    return (int(parts.group(1)), int(parts.group(2)), int(parts.group(3)))


# ---------------------------------------------------------------------------
# Change detection
# ---------------------------------------------------------------------------

LOCKFILE_RE = re.compile(r"(?:^|/)Cargo\.lock$")


def discover_changed_lockfiles(base_ref: str) -> list[str]:
    """Return every Cargo.lock path (root or nested) changed since base_ref."""
    try:
        output = subprocess.check_output(
            ["git", "diff", "--name-only", f"{base_ref}...HEAD"],
            text=True,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as e:
        print(
            f"::warning::git diff against {base_ref} failed: {e.stderr.strip()}",
            file=sys.stderr,
        )
        return []
    return [line for line in output.splitlines() if LOCKFILE_RE.search(line)]


@dataclass
class Change:
    name: str
    old_version: str | None
    new_version: str | None
    change_type: str  # "added", "upgraded", "downgraded"
    old_checksum: str | None = None
    new_checksum: str | None = None


def compute_changes(
    base_pkgs: dict[str, dict[str, str | None]],
    head_pkgs: dict[str, dict[str, str | None]],
) -> list[Change]:
    """Compute the list of dependency changes between base and head."""
    changes: list[Change] = []
    all_names = set(base_pkgs) | set(head_pkgs)

    for name in sorted(all_names):
        base_versions = set(base_pkgs.get(name, {}).keys())
        head_versions = set(head_pkgs.get(name, {}).keys())

        if base_versions == head_versions:
            continue

        # Skip removed deps entirely — no supply chain risk
        if name not in head_pkgs:
            continue

        removed = base_versions - head_versions
        added = head_versions - base_versions

        if name not in base_pkgs:
            # Entirely new dependency
            for ver in sorted(added, key=parse_semver):
                changes.append(
                    Change(
                        name=name,
                        old_version=None,
                        new_version=ver,
                        change_type="added",
                        new_checksum=head_pkgs[name].get(ver),
                    )
                )
        else:
            # Version changed — pair up removed/added versions
            removed_sorted = sorted(removed, key=parse_semver)
            added_sorted = sorted(added, key=parse_semver)

            if len(removed_sorted) == 1 and len(added_sorted) == 1:
                old_v = removed_sorted[0]
                new_v = added_sorted[0]
                change_type = (
                    "downgraded"
                    if parse_semver(new_v) < parse_semver(old_v)
                    else "upgraded"
                )
                changes.append(
                    Change(
                        name=name,
                        old_version=old_v,
                        new_version=new_v,
                        change_type=change_type,
                        old_checksum=base_pkgs[name].get(old_v),
                        new_checksum=head_pkgs[name].get(new_v),
                    )
                )
            else:
                # Multiple version changes — pair by position, extras are adds
                for old_v in removed_sorted:
                    if added_sorted:
                        new_v = added_sorted.pop(0)
                        change_type = (
                            "downgraded"
                            if parse_semver(new_v) < parse_semver(old_v)
                            else "upgraded"
                        )
                        changes.append(
                            Change(
                                name=name,
                                old_version=old_v,
                                new_version=new_v,
                                change_type=change_type,
                                old_checksum=base_pkgs[name].get(old_v),
                                new_checksum=head_pkgs[name].get(new_v),
                            )
                        )
                for new_v in added_sorted:
                    changes.append(
                        Change(
                            name=name,
                            old_version=None,
                            new_version=new_v,
                            change_type="added",
                            new_checksum=head_pkgs[name].get(new_v),
                        )
                    )

    return changes


# ---------------------------------------------------------------------------
# Crate downloading and extraction
# ---------------------------------------------------------------------------


def download_crate(name: str, version: str, dest_dir: Path) -> Path | None:
    """Download a .crate tarball from crates.io. Returns path or None on failure."""
    url = f"{CRATES_IO_CDN}/{name}/{name}-{version}.crate"
    dest = dest_dir / f"{name}-{version}.crate"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            dest.write_bytes(resp.read())
        return dest
    except (urllib.error.URLError, OSError) as e:
        print(f"::warning::Failed to download {name}-{version}: {e}", file=sys.stderr)
        return None


def extract_crate(tarball: Path, dest_dir: Path) -> Path | None:
    """Extract a .crate tarball. Returns the extracted directory path."""
    try:
        with tarfile.open(tarball, "r:gz") as tf:
            # Use data_filter for path traversal safety (Python 3.12+)
            if hasattr(tarfile, "data_filter"):
                tf.extractall(dest_dir, filter="data")
            else:
                # Fallback: manual safety check
                for member in tf.getmembers():
                    resolved = (dest_dir / member.name).resolve()
                    if not str(resolved).startswith(str(dest_dir.resolve())):
                        print(
                            f"::warning::Path traversal in {tarball.name}: {member.name}",
                            file=sys.stderr,
                        )
                        return None
                tf.extractall(dest_dir)

        # The tarball extracts to {name}-{version}/
        extracted = list(dest_dir.iterdir())
        # Find the directory (not the tarball itself)
        for item in extracted:
            if item.is_dir():
                return item
        return None
    except (tarfile.TarError, OSError) as e:
        print(f"::warning::Failed to extract {tarball.name}: {e}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Diffing
# ---------------------------------------------------------------------------


def is_binary(path: Path) -> bool:
    """Heuristic: file is binary if first 8KB contains null bytes."""
    try:
        chunk = path.read_bytes()[:8192]
        return b"\x00" in chunk
    except OSError:
        return True


def collect_files(directory: Path) -> dict[str, Path]:
    """Collect all files in a directory as {relative_path: absolute_path}."""
    files = {}
    if directory is None:
        return files
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            rel = str(path.relative_to(directory)).replace("\\", "/")
            files[rel] = path
    return files


def diff_crates(old_dir: Path | None, new_dir: Path) -> str:
    """Produce a unified diff between two extracted crate directories."""
    old_files = collect_files(old_dir) if old_dir else {}
    new_files = collect_files(new_dir)

    all_paths = sorted(set(old_files) | set(new_files))
    diff_parts: list[str] = []

    for rel_path in all_paths:
        old_path = old_files.get(rel_path)
        new_path = new_files.get(rel_path)

        if old_path and new_path:
            # Both exist — diff them
            if is_binary(old_path) or is_binary(new_path):
                old_size = old_path.stat().st_size
                new_size = new_path.stat().st_size
                if old_size != new_size:
                    diff_parts.append(
                        f"Binary file {rel_path} changed ({old_size} -> {new_size} bytes)\n"
                    )
                continue
            try:
                old_lines = old_path.read_text(errors="replace").splitlines(keepends=True)
                new_lines = new_path.read_text(errors="replace").splitlines(keepends=True)
            except OSError:
                continue
            diff = difflib.unified_diff(
                old_lines, new_lines, fromfile=f"a/{rel_path}", tofile=f"b/{rel_path}"
            )
            diff_text = "".join(diff)
            if diff_text:
                diff_parts.append(diff_text)

        elif new_path:
            # New file
            if is_binary(new_path):
                size = new_path.stat().st_size
                diff_parts.append(f"Binary file {rel_path} added ({size} bytes)\n")
                continue
            try:
                lines = new_path.read_text(errors="replace").splitlines(keepends=True)
            except OSError:
                continue
            diff = difflib.unified_diff(
                [], lines, fromfile="/dev/null", tofile=f"b/{rel_path}"
            )
            diff_parts.append("".join(diff))

        elif old_path:
            # Deleted file
            if is_binary(old_path):
                size = old_path.stat().st_size
                diff_parts.append(f"Binary file {rel_path} removed ({size} bytes)\n")
                continue
            try:
                lines = old_path.read_text(errors="replace").splitlines(keepends=True)
            except OSError:
                continue
            diff = difflib.unified_diff(
                lines, [], fromfile=f"a/{rel_path}", tofile="/dev/null"
            )
            diff_parts.append("".join(diff))

    return "\n".join(diff_parts)


# ---------------------------------------------------------------------------
# Claude API
# ---------------------------------------------------------------------------


def _truncate_diff(diff_text: str) -> tuple[str, bool]:
    """Cap diff_text at MAX_DIFF_CHARS; return (maybe-truncated-text, was_truncated)."""
    if len(diff_text) <= MAX_DIFF_CHARS:
        return diff_text, False
    omitted = len(diff_text) - MAX_DIFF_CHARS
    truncated = diff_text[:MAX_DIFF_CHARS] + (
        f"\n\n... (diff truncated: {omitted} characters omitted to fit within "
        f"Claude's context window; audit only reflects the leading "
        f"{MAX_DIFF_CHARS} characters)\n"
    )
    return truncated, True


def parse_verdict_text(text: str) -> dict:
    """Extract the JSON verdict from Claude's response text.

    Tolerates three forms of decoration around the JSON object:
      - markdown fences (```json ... ```),
      - leading prose before the `{`,
      - trailing commentary after the `}`.
    Raises json.JSONDecodeError if no valid JSON object can be located.
    """
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```\w*\n?", "", text)
        text = re.sub(r"\n?```$", "", text)
        text = text.strip()

    decoder = json.JSONDecoder()
    # Try each `{` as a potential start. raw_decode ignores trailing junk, so
    # we just need to find a start offset that yields a valid object.
    last_err: json.JSONDecodeError | None = None
    for start in range(len(text)):
        if text[start] != "{":
            continue
        try:
            parsed, _ = decoder.raw_decode(text, start)
            return parsed
        except json.JSONDecodeError as e:
            last_err = e
            continue

    raise last_err or json.JSONDecodeError("No JSON object found", text, 0)


def call_claude(
    name: str,
    old_version: str | None,
    new_version: str,
    change_type: str,
    diff_text: str,
    api_key: str,
    model: str,
) -> dict:
    """Call Claude to audit a crate diff. Returns the parsed verdict dict."""
    diff_text, was_truncated = _truncate_diff(diff_text)
    truncation_note = (
        "\n\nNote: the diff exceeded the size limit and was truncated. "
        "Reflect this uncertainty in your verdict — do not claim confidence "
        "about un-inspected regions.\n"
        if was_truncated
        else ""
    )
    if change_type == "added":
        user_msg = (
            f'Analyze the following contents for the newly added Rust crate dependency "{name}" '
            f"version {new_version}.\n\n"
            f"This is a new dependency being added to the project. All file contents are shown "
            f"as additions. Pay special attention to whether this crate's purpose matches its "
            f"stated description and whether it contains any suspicious functionality.{truncation_note}\n\n"
            f"<diff>\n{diff_text}\n</diff>"
        )
    else:
        user_msg = (
            f'Analyze the following diff for the Rust crate "{name}" '
            f"({change_type} from {old_version} to {new_version}).\n\n"
            f"The diff shows all file changes between the old and new versions of this crate "
            f"as published on crates.io.{truncation_note}\n\n"
            f"<diff>\n{diff_text}\n</diff>"
        )

    body = json.dumps(
        {
            "model": model,
            "max_tokens": 4096,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user_msg}],
        }
    ).encode()

    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": api_key,
        "Anthropic-Version": ANTHROPIC_API_VERSION,
        "User-Agent": USER_AGENT,
    }

    req = urllib.request.Request(CLAUDE_API_URL, data=body, headers=headers, method="POST")

    last_err = None
    for attempt in range(2):
        if attempt > 0:
            time.sleep(5)
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                result = json.loads(resp.read())
            # Extract text from the response
            text = ""
            for block in result.get("content", []):
                if block.get("type") == "text":
                    text += block["text"]
            return parse_verdict_text(text)
        except json.JSONDecodeError as e:
            last_err = f"Invalid JSON from Claude: {e}\nRaw response: {text[:500]}"
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                body = "<unreadable>"
            last_err = f"API request failed: {e} — {body[:500]}"
        except (urllib.error.URLError, OSError) as e:
            last_err = f"API request failed: {e}"

    # All retries exhausted
    return {
        "risk": "high",
        "summary": f"Audit failed — manual review required. Error: {last_err}",
        "findings": [],
    }


# ---------------------------------------------------------------------------
# Comment formatting
# ---------------------------------------------------------------------------

RISK_EMOJI = {
    "none": "\u2705",     # green checkmark
    "low": "\u2705",      # green checkmark
    "medium": "\u26a0\ufe0f",   # warning
    "high": "\U0001f534",       # red circle
    "critical": "\U0001f534",   # red circle
}

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}


@dataclass
class Verdict:
    change: Change
    risk: str
    summary: str
    findings: list[dict]
    error: str | None = None


def format_comment(verdicts: list[Verdict]) -> str:
    """Format all verdicts into a single Markdown PR comment."""
    # Sort by risk level (critical first)
    verdicts.sort(key=lambda v: RISK_ORDER.get(v.risk, 5))

    high_risk_count = sum(1 for v in verdicts if v.risk in ("high", "critical"))
    total = len(verdicts)

    lines: list[str] = []
    lines.append("## Supply Chain Audit - Cargo\n")

    if high_risk_count > 0:
        lines.append(
            f"> **{high_risk_count}** of **{total}** dependency changes flagged "
            f"as high/critical risk.\n"
        )
    else:
        lines.append(
            f"> Analyzed **{total}** dependency changes. No high-risk findings.\n"
        )

    for v in verdicts:
        emoji = RISK_EMOJI.get(v.risk, "\u2753")
        change = v.change
        if change.old_version:
            version_str = f"`{change.old_version}` \u2192 `{change.new_version}`"
        else:
            version_str = f"`{change.new_version}` (new)"

        header = f"{emoji} **`{change.name}`** {version_str} \u2014 **{v.risk}**"

        if v.risk in ("high", "critical"):
            # Show expanded
            lines.append(f"### {header}\n")
            lines.append(f"{v.summary}\n")
            if v.findings:
                for f in v.findings:
                    sev = f.get("severity", "?")
                    desc = f.get("description", "")
                    evidence = f.get("evidence", "")
                    lines.append(f"- **[{sev}]** {desc}")
                    if evidence:
                        lines.append(f"  ```\n  {evidence}\n  ```")
                lines.append("")
        else:
            # Show collapsed
            lines.append(f"<details>\n<summary>{header}</summary>\n")
            lines.append(f"{v.summary}\n")
            if v.findings:
                for f in v.findings:
                    sev = f.get("severity", "?")
                    desc = f.get("description", "")
                    evidence = f.get("evidence", "")
                    lines.append(f"- **[{sev}]** {desc}")
                    if evidence:
                        lines.append(f"  ```\n  {evidence}\n  ```")
            lines.append("\n</details>\n")

    lines.append("---")
    lines.append(
        f"*Audit performed by Claude (`{os.environ.get('AUDIT_MODEL', DEFAULT_MODEL)}`) "
        f"via [cargo-lock-supply-chain-claude]"
        f"(https://github.com/originsec/cargo-lock-supply-chain-claude)*"
    )

    comment = "\n".join(lines)

    # Truncate if too long for GitHub
    if len(comment) > MAX_COMMENT_CHARS:
        truncation_note = (
            "\n\n> **Note:** This comment was truncated due to GitHub's size limit. "
            "See CI logs for the full audit output.\n"
        )
        comment = comment[: MAX_COMMENT_CHARS - len(truncation_note)] + truncation_note

    return comment


# ---------------------------------------------------------------------------
# Verdict cache
# ---------------------------------------------------------------------------
#
# Cargo.lock records a content hash (checksum) for every registry dep, so
# a (name, old_checksum, new_checksum) triple is a truly immutable identity
# for a given audit: crates.io does not republish a version under the same
# hash. Cache entries keyed this way can be safely shared across repos.

CACHE_VERSION = 1


def cache_key(name: str, old_id: str | None, new_id: str | None) -> str:
    return f"{name}|{old_id or ''}|{new_id or ''}"


def load_verdict_cache(path: str | None) -> dict[str, dict]:
    if not path:
        return {}
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict) or data.get("version") != CACHE_VERSION:
        return {}
    entries = data.get("entries", {})
    return entries if isinstance(entries, dict) else {}


def save_verdict_cache(path: str | None, cache: dict[str, dict]) -> None:
    if not path:
        return
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump({"version": CACHE_VERSION, "entries": cache}, f)
    except OSError as e:
        print(f"::warning::Failed to save verdict cache: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    base_ref = sys.argv[1] if len(sys.argv) > 1 else "origin/main"

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("::error::ANTHROPIC_API_KEY not set", file=sys.stderr)
        return 1

    model = os.environ.get("AUDIT_MODEL", DEFAULT_MODEL)

    # Check for suppression marker in PR body
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path:
        try:
            with open(event_path) as f:
                event = json.load(f)
            pr_body = event.get("pull_request", {}).get("body") or ""
            if SUPPRESS_MARKER in pr_body:
                print(
                    f"Supply chain audit suppressed via '{SUPPRESS_MARKER}' in PR body.",
                    file=sys.stderr,
                )
                return 0
        except (OSError, json.JSONDecodeError):
            pass

    lockfiles = discover_changed_lockfiles(base_ref)
    if not lockfiles:
        print("No Cargo.lock changes detected.", file=sys.stderr)
        return 0

    print(
        f"Auditing {len(lockfiles)} changed Cargo.lock file(s): {', '.join(lockfiles)}",
        file=sys.stderr,
    )

    # Merge changes across all lockfiles, deduping by (name, old_version, new_version).
    # A monorepo may have the same crate upgrade in multiple lockfiles — the source
    # diff is identical, so auditing once is sufficient.
    merged: dict[tuple[str, str | None, str | None], Change] = {}
    for lockfile in lockfiles:
        try:
            base_text = subprocess.check_output(
                ["git", "show", f"{base_ref}:{lockfile}"],
                text=True,
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError:
            print(
                f"::warning::Could not read {lockfile} from {base_ref}, "
                f"treating all deps as new.",
                file=sys.stderr,
            )
            base_text = ""

        try:
            with open(lockfile) as f:
                head_text = f.read()
        except OSError as e:
            print(f"::warning::Could not read {lockfile}: {e}", file=sys.stderr)
            continue

        base_pkgs = parse_lockfile(base_text)
        head_pkgs = parse_lockfile(head_text)
        for change in compute_changes(base_pkgs, head_pkgs):
            merged.setdefault(
                (change.name, change.old_version, change.new_version), change
            )

    changes = sorted(merged.values(), key=lambda c: c.name)

    if not changes:
        print("No registry dependency changes detected.", file=sys.stderr)
        return 0

    print(
        f"Found {len(changes)} unique dependency change(s) to audit.",
        file=sys.stderr,
    )

    cache_path = os.environ.get("AUDIT_CACHE_FILE")
    cache = load_verdict_cache(cache_path)
    cache_hits = 0

    verdicts: list[Verdict] = []

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        for i, change in enumerate(changes):
            print(
                f"[{i+1}/{len(changes)}] Auditing {change.name} "
                f"({change.old_version} -> {change.new_version})...",
                file=sys.stderr,
            )

            # Cache lookup before any network I/O or Claude call.
            key = cache_key(change.name, change.old_checksum, change.new_checksum)
            if key in cache:
                entry = cache[key]
                verdicts.append(
                    Verdict(
                        change=change,
                        risk=entry.get("risk", "medium"),
                        summary=entry.get("summary", ""),
                        findings=entry.get("findings", []),
                    )
                )
                cache_hits += 1
                print(f"  cache hit ({key})", file=sys.stderr)
                continue

            # Download and extract new version
            new_tarball = download_crate(change.name, change.new_version, tmp)
            if not new_tarball:
                verdicts.append(
                    Verdict(
                        change=change,
                        risk="high",
                        summary=f"Could not download {change.name}-{change.new_version}.crate "
                        f"from crates.io. Manual review required.",
                        findings=[],
                        error="download_failed",
                    )
                )
                continue

            new_extract_dir = tmp / f"new-{change.name}-{change.new_version}"
            new_extract_dir.mkdir()
            new_dir = extract_crate(new_tarball, new_extract_dir)
            if not new_dir:
                verdicts.append(
                    Verdict(
                        change=change,
                        risk="high",
                        summary=f"Could not extract {change.name}-{change.new_version}.crate. "
                        f"Manual review required.",
                        findings=[],
                        error="extract_failed",
                    )
                )
                continue

            # Download and extract old version (if upgrading/downgrading)
            old_dir = None
            if change.old_version:
                if CRATE_DOWNLOAD_DELAY > 0:
                    time.sleep(CRATE_DOWNLOAD_DELAY)
                old_tarball = download_crate(change.name, change.old_version, tmp)
                if old_tarball:
                    old_extract_dir = tmp / f"old-{change.name}-{change.old_version}"
                    old_extract_dir.mkdir()
                    old_dir = extract_crate(old_tarball, old_extract_dir)

            if CRATE_DOWNLOAD_DELAY > 0:
                time.sleep(CRATE_DOWNLOAD_DELAY)

            # Diff
            diff_text = diff_crates(old_dir, new_dir)
            if not diff_text.strip():
                # No actual source changes (maybe only checksum changed)
                entry = {
                    "risk": "none",
                    "summary": "No source changes detected between versions.",
                    "findings": [],
                }
                cache[key] = entry
                verdicts.append(Verdict(change=change, **entry))
                continue

            # Call Claude
            verdict_data = call_claude(
                name=change.name,
                old_version=change.old_version,
                new_version=change.new_version,
                change_type=change.change_type,
                diff_text=diff_text,
                api_key=api_key,
                model=model,
            )

            entry = {
                "risk": verdict_data.get("risk", "medium"),
                "summary": verdict_data.get("summary", "No summary provided."),
                "findings": verdict_data.get("findings", []),
            }
            # Only cache successful Claude verdicts — transient errors (network
            # failures, rate limits) should re-try on the next run rather than
            # pinning "high — audit failed" forever.
            if "Audit failed" not in entry["summary"]:
                cache[key] = entry
            verdicts.append(Verdict(change=change, **entry))

    save_verdict_cache(cache_path, cache)
    if cache_path:
        print(
            f"Verdict cache: {cache_hits}/{len(changes)} hits; "
            f"{len(cache)} total entries stored.",
            file=sys.stderr,
        )

    # Format and output the comment
    comment = format_comment(verdicts)
    print(comment)

    # Exit with non-zero if any critical findings
    has_critical = any(v.risk == "critical" for v in verdicts)
    return 1 if has_critical else 0


if __name__ == "__main__":
    sys.exit(main())
