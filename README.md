# cargo-lock-supply-chain-claude

A GitHub Action that audits Cargo.lock dependency changes for supply chain attacks using Claude.

When a PR modifies `Cargo.lock`, this action:

1. Diffs the lockfile to find every added, upgraded, or downgraded registry dependency
2. Downloads the old and new `.crate` tarballs from crates.io
3. Extracts and diffs the actual source code between versions
4. Sends each diff to Claude for security analysis
5. Posts a single PR comment with per-dependency risk verdicts

## What it detects

- `build.rs` backdoors that download or execute external code at build time
- Obfuscated code (base64, XOR, hex encoding, string reversal)
- Network calls to suspicious domains in non-networking crates
- File system writes to credential locations (~/.ssh, ~/.aws, browser profiles)
- Unexpected new dependencies injected within a crate's Cargo.toml
- Binary blobs or encoded payloads
- Environment variable harvesting for secrets/tokens
- `std::process::Command` usage for shell execution
- CI-conditional behavior (code that runs differently in CI vs local)
- System information exfiltration

## Usage

Add this workflow to your repository at `.github/workflows/supply-chain-audit.yml`:

```yaml
name: Supply Chain Audit

on:
  pull_request:
    paths:
      - "Cargo.lock"

permissions:
  contents: read
  pull-requests: write

jobs:
  audit:
    name: Audit dependency changes
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: originsec/cargo-lock-supply-chain-claude@main
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `anthropic_api_key` | Yes | - | Anthropic API key for Claude |
| `model` | No | `claude-sonnet-4-20250514` | Claude model to use |
| `base_ref` | No | Auto-detected from PR | Git ref to diff against |

### Secrets

Add `ANTHROPIC_API_KEY` to your repository secrets (Settings > Secrets and variables > Actions).

## PR comment output

The action posts a comment like:

> ## Supply Chain Audit
>
> Analyzed **3** dependency changes. No high-risk findings.
>
> <details><summary>:white_check_mark: <b><code>serde</code></b> <code>1.0.200</code> -> <code>1.0.201</code> -- <b>none</b></summary>
> Routine patch release with minor bug fixes.
> </details>

High/critical findings are shown expanded with detailed evidence.

## Suppression

Add `[supply-chain-audit-ok]` to your PR description to skip the audit for a specific PR.

## How it works

The script downloads `.crate` tarballs directly from crates.io's CDN (`static.crates.io`), extracts them, and performs a local file-by-file diff using Python's `difflib`. This is more reliable than trying to find and clone git repositories, since:

- Every published crate version has a tarball on crates.io
- The tarball contains exactly what was published (no git history noise)
- No need to guess tag naming conventions across thousands of repos

The diff is then sent to Claude with a system prompt tuned for supply chain attack indicators, based on real-world attacks like the [axios npm supply chain attack](https://unit42.paloaltonetworks.com/axios-supply-chain-attack/).

## Requirements

- Python 3.10+ (available on `ubuntu-latest` runners)
- `fetch-depth: 0` on checkout (needed to diff against the base branch)

## License

Prelude Research License — see [LICENSE](LICENSE) for details.
