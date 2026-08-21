# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Note that **check ids and exit codes are public API**. Renaming a check or
changing an exit code is a breaking change, because both appear in other
people's CI pipelines.

## [Unreleased]

## [0.1.0] - 2026-08-21

Initial scaffolding.

### Added
- Check registry with automatic discovery and a `sar_aws_faultline.checks`
  entry-point group for third-party checks.
- Two-axis finding model: security `Severity` plus `AuditImpact`
  (`blocker` / `expected` / `hardening`), ordered by audit impact first.
- `Remediation` on every check: console steps, CLI commands, effort estimate,
  monthly cost of the fix, and caveats.
- Threaded runner over (check, region) units; a failing check is recorded as a
  `CheckError` and the scan continues.
- Structural read-only guarantee via a botocore `before-call` guard.
- Compliance mapping in TOML, with objective (CIS) and interpretive (SOC 2 TSC)
  hops tracked separately. No relationship stronger than `partially_supports`.
- Output formats: `table`, `json`, `markdown`.
- `scan`, `checks`, `frameworks` and `iam-policy` commands.
- Least-privilege IAM policy generated from the registry and diffed in CI.
- Configuration via `sar-aws-faultline.toml`, `SAR_AWS_FAULTLINE_*`, and flags.
- First check: `s3-bucket-public-access`.

[Unreleased]: https://github.com/achutharaman/sar-aws-faultline/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/achutharaman/sar-aws-faultline/releases/tag/v0.1.0
