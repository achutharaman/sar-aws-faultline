# Contributing

Thanks for looking. This project is small on purpose, so the most useful
contributions are usually **a well-scoped check** or **a correction to a
compliance mapping**.

## Setup

```bash
git clone https://github.com/achutharaman/sar-aws-faultline
cd sar-aws-faultline
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

pytest
ruff check . && ruff format --check .
```

No AWS credentials are needed, and none should be. Tests run against `moto`,
and `tests/conftest.py` injects fake credentials so a misconfigured test can
never reach a real account.

## Adding a check

Drop a file in `src/sar_aws_faultline/checks/`. Nothing else changes — the
registry discovers it, `iam-policy` picks up its permissions, and the renderers
handle it.

```python
@register
class UnencryptedRdsInstances:
    id = "rds-instance-unencrypted"
    title = "RDS instances without encryption at rest"
    service = "rds"
    resource_type = "AWS::RDS::DBInstance"
    scope = Scope.REGIONAL
    severity = Severity.HIGH
    audit_impact = AuditImpact.BLOCKER
    rationale = "..."  # plain language, for a founder
    remediation = Remediation(...)
    required_actions = frozenset({"rds:DescribeDBInstances"})

    def run(self, ctx: ScanContext) -> Iterator[Finding]: ...
```

Then regenerate the policy:

```bash
python scripts/generate_iam_policy.py
```

CI diffs `docs/iam-policy.json`, so forgetting this fails the build. That is
deliberate: the README's IAM policy must never advertise permissions the code
does not use, or omit ones it does.

### What the registry enforces at import time

`register()` rejects a check that is missing metadata, uses the wrong enum
type, passes a `set` where a `frozenset` is required, declares a malformed IAM
action, or ships a stub `rationale` under 80 characters. A malformed check
fails the test suite immediately rather than at 3am during someone's scan.

### Bar for a new check

This project competes on curation, not coverage. A check earns its place if:

1. **It is actionable.** The reader can fix it, and `Remediation` says exactly
   how, how long it takes, and what it costs per month. A finding nobody can
   act on is just anxiety.
2. **It is low-noise.** If it will fire on accounts that are actually fine, it
   needs narrowing first. False positives are the specific failure mode this
   tool exists to avoid — one bad check costs more trust than five good ones
   earn.
3. **It matters to the audience.** Small teams facing SOC 2 for the first time.
   Not multi-account estates, not exotic services.
4. **It fits the time budget.** Full scans target under 60 seconds. A check
   needing per-resource calls across thousands of resources needs a plan.

If a check does not clear that bar, the honest answer is that Prowler already
has it. Say so and move on.

### Severity vs audit impact

These are different questions and must be set independently. Missing CloudTrail
is `MEDIUM` severity and a `BLOCKER` for audit. A permissive security group on
an isolated dev VPC is `HIGH` severity and closer to `HARDENING`. If you find
yourself setting both to the same intensity every time, one of them is wrong.

### Cost estimates

`monthly_cost_usd` should be an honest order of magnitude for a small account,
with the assumption stated in `cost_note`. A wrong number is worse than a
missing one; `0.0` for a free control is a real answer, not a placeholder.

## Tests

Every check needs both:

- **Pure logic tests** over the decision function, covering the state space.
  Keep the verdict logic in a module-level function taking a plain dataclass so
  it can be tested without AWS or moto. See `exposure_paths` in
  `checks/s3_public_access.py`.
- **A moto test** for `run()`, covering the boto3 wiring only.

The split matters. Detection logic is where correctness lives, and it should be
testable without a mocking layer standing between the test and the assertion.

## Compliance mappings

Mappings live in `src/sar_aws_faultline/data/mappings/`. To add one:

```toml
[[mappings]]
check = "rds-instance-unencrypted"

  [[mappings.controls]]
  framework = "cis-aws"
  control = "2.3.1"
  relationship = "supports"
  rationale = """At least fifteen words explaining why this check bears on
  this control."""
```

Rules, enforced by `tests/test_compliance.py`:

- Every check must be mapped. An unmapped check vanishes from `--framework`.
- Every control must exist in its framework's catalogue.
- Mappings into an **interpretive** framework (SOC 2 TSC) must set
  `derived_from` naming an objective control, so a reader can audit the
  inference.
- `partially_supports` rationales must say the word "partial" and explain the
  limit. Claiming partial support without naming the gap implies coverage the
  check does not provide.
- **Never add a `satisfies` relationship.** A configuration scanner cannot
  establish that a control is met. A test asserts the enum stays at two members.
- **Never paste licensed text.** AICPA TSC and CIS benchmark text are both
  copyrighted. Identifiers and short paraphrases only.

## Things that will be declined

- **Remediation or any write path.** See the README. The read-only guarantee is
  structural and load-bearing.
- **Multi-cloud.** Prowler does this well; there is no reason to do it badly.
- **Check-count padding.** Checks that almost always pass, or that duplicate an
  AWS default, make the output worse.
- **A shared `sar-aws-common` package.** Duplication across the `sar-` repos is
  intentional and currently cheaper than the coupling.

## Reporting a security issue

Please do not open a public issue. Email the maintainer via the address on the
GitHub profile.
