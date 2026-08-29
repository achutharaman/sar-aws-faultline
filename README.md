# sar-aws-faultline

**Find the security gaps in your AWS account, ranked by what to fix first.**

Read-only. Never changes anything.

```bash
pipx install sar-aws-faultline
sar-aws-faultline scan --all-regions
```

---

## The problem

You are three people. A prospect just sent a security questionnaire, or an
investor asked when you will have SOC 2. You know your AWS account has
problems. You do not know which ones matter, which ones an auditor will
actually stop at, or which fixes will show up on next month's bill.

So you run a scanner. It produces four hundred findings, sorted by severity,
in vocabulary written for people who already know the answer. You scroll for
ten minutes, close the tab, and nothing changes.

This tool takes the opposite bet: **a small number of checks, ordered by what
to fix first, each with the steps to fix it, how long it takes, and what it
costs per month.**

## What makes it different

Every finding carries two axes, not one:

- **Severity** — how bad this is if someone exploits it.
- **Audit impact** — `blocker`, `expected` or `hardening`. What it costs you
  in a SOC 2 readiness conversation.

These do not correlate, and collapsing them is why generic scanner output
needs triage before it is useful. A missing CloudTrail trail is medium
severity — nothing is exposed — but it is an absolute audit blocker, because
without it you cannot evidence any monitoring control at all. A permissive
security group on an isolated dev VPC is the reverse.

Findings are ordered by audit impact first. That ordering is the product.

And every fix carries its price:

| Finding | Severity | Audit impact | Effort | Cost of fixing |
|---|---|---|---|---|
| Publicly accessible S3 bucket | critical | blocker | minutes | $0 |
| No active multi-region CloudTrail trail | medium | blocker | minutes | $2 |
| GuardDuty is not enabled | medium | expected | minutes | $5 |
| No active AWS Config recorder | medium | blocker | minutes | $3 |

GuardDuty, a Config recorder and VPC flow logs all carry a real monthly bill.
A three-person team deciding whether to turn them on needs that number in the
same table as the red X.

## Sample output

Every check that ran gets a row — clean, not just the ones with a finding —
so you can tell "checked, found nothing" apart from "never looked":

```
sar-aws-faultline — account 123456789012

Checks run
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ Check                            ┃ Status    ┃ Detail       ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ aws-config-not-enabled           │ ok        │ clean        │
│ cloudtrail-not-enabled           │ ok        │ clean        │
│ ebs-snapshot-public              │ ok        │ clean        │
│ ebs-volume-unencrypted           │ ok        │ clean        │
│ guardduty-not-enabled            │ issue     │ 1 finding(s) │
│ iam-access-key-stale             │ ok        │ clean        │
│ iam-password-policy-weak         │ ok        │ clean        │
│ iam-root-account-no-mfa          │ ok        │ clean        │
│ iam-user-no-mfa                  │ ok        │ clean        │
│ kms-key-rotation-disabled        │ issue     │ 1 finding(s) │
│ rds-instance-multi-az-disabled   │ ok        │ clean        │
│ rds-instance-publicly-accessible │ ok        │ clean        │
│ rds-instance-unencrypted         │ ok        │ clean        │
│ rds-snapshot-public              │ ok        │ clean        │
│ s3-block-public-access-disabled  │ ok        │ clean        │
│ s3-bucket-public-access          │ issue     │ 1 finding(s) │
│ s3-bucket-tls-not-enforced       │ ok        │ clean        │
│ security-group-open-admin-ports  │ issue     │ 1 finding(s) │
│ vpc-flow-logs-disabled           │ ok        │ clean        │
└──────────────────────────────────┴───────────┴──────────────┘

Findings, in order
┏━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃   # ┃ Impact    ┃ Severity ┃ Region       ┃ Resource              ┃ Finding                               ┃ Fix      ┃
┡━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│   1 │ blocker   │ critical │ global       │ acme-customer-exports │ Publicly accessible S3 bucket         │ minutes  │
│     │           │          │              │                       │ Readable by anonymous or any-AWS      │          │
│     │           │          │              │                       │ principals via bucket policy          │          │
│   2 │ blocker   │ critical │ us-east-1    │ sg-0a1b2c3d           │ Security group allows SSH or RDP from │ minutes  │
│     │           │          │              │                       │ the internet                          │          │
│     │           │          │              │                       │ Group 'legacy-bastion' allows SSH     │          │
│     │           │          │              │                       │ (22) from 0.0.0.0/0                   │          │
│   3 │ expected  │ medium   │ us-east-1    │ us-east-1             │ GuardDuty is not enabled              │ minutes  │
│     │           │          │              │                       │ No GuardDuty detector exists in this  │          │
│     │           │          │              │                       │ region                                │          │
│   4 │ hardening │ low      │ us-east-1    │ mrk-f265774           │ KMS key without automatic rotation    │ minutes  │
│     │           │          │              │                       │ Customer-managed key does not have    │          │
│     │           │          │              │                       │ automatic annual rotation enabled     │          │
└─────┴───────────┴──────────┴──────────────┴───────────────────────┴───────────────────────────────────────┴──────────┘

19 check(s) across 1 region(s) in 41.6s — 4 gap(s), 2 blocker(s).
Run with --output markdown for fix steps, effort and monthly cost.

Checks AWS configuration only, which is one part of a SOC 2 audit. Not a compliance assessment.
```

Notice the ordering: a `blocker` finding at `medium` severity (missing CloudTrail
territory) would outrank a `hardening` finding at `critical` severity — audit
impact sorts first. Here, `expected`/medium (GuardDuty) still outranks
`hardening`/low (KMS rotation) for the same reason.

`--output markdown` produces a report with, for each finding: why it matters in
plain language, the affected resources, console steps, a CLI one-liner, what
the fix might break, and the control references it bears on.

## Install

```bash
pipx install sar-aws-faultline     # recommended
pip install sar-aws-faultline
```

Python 3.11+. Three runtime dependencies: boto3, typer, rich.

## Usage

```bash
sar-aws-faultline scan                          # default profile, default region
sar-aws-faultline scan --all-regions            # every enabled region
sar-aws-faultline scan --profile prod -r us-east-1 -r eu-west-1

sar-aws-faultline scan --output markdown > gaps.md
sar-aws-faultline scan --output json | jq '.findings[] | select(.audit_impact=="blocker")'

sar-aws-faultline scan --framework soc2-tsc     # only checks mapped to SOC 2
sar-aws-faultline scan --impact blocker         # only audit blockers
sar-aws-faultline scan --severity high          # only high and above

sar-aws-faultline checks                        # what it looks at
sar-aws-faultline frameworks                    # what it maps to
sar-aws-faultline iam-policy                    # the policy it needs
```

Configuration can also live in `sar-aws-faultline.toml` — see
[`sar-aws-faultline.toml.example`](sar-aws-faultline.toml.example). Precedence
is CLI flags > `SAR_AWS_FAULTLINE_*` environment > config file > defaults.

`--profile` is actually optional: if a profile named `sar-aws-faultline-scanner`
exists in your AWS config, `sar-aws-faultline scan` uses it automatically when
you don't pass `--profile` at all. This is a fallback, not a requirement — it
only ever applies when that exact profile is present, so it changes nothing
for default credentials, an instance role, or CI OIDC.

### As a CI gate

```yaml
- run: pipx install sar-aws-faultline
- run: sar-aws-faultline scan --all-regions --fail-on blocker
```

Exit codes are an interface; changing them is a breaking change.

| Code | Meaning |
|---|---|
| 0 | Clean, or findings below the `--fail-on` threshold |
| 1 | Findings at or above the threshold |
| 2 | One or more checks could not run |
| 3 | Usage error |

Code 2 is deliberately distinct from code 1. *"You have two problems"* and
*"I could not look at three of your checks"* are different messages, and a
pipeline that treats an AccessDenied as a clean pass is worse than no scan at
all. `--fail-on blocker` is usually what you want: fail on anything an auditor
would stop at, regardless of its severity score.

## Read-only, structurally

This is not a promise in a README. A botocore `before-call` hook inspects every
operation before it goes over the wire and raises if the operation name is not
a read. A check that tried to change something would fail in CI rather than
quietly succeed against your production account.

The guarantee is enforced twice more: the generated IAM policy is asserted to
contain no mutating action, and the policy generator refuses to emit one.

**There is no remediation in v1, deliberately.** A tool that can fix things is
a tool that needs write credentials, and write credentials change the risk
calculus of pointing it at production for the first time — which is exactly
when it is most useful. Every finding ships with the commands to fix it
yourself. You run them.

## IAM policy

Generated from the check registry, never hand-written. CI regenerates and diffs
it, so it cannot advertise permissions the code does not use, or omit ones it
does.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SarAwsFaultlineReadOnlyScan",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "config:DescribeConfigurationRecorderStatus",
        "config:DescribeConfigurationRecorders",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshotAttribute",
        "ec2:DescribeSnapshots",
        "ec2:DescribeVolumes",
        "ec2:DescribeVpcs",
        "guardduty:GetDetector",
        "guardduty:ListDetectors",
        "iam:GenerateCredentialReport",
        "iam:GetAccountPasswordPolicy",
        "iam:GetCredentialReport",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "kms:ListKeys",
        "rds:DescribeDBInstances",
        "rds:DescribeDBSnapshotAttributes",
        "rds:DescribeDBSnapshots",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketTagging",
        "s3:ListAllMyBuckets",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

Always current at [`docs/iam-policy.json`](docs/iam-policy.json), or run
`sar-aws-faultline iam-policy`. AWS's managed `SecurityAudit` policy also
covers everything here, if you would rather not manage a custom one.

## Compliance mapping, honestly

Each check maps to control references. **The mapping is deliberately modest
about what it claims.**

**Two hops, with different confidence.** Mapping a check to a CIS AWS
Foundations recommendation is *objective* — recommendations are numbered,
prescriptive and testable. Mapping that to a SOC 2 Trust Services Criterion is
*interpretive*: the TSC are principles-based, and there is no authoritative
AWS-configuration-to-TSC mapping. Every interpretive mapping must declare the
objective control it was reasoned from, so you can audit the inference instead
of taking it on trust.

**Nothing is ever "satisfied".** The relationship vocabulary has exactly two
values, `supports` and `partially_supports`, and a test fails the build if
anyone adds a third. A configuration scanner cannot establish that a control is
met; it produces one input to that judgement.

**What this tool does not see.** AWS configuration is roughly a quarter of a
SOC 2 audit. Access reviews, onboarding and offboarding, change management,
vendor management, incident response, security training and written policy are
the rest, and no scanner can see any of it. This tool is not a substitute for
Vanta, Drata or Secureframe — those cover the organisational side and barely
touch what this does. It is also not a substitute for an auditor.

**Green output does not mean compliant.** It means no gaps were found in the
things this tool looks at. That is a useful thing to know and a much smaller
thing than compliance.

Mapping data lives in [`src/sar_aws_faultline/data/`](src/sar_aws_faultline/data/)
as TOML, one file per framework, reviewable without reading Python. Adding a
framework touches no code.

> Control identifiers and short paraphrased titles only. The AICPA's Trust
> Services Criteria text and CIS's benchmark text are both licensed and are not
> reproduced in this repository.

## Why this exists when Prowler does

It mostly should not, and you should probably use Prowler.

[Prowler](https://github.com/prowler-cloud/prowler) runs 600+ AWS checks across
80+ services, maps to 40+ compliance frameworks including a 156-check SOC 2
framework, exports HTML/CSV/JSON, and has a funded team behind it. **For a real
audit, use Prowler.** This tool does not try to match it and will not.

[AWS Security Hub](https://aws.amazon.com/security-hub/) is the managed option
and a good floor if you are already all-in on AWS. Per-check pricing across
accounts and regions adds up, and findings live in one account's console.

[ScoutSuite](https://github.com/nccgroup/ScoutSuite) has not been updated since
May 2024.

What this does that they do not:

- **Ordering by audit impact, not just severity.** Nothing else models the
  second axis, so nothing else can tell you a medium-severity finding is the
  one that will stop your audit.
- **Cost of remediation on every finding.** Nobody puts the monthly bill of
  turning on a control next to the finding that says you should.
- **A scan short enough to actually read.** Prowler's full run takes 15–40
  minutes and produces hundreds of findings. This targets under a minute and
  a page.
- **Fix steps written for someone who does not already know.** Console path
  and CLI one-liner, plus what the fix might break.

If you want completeness, use Prowler. If you want to know what to do on Monday
morning, try this.

## Checks

Nineteen so far, with more landing incrementally. `sar-aws-faultline checks`
lists what is present in your installed version.

| Check | Severity | Audit impact | Effort | Cost/mo |
|---|---|---|---|---|
| `s3-bucket-public-access` | critical | blocker | minutes | $0 |
| `s3-block-public-access-disabled` | medium | expected | minutes | $0 |
| `s3-bucket-tls-not-enforced` | medium | expected | minutes | $0 |
| `rds-instance-unencrypted` | high | blocker | planned | $0 |
| `rds-instance-publicly-accessible` | high | blocker | minutes | $0 |
| `rds-snapshot-public` | critical | blocker | minutes | $0 |
| `rds-instance-multi-az-disabled` | low | hardening | minutes | $15 |
| `ebs-volume-unencrypted` | medium | expected | hours | $0 |
| `ebs-snapshot-public` | critical | blocker | minutes | $0 |
| `security-group-open-admin-ports` | critical | blocker | minutes | $0 |
| `vpc-flow-logs-disabled` | low | hardening | minutes | $2 |
| `iam-root-account-no-mfa` | critical | blocker | minutes | $0 |
| `iam-user-no-mfa` | high | expected | minutes | $0 |
| `iam-access-key-stale` | medium | expected | hours | $0 |
| `iam-password-policy-weak` | low | expected | minutes | $0 |
| `cloudtrail-not-enabled` | medium | blocker | minutes | $2 |
| `aws-config-not-enabled` | medium | blocker | minutes | $3 |
| `guardduty-not-enabled` | medium | expected | minutes | $5 |
| `kms-key-rotation-disabled` | low | hardening | minutes | $0 |

Every planned area from the original roadmap now has at least one check, and
public exposure, data protection, and IAM hygiene each have several. Scope is
still intentionally curated relative to a full compliance-scanner's check
count — false positives are the specific failure mode this project exists to
avoid, and every check here still had to clear the bar in `CONTRIBUTING.md`.
See what was cut and why in
[`docs/DECISIONS.md`](docs/DECISIONS.md#9-v1-scope).

## Limitations

- **Single account.** No AWS Organizations or multi-account aggregation.
- **Point in time.** Not continuous monitoring.
- **Configuration only.** Cannot see your processes, your people, or your code.
- **No remediation.** By design; see above.
- **Curated, not complete.** Passing every check means passing every check. It
  does not mean your account is secure.
- **`--all-regions` is slower than it looks** on accounts with many enabled
  regions.

## Adding a check

Drop a file in `src/sar_aws_faultline/checks/`. Nothing else changes — the
registry discovers it, the IAM policy picks up its permissions, and the
renderers handle it. Third-party distributions can ship checks via the
`sar_aws_faultline.checks` entry-point group.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
