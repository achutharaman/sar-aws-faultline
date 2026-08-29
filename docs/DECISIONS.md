# Decisions

The living spec. Updated whenever scope or a design choice changes, so neither of
us has to reconstruct "why is it like this?" from a long conversation.

**Status:** v0.1 scaffolding complete — core engine and one check, 119 tests green.
**Last updated:** 2026-08-21

---

## 1. What this is

A read-only scanner that finds the gaps between a small team's AWS account and
SOC 2 / AWS security best practice, and tells them **what to fix first, how, and
what it costs**.

Audience: developers, solo founders, 1–3 person teams with no security hire,
facing SOC 2 for the first time — usually because a customer asked.

Positioning: *"Prowler tells you everything that's wrong. This tells you what to
fix first and what it'll cost you."*

---

## 2. Reality check (2026-08-21)

Recorded because it constrains everything below, and because forgetting it would
lead straight back to building a worse Prowler.

Prowler is not merely adjacent — it occupies the exact square originally
proposed. It ships a `soc2_aws` framework with 27 requirements across 156
checks, markets "SOC 2 evidence collection" as a headline solution, exports
HTML/CSV/JSON, and covers ~600 AWS checks across 80+ services with a funded team
behind it. **"SOC 2 evidence output" is therefore not available as a
differentiator.** ScoutSuite has been unmaintained since May 2024 and is not
worth comparing against.

Two real gaps remain, both about *signal* rather than coverage:

1. A full Prowler run takes 15–40 minutes and produces hundreds of unranked
   findings. The target reader closes that tab.
2. Nothing in the space models *audit impact* separately from *severity*, and
   nothing prices the remediation.

The tool is built into those two gaps. It does not attempt completeness and the
README says so explicitly.

---

## 3. Naming

| Surface | Name |
|---|---|
| PyPI distribution | `sar-aws-faultline` |
| Import package | `sar_aws_faultline` |
| CLI command | `sar-aws-faultline` |
| GitHub repo | `sar-aws-faultline` |
| Config file | `sar-aws-faultline.toml` |
| Env prefix | `SAR_AWS_FAULTLINE_` |
| IAM Sid | `SarAwsFaultlineReadOnlyScan` |

A fault line is a latent discontinuity — where stress concentrates and failure
eventually starts. Finding one is not finding a disaster; it is finding where
one could begin. That carries the right epistemic weight for a tool that must
not overclaim.

**Rejected:** `sentinel` (collides head-on with Microsoft Sentinel and
HashiCorp Sentinel, both in the immediately adjacent space), `tripwire`
(Tripwire Inc.), `checkpoint` (Check Point Software), `lighthouse` (Google
Lighthouse). `preflight` was a strong runner-up — it encoded "finite checklist,
run before the real thing" into the name itself — but does not say what the
tool hunts for. The README's opening paragraph now carries that framing
instead.

**No npm package.** This is a Python distribution; squatting an unused npm name
would be bad form.

---

## 4. Relationship to the rest of the `sar-` set

**Fully decoupled** (revised 2026-08-21). Originally scoped as the verification
half of `sar-aws-baseline` — a drift detector for that Terraform baseline,
expressed in compliance language. That was the one position no competitor could
occupy, and giving it up is a real cost, recorded here deliberately.

What decoupling means in practice:

- No narrative link in the README beyond a "Related" section.
- No dependency, shared package, or coordinated release between repos.
- **No EBS check migration.** The sibling cost tool keeps `ebs-unattached`
  permanently. Faultline will implement its own encryption checks
  independently and wider (volumes + snapshots + account-level
  default-encryption). Two independent tools flagging the same resource for
  different reasons is not a defect: a cost tool and a security tool care
  about an unencrypted volume for entirely different reasons. This deletes a
  multi-release deprecation dance and removes all risk to that tool's launch.
- **No `sar-aws-common` package.** Two repos duplicating ~150 lines of session
  setup is cheaper than three repos coupled to a versioned internal dependency.
  Revisit at repo #4 or past ~300 lines of duplication.

What is shared is *conventions*, not code — see §5.

---

## 5. Conventions inherited from a sibling project

Adopted so the two repos read as one hand. Reconciled against that project's
actual source on 2026-08-21.

| Convention | Detail |
|---|---|
| Layout | Flat `src/sar_aws_faultline/`. No `core/` subpackage. |
| Modules | `models` `registry` `runner` `context` `session` `config` `iam` `cli` |
| Renderers | `output/` with `base.py` + one module per format |
| Data types | `@dataclass(frozen=True, slots=True)` + `StrEnum`. No Pydantic. |
| Check contract | ClassVar metadata + `run(ctx) -> Iterable[Finding]`, `@register` validating at import time, `Protocol` for typing |
| Scope | `REGIONAL` / `GLOBAL`, expanded by `plan_units` |
| Errors | `CheckError` recorded separately; scan continues |
| Concurrency | `ThreadPoolExecutor` over (check, region), thread-local sessions |
| Read-only | botocore `before-call` guard; `ReadOnlyViolationError` propagates |
| IAM | Generated from `required_actions`, committed to `docs/iam-policy.json`, diffed in CI |
| Config | TOML + `SAR_AWS_FAULTLINE_*` env + CLI, per-check options via `ctx.option()` |
| Plugins | `sar_aws_faultline.checks` entry-point group |
| Exit codes | `ExitCode` class; documented as an interface |
| Living spec | This file |

### Deliberate divergences

| Divergence | Why |
|---|---|
| `Severity.CRITICAL` added | The sibling cost tool tops out at HIGH. A security tool needs a level meaning "an unauthenticated stranger can read this right now". |
| `AuditImpact` axis added | The core product idea. No cost-tool analogue. |
| `Remediation` on the check | Fix steps, effort and monthly cost are intrinsic to a security finding; the cost tool's equivalent (price) is per-resource and computed. |
| `rationale` ClassVar | Product copy rendered verbatim in the report. `register()` rejects stubs under 80 chars. |
| `markdown` output format | The sibling tool has table + json only. |
| `compliance.py` + `data/` | No analogue in the sibling tool. |
| `FailOn.BLOCKER` | A threshold a severity-only tool cannot express, and the one most CI pipelines want. |
| No `pricing/` | Remediation cost is a static per-check figure, not a live API lookup. |

---

## 6. The two-axis model

The central design bet. Every finding carries **severity** (exploit impact) and
**audit impact** (`blocker` / `expected` / `hardening`). They do not correlate:

- Missing CloudTrail: medium severity, absolute audit blocker.
- Permissive SG on an isolated dev VPC: high severity, barely registers.

`Finding.sort_key` orders by audit impact **before** severity. `--fail-on
blocker` gates CI on the audit axis alone. Enforced by
`test_sort_key_ranks_audit_impact_above_severity` and
`test_fail_on_blocker_ignores_severity`.

Second differentiator: `Remediation.monthly_cost_usd`. GuardDuty, Config and
flow logs all cost real money at startup scale. Nobody else puts that number
next to the finding.

---

## 7. Compliance mapping

**Data, not code.** TOML under `data/frameworks/` and `data/mappings/`.
Adding a framework adds a file and touches no Python. TOML rather than YAML so
stdlib `tomllib` covers it — this keeps the runtime dependency set to three:
boto3, typer, rich.

**Two hops, different confidence.** check → CIS recommendation is *objective*
(numbered, testable). CIS → SOC 2 TSC is *interpretive* (principles-based, no
authoritative mapping exists). Frameworks declare `interpretive`; interpretive
mappings **must** set `derived_from` pointing at an objective control, enforced
at load time and in tests.

**No "satisfies".** `Relationship` has exactly two members. A test asserts the
enum never grows a third. This is the overclaiming problem solved by the type
system rather than by a disclaimer nobody reads.

**No licensed text.** AICPA TSC text and CIS benchmark text are both licensed.
Only identifiers and short paraphrased titles are stored, with a `notice` field
per framework surfaced in every report.

**CIS version:** targeting v4.0.0, where §2.1.4 is the S3 Block Public Access
recommendation. v5.0.0 exists (Security Hub tracks it); advancing means
re-reviewing every mapping, not editing a version string.

---

## 8. Read-only

Three independent enforcement points, because the likeliest first use is a
nervous person pointing this at production:

1. Runtime — botocore `before-call` guard rejects any operation whose name is
   not in `READ_ONLY_PREFIXES`.
2. Permission boundary — `test_generated_policy_contains_no_mutating_action`.
3. Generator — `scripts/generate_iam_policy.py` refuses to emit a mutating
   policy.

`ReadOnlyViolationError` is the one exception the runner never swallows: it
means a bug in this codebase, not a problem in the user's environment.

**No remediation in v1.** A tool that fixes things needs write credentials, and
write credentials change the risk calculus of the first run — exactly when the
tool is most useful.

---

## 9. v1 scope

**Shipped:** `s3-bucket-public-access`.

Models *effective* exposure, not "are all four BPA flags set". `IgnorePublicAcls`
neutralises existing public ACLs; `BlockPublicAcls` only rejects new ones.
Likewise `RestrictPublicBuckets` vs `BlockPublicPolicy`. Flag-counting produces
false positives on genuinely private buckets, which is the exact failure mode
this project exists to avoid.

### Planned areas (TODO)

One check has landed in each area. None of these are exhaustive coverage of
their area -- one check per area was the bar, matching "curated, not
complete." Widening any of these (snapshots and default-encryption for the
EBS area, additional public-exposure resource types beyond S3, more of the
credential-report-derived IAM findings the efficiency note below describes)
is future work, not a gap in what shipped.

- [x] **Encryption at rest** — `ebs-volume-unencrypted`. Snapshots and the
      account-level default-encryption setting are still open; see §4 for
      why this stays independent of the sibling cost tool's
      `ebs-unattached`.
- [x] **Public exposure** — `s3-bucket-public-access`,
      `s3-block-public-access-disabled`.
- [x] **IAM hygiene** — `iam-root-account-no-mfa`, pulled from the IAM
      credential report per the efficiency note below. Key age, rotation and
      password age from the same report are still open; see "Broad IAM
      policy analysis" above for why broader policy analysis stays narrow.
- [x] **Logging and monitoring** — `cloudtrail-not-enabled`.
- [x] **Key management** — `kms-key-rotation-disabled`.
- [x] **Data protection** — `rds-instance-unencrypted`, the check
      CONTRIBUTING.md uses as its worked example, implemented for real here.

Each needs its own severity/audit-impact pairing, remediation, IAM actions
and compliance mapping — see "Adding a check" in `CONTRIBUTING.md`.

Two of the new CIS AWS mappings (`1.5` root MFA, `2.3.1` RDS encryption) are
a best inference, not a confirmed v4.0.0 citation -- see the comment above
those controls in `data/frameworks/cis-aws.toml` for why, and revisit
against the primary CIS document if it becomes available.

`READ_ONLY_PREFIXES` (session.py) gained `"Generate"` for
`iam:GenerateCredentialReport` -- a server-side report, not a mutation. See
the comment there for the reasoning and the boundary it does not extend to.

### Cut from v1, on domain grounds

| Cut | Why |
|---|---|
| DynamoDB encryption | Encrypted at rest by default since 2018. Always passes; only AWS-owned-vs-CMK is interesting, and that is a weak finding. Including it would be padding the check count. |
| NACLs | Correct evaluation needs ordered rule processing across ingress and egress. High false-positive rate; security groups are where real exposure lives. |
| Unused IAM roles | Needs Access Advisor last-accessed data: slow, per-principal, and "unused" is a judgement call rather than a finding. |
| S3 access logging | Noisy, frequently off on purpose, weak control value. |
| Broad IAM policy analysis | Rabbit hole; IAM Access Analyzer already does policy validation. Narrowed to customer-managed policies with `Action:*` + `Resource:*`, plus wildcard `iam:PassRole`. |
| Multi-account / Organizations | Out of scope for the target audience. |

### Efficiency note for the IAM area

Pull the **IAM credential report** once and derive MFA status, key age, key
rotation, root usage and password age from it, rather than N per-user calls.
Single API, and it keeps the whole area inside the time budget.

---

## 10. Performance budget

Full scan under 60 seconds on a small account. This is a founder-patience
budget, and it is a real constraint on check selection — it is why filtering
happens in `select_checks` before the runner rather than on findings afterwards.

---

## 11. Python support

Current stable is 3.14.7 (3.15 due October 2026). `requires-python = ">=3.11"`;
CI matrix 3.11–3.14. 3.10 reaches end of life in October 2026 and is not
supported. 3.11 is the floor because `tomllib` and `StrEnum` are both stdlib
from 3.11, and both are load-bearing here.

---

## 12. Open questions

- Should the report state how many resources were *checked*, not just how many
  failed? "2 of 47 buckets exposed" is more useful than "2 exposed", but the
  sibling tool's model has no pass concept and adding one is a schema change.
- ASFF or OCSF exporter as a fourth renderer — worth it only if someone
  actually wants Security Hub ingestion.
- Whether `--all-regions` should cap concurrency separately from `max_workers`.
