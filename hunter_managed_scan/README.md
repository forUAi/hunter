# Hunter Managed Session Workflow

This additive framework prepares and gates a parent-managed security scan while
leaving Hunter's existing accelerator, matcher commands, and authoritative
85-class taxonomy unchanged. Python handles repeatable evidence processing;
managed Devin roles perform investigation, runtime validation, independent
coverage review, and fresh-context criticism. The framework does not start real
sessions by itself.

## Architecture and trust boundaries

`prepare` takes a clean Git target at an exact commit and a separate Git results
repository on the requested branch. It runs the existing deterministic
accelerator once, imports its inventory, carriers, matcher specifications,
negative evidence, logic targets, coverage gaps, and telemetry through adapters,
then writes an 85-entry coverage plan and approximately six bounded work
packages. Generic source presence is filtered out as category applicability.

Children write only to isolated `hunter-run/<run-id>/<task-id>` results branches.
The parent fetches a terminal child branch, checks changed paths, schemas,
identity, assigned-class accounting, exact excerpts and hashes, generated/test
production relevance, secret hygiene, and target immutability. Chat messages are
never accepted as completion evidence.

After all investigation finishes, Python recomputes CVSS, merges only exact
mechanical duplicates, preserves every instance, and emits broader clustering
suggestions for human review. Compatible findings are grouped into validator
packs of at most six; incompatible runtime families are kept separate. Every
surviving candidate must have exactly one accepted record containing a meaningful
executable proof and control. A newly created Critic sees only verified inputs.
The final gate fails closed on missing coverage, ownership, child artifacts,
validation, Critic output, consistent CVSS, preserved instances, immutable target
state, or final artifacts.

Python never promotes a matcher hit to a finding, declares code safe or
vulnerable, semantically merges business workflows, marks a class N/A, changes
target code, or launches remediation.

## Reused Hunter implementation

The exact integration inventory is in [REUSE.md](REUSE.md). Adapters import the
existing workspace/Git guard, inventory and classification, carrier and
capability detection, matcher-spec generation, negative evidence, logic-target
enumeration, hashing/redaction, telemetry, and canonical taxonomy. No second
taxonomy is maintained.

## Roles and Playbook

The single role-gated Playbook is
`hunter_managed_scan/playbook/hunter-managed-security-scan.devin.md`. Supported
roles are `ORCHESTRATOR`, `INVESTIGATOR`, `VALIDATOR`, and `CRITIC`. Missing or
unsupported roles stop before repository access. The orchestrator uses session
status/usage APIs, records ACUs, retries failed tasks at most twice with the exact
mechanical error, and never performs child reasoning itself.

Default budgets are parent 10 ACUs, investigator 5, coverage auditor 5, validator
pack 7, Critic 5, at most 7 investigation children, 5 validation children, and 2
retries. Exhaustion creates a gap; it never relaxes completeness.

## Local deterministic commands

Run from the `forUAi/hunter` repository root:

```bash
python -m hunter_managed_scan.cli prepare \
  --target-repo-path /path/to/target \
  --target-repo amex-eng/example-repo \
  --target-commit <full-sha> \
  --results-repo-path /path/to/forUAi-hunter \
  --results-branch hunter-managed-test \
  --run-id hunter-example-20260718

python -m hunter_managed_scan.cli verify-task \
  --run-dir /path/to/forUAi-hunter/scan_runs/hunter-example-20260718 \
  --work-package /path/to/package.json \
  --child-artifact-dir /fetched/scan_runs/hunter-example-20260718/tasks/investigator-authz-business \
  --target-repo-path /path/to/target \
  --changed-path scan_runs/hunter-example-20260718/tasks/investigator-authz-business/result.json

python -m hunter_managed_scan.cli normalize-findings --run-dir <run-dir>
python -m hunter_managed_scan.cli cluster-findings --run-dir <run-dir>
python -m hunter_managed_scan.cli create-validation-packs --run-dir <run-dir>
python -m hunter_managed_scan.cli verify-validation \
  --run-dir <run-dir> --pack <pack.json> --finding-id <id> \
  --artifact-dir <validation-dir> --target-repo-path /path/to/target
python -m hunter_managed_scan.cli coverage-audit \
  --run-dir <run-dir> --audit <run-dir>/investigation/verified/coverage-auditor.json
python -m hunter_managed_scan.cli apply-critic --run-dir <run-dir> --critic-result <critic-result.json>
python -m hunter_managed_scan.cli completion-gate --run-dir <run-dir> --target-repo-path /path/to/target
```

Exit codes are stable: `0` success, `1` operational error, `2` schema or
verification failure, `3` incomplete coverage, `4` missing validation, and `5`
target modification.

All default controls can be overridden on `prepare` with `--parent-acu`,
`--investigator-acu`, `--coverage-auditor-acu`, `--validator-acu`,
`--critic-acu`, `--max-investigation-children`, `--max-validation-children`,
and `--max-retries`. Safety maxima remain seven investigation children, five
validation children, and two retries.

## Exact session prompt

```text
hunter-managed(playbook).

ROLE=ORCHESTRATOR

Scan amex-eng/600000493-mp3-account-pricing-review.

Write accepted artifacts and final results to the hunter-cbom branch of
forUAi/hunter.

Detection and runtime validation only.

Do not modify the target repository and do not create any PRs.
```

Normal input handling must resolve or request target repository, exact target
commit/ref, results repository, results branch, optional ACU budget, and optional
run ID before preparation.

## Artifacts and failure behavior

Accepted artifacts live only beneath `scan_runs/<run-id>/`: the manifest and
canonical JSONL audit log; accelerator inventory; coverage plan/audit/final;
bounded packages; raw/normalized/verified investigations; root-cause output;
validation packs and one validation tree per finding; Critic output; final JSON;
executive brief; and run summary. Contracts in `schemas/` are validated with a
standard-library validator so deployment has no new package dependency.

The gate fails rather than emitting a complete result when a class, logic target,
surface owner, branch artifact, assigned-class outcome, exact excerpt, executable
validation attempt, Critic decision, consistent CVSS value, affected instance,
immutable target check, or final artifact is absent. Inconclusive validation is
retained with its blocker and confirmation criteria; it is never silently
discarded.

## Comparison with a previous Gold scan

Use the same target commit for both runs. Compare class-by-class coverage state,
logic-target ownership, candidate and final finding IDs, affected instances,
validation statuses, Critic verdicts, gaps, elapsed phases, and total/per-session
ACUs. Investigate differences as methodology/evidence differences before treating
them as regressions. The recommended first run is a representative repository
with a known Gold scan, one primary backend runtime, CI, infrastructure, and a
small number of previously validated findings; this exercises grouping without
creating an artificial maximum-child failure.

Known limitation: remote managed-session creation, status polling, branch fetch,
and commit/push are deployment-environment integrations described by the
Playbook and represented by the `SessionGateway` protocol. Automated tests mock
that boundary; this repository intentionally contains no credentials and starts
no real child sessions.
