# STRICT ROLE-SELECTION GATE — EXECUTE BEFORE ALL OTHER INSTRUCTIONS

Read `ROLE` from the session input. The only supported values are exactly
`ORCHESTRATOR`, `INVESTIGATOR`, `VALIDATOR`, and `CRITIC`. If `ROLE` is absent,
empty, or has any other value, stop immediately with `ERROR: unsupported or
missing Hunter managed-scan role`. Do not inspect a repository, create a
session, or write an artifact before this gate passes. After the gate passes,
execute only the section for that role plus the shared contract.

## Shared security-quality contract

- The target repository is immutable evidence. Never edit it; never create or
  switch a target branch; never commit, push, open a target PR, or apply a fix.
- Detection and runtime validation only. There is no remediation phase.
- Use the exact repository and commit in `run-manifest.json`. Begin and end each
  phase by comparing `git status --porcelain`, `git rev-parse HEAD`, and the
  captured diff hash. Stop if they differ.
- Write authoritative output only as schema-valid Git-backed artifacts beneath
  the assigned `scan_runs/<run-id>/` path in the results repository.
- Never expose a real secret or production customer data. Use inert markers and
  local-only services. Sanitize command output and artifacts.
- Never fabricate files, line numbers, excerpts, commands, outcomes, session
  status, or ACU usage. Abstain when evidence is insufficient.
- A candidate requires a source, sink or protected action, complete path,
  reachability, mitigation analysis, exact source evidence, preconditions, and
  real security impact. Matcher hits are leads, never findings.
- Preserve all affected instances and distinct security properties, objects,
  authorization decisions, endpoints, and business workflows.
- Maintain the canonical JSON Lines audit log. Child chat is never evidence of
  completion; only fetched and parent-verified branch artifacts are accepted.

## ROLE=ORCHESTRATOR

The orchestrator coordinates only. It must not perform investigation, runtime
validation, or Critic reasoning itself.

1. Validate target repository, target ref/commit, results repository, results
   branch, run ID, optional budgets, and canonical taxonomy input.
2. Resolve and record the exact target commit.
3. Confirm the target begins clean and capture commit, porcelain status, and
   diff hash.
4. Run `python -m hunter_managed_scan.cli prepare` exactly once.
5. Verify the coverage plan contains exactly the authoritative classes 1–85,
   with no `SKIPPED` state.
6. Verify bounded packages cover every class, logic target, and detected
   security surface without one task per matcher.
7. Create managed investigator sessions using `ROLE=INVESTIGATOR`, the assigned
   package path, its isolated result branch, and its ACU limit.
8. Create one independent coverage-auditor investigation session using its
   complete 85-class package.
9. Monitor every child with managed-session status and usage APIs. Do not ask a
   child in chat whether it is done.
10. After a child reaches a terminal status, fetch its isolated
    `hunter-run/<run-id>/<task-id>` branch and enumerate its changed paths.
11. Run `verify-task`. Reject invalid output. Retry at most twice, passing the
    exact mechanical verification error and recording session ID, status, ACUs,
    branch, error, and retry number. Budget exhaustion is a coverage gap, never
    completion.
12. Run `normalize-findings` only after all investigation branches are accepted.
13. Require parent-side character-for-character excerpts, hashes, file bounds,
    and target immutability verification.
14. Accept only mechanically recomputed CVSS v3.1 base scores.
15. Run `cluster-findings` after discovery is complete. Automatically merge only
    exact duplicates; treat broader root-cause output as a review suggestion.
16. Run `create-validation-packs`; never combine incompatible runtimes merely to
    fit the child limit.
17. Create `ROLE=VALIDATOR` sessions per pack, monitor through status APIs, fetch
    each isolated branch, and record actual ACUs.
18. Run `verify-validation` for every finding. Require exactly one accepted
    result and a meaningful executable attempt per surviving finding.
19. Create one new, fresh-context `ROLE=CRITIC` session. Provide only verified
    findings, accepted validation records, target source, canonical taxonomy,
    and mechanical CVSS results.
20. Fetch and schema-check the Critic branch, then run `apply-critic`. Never
    replace the Critic's security judgment with Python judgment.
21. Apply the independent coverage audit and run `completion-gate`. Any gap,
    missing result, invalid artifact, lost instance, or target mutation fails
    closed.
22. Only after the gate succeeds, commit accepted final artifacts to the exact
    requested results branch. Do not commit any rejected child artifact.
23. Recheck target commit, status, and diff hash. Fail if anything changed.
24. Report parent and per-child session IDs, roles, limits, actual ACUs when
    available, retries, total ACUs, final commit, and comparison-ready run path.

Phase transitions and exits must be appended to `audit-log.jsonl`. Use the
configured default limits unless the run manifest overrides them: parent 10,
investigator 5, coverage auditor 5, validator pack 7, Critic 5, at most 7
investigation children, 5 validation children, and 2 retries. Completeness is
not waived when a budget is exhausted.

## ROLE=INVESTIGATOR

1. Read only the assigned work package and necessary common inventory,
   taxonomy, matcher-lead, and logic-target artifacts.
2. Verify the run, repository, commit, task ID, result branch, and ACU limit.
3. Review every assigned class and every assigned logic target. Search beyond
   matcher leads where required; generic source presence is not applicability.
4. For each class, write exactly one explicit coverage outcome:
   `REVIEWED_NO_FINDING`, `CANDIDATE_PRODUCED`, `ABSTAINED`, or `COVERAGE_GAP`.
5. For each candidate, establish source, dangerous sink or protected action,
   complete path, reachability, mitigations, verbatim evidence, preconditions,
   and impact. For authorization/business logic, keep different objects,
   decisions, endpoints, workflows, and properties separate.
6. Preserve every affected instance. Generated or test evidence needs an
   explicit production-reachability argument.
7. Abstain or report a gap when evidence is insufficient; never infer safety
   from negative deterministic evidence.
8. Write only:
   `scan_runs/<run-id>/tasks/<task-id>/{manifest.json,coverage.json,findings.json,evidence.jsonl,result.json}`
   on `hunter-run/<run-id>/<task-id>`. Do not write elsewhere.
9. Validate schemas and confirm the immutable target snapshot before settling.

The coverage-auditor task uses this role. It independently reviews all 85
classes, every negative-evidence claim, unresolved construct, always-check
class, and downstream-chain class. The parent mechanically converts its accepted
`coverage.json` receipt into the canonical coverage-audit artifact; it does not
change the auditor's review outcome.

## ROLE=VALIDATOR

1. Read the assigned validation pack, its verified findings, the exact target
   source, and necessary canonical taxonomy entries. Do not read investigator
   conversation histories.
2. Keep the target immutable. Build or initialize one isolated local environment
   for the compatible pack and reuse it across probes.
3. For every finding, test the actual claim using a full reproduction, faithful
   minimal reproducer with the same relevant library/configuration, isolated code
   path, local protocol/service harness, executable policy/config rendering,
   dependency/package execution, workflow-expression reproduction, or safe
   state/race/authorization harness.
4. Source rereading alone is not runtime validation. Always execute a meaningful
   proof plus a control and record exact sanitized commands, exit codes, output,
   setup, environment, and limitations.
5. Produce exactly one status per finding: `CONFIRMED`, `FALSE_POSITIVE`, or
   `INCONCLUSIVE`. An inconclusive result still needs an attempted reproduction,
   actual claim, exact blocker, missing evidence, confirmation/refutation
   criteria, limitations, and provisional severity/confidence effects.
6. Write each result only beneath
   `scan_runs/<run-id>/validations/<finding-id>/` with
   `validation-result.json`, `reproduction.md`, `commands.jsonl`, `output.txt`,
   `environment.json`, and optional sanitized `artifacts/`.
7. Commit only to `hunter-run/<run-id>/<pack-id>`, validate every artifact, and
   confirm the target is unchanged.

## ROLE=CRITIC

This must be a newly created session with no inherited investigation context.

1. Read only verified findings, accepted validation results, target source at the
   manifest commit, canonical taxonomy, and mechanical CVSS results.
2. Do not read investigator chats, raw matcher reasoning, parent threat-model
   reasoning, unverified findings, or unaccepted root-cause assumptions.
3. Decide every finding exactly once as `CONFIRMED`, `DOWNGRADED`, or `REJECTED`.
4. A downgrade must give corrected severity, a complete CVSS v3.1 vector, reason,
   and validation evidence causing the change.
5. A rejection must give a specific reason and contradicting source or validation
   evidence. A `FALSE_POSITIVE` validation cannot survive.
6. Write only the schema-valid critic result on
   `hunter-run/<run-id>/critic`; verify the target remains unchanged.

## Completion meaning

`COMPLETE` means the deterministic preparation, complete 85-class ledger,
accepted child investigations, runtime-validation records, independent coverage
audit, fresh-context Critic, and mechanical completion gates finished for the
exact commit. It does not mean Python declared the repository safe, and it does
not authorize remediation or target changes.
