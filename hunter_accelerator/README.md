# Hunter All deterministic accelerator — Phase 1

This directory contains an installation-free, read-only preparation accelerator for the existing **Hunter All** Devin Code Scan profile. It performs the mechanical repository work from matcher-phase Steps 0–6 once, then gives Devin compact, evidence-backed artifacts for the security investigation.

Hunter All remains the final authority. The accelerator does not decide that code is vulnerable or secure, does not suppress investigation, and does not implement investigation, triage, runtime validation, remediation, CVSS, deduplication, final findings, or reporting. Matcher specifications are leads, not findings.

## Why it exists

The profile requires a deep repository profile, 85-class applicability accounting, carrier searches, negative evidence, non-source matchers, and standing business-logic target enumeration. Repeating those deterministic searches consumes reasoning context. This tool performs them locally with a single repository walk and content-addressed per-file caching. Any unsupported or incomplete area is surfaced as a coverage gap and handed back to the original Hunter All process.

No ACU-reduction claim is made by this implementation. Reduction must be measured with the specified A/B Code Scan using the same target commit.

## Run directly

Python 3.11 or newer is required. No installation is required and no dependency is downloaded.

```bash
python3 /path/to/security-scan-results/hunter_accelerator/devin_prepare.py \
  --target-repo /path/to/target-repository \
  --output-dir /tmp/hunter-accelerator
```

From the snapshot repository:

```bash
python3 hunter_accelerator/devin_prepare.py \
  --target-repo "$PWD" \
  --output-dir /tmp/hunter-accelerator
```

Options include `--taxonomy`, `--max-file-size`, `--max-total-bytes`, `--cache-dir`, `--no-cache`, `--strict`, and `--summary-only`. Exit codes are `0` COMPLETE, `2` PARTIAL, `3` FAILED, and `4` invalid invocation.

## Artifacts

The output directory is required to be outside the target repository.

- `manifest.json`: versions, repository state, file-manifest hash, artifact hashes, status, and counts.
- `summary.json`: compact Devin-facing counts and capability summary.
- `repository-profile.json`: languages, frameworks, build systems, technologies, repository types, and unsupported constructs.
- `file-inventory.jsonl`: stable, hashed, classified file inventory from the single walk, including generated and vendor-derived provenance tags.
- `skipped-files.json`: every ignored or unread file/directory and the exact reason.
- `carrier-inventory.json`: path/content/dependency carrier evidence with stable relative source locations.
- `category-applicability.json`: all 85 classes with exactly one applicability state and its evidence.
- `negative-evidence.json`: executed carrier/indicator searches supporting N/A or unresolved decisions.
- `mandatory-matchers.json`: class-numbered, OWASP-tagged matcher specifications; never findings.
- `logic-targets.json`: state-changing and business-sensitive targets for the mandatory Hunter All logic pass.
- `unsupported-constructs.json`: constructs requiring original Hunter All manual analysis.
- `coverage-gaps.json`: explicit fail-closed gap conditions.
- `telemetry.json`: local phase timings, scanned bytes, cache counts, regex searches, and gaps.
- `errors.json`: sanitized pipeline errors (empty on a successful preparation run).

## Status contract

- `COMPLETE` means all supported deterministic Phase 1 preparation completed. It does **not** mean the repository is secure, investigated, or finding-free.
- `PARTIAL` means Devin must perform the original Hunter All process for every unresolved category, skipped security-relevant file, unsupported construct, unresolved Git metadata area, and coverage gap. Completed evidence may still be used.
- `FAILED` means the output cannot be trusted and the unmodified Hunter All matcher process must run in full. `--strict` promotes a partial result to failed.

The tool refuses invalid taxonomy data and never emits COMPLETE with applicable classes missing matcher/logic coverage, unresolved applicability, skipped relevant files, unsupported coverage, or invalid output.

## Cache

The default cache is `/tmp/hunter-accelerator-cache/`, outside the target. Cache entries are keyed by target absolute path, stable relative path, working-tree content hash, taxonomy version, accelerator version, and configuration version. A changed file invalidates only its per-file analysis. Applicability is rebuilt from the current manifest on every run, so an N/A decision is never reused after a security-relevant file changes. Use `--no-cache` to disable cache reads and writes.

## Safety and quality guarantees

- The target is treated as untrusted data and is never imported, evaluated, executed, built, installed, or sent to a network/model.
- Git inspection uses read-only commands with hooks, prompts, fsmonitor, and optional locks disabled.
- Symlinks are never followed; escapes are recorded and make affected coverage partial.
- `target`, `build`, `dist`, `.next`, and `vendor` are traversed. Relevant text, source, configuration, prompt, CI/CD, manifest, and infrastructure files are analyzed and tagged as generated or vendor-derived. Limits that prevent inspection produce security-relevant skips and PARTIAL coverage.
- `.git`, `node_modules`, Python virtual environments and bytecode caches, `.gradle`, and coverage output remain excluded from the content walk. A `.git` gitfile is handled separately through constrained, read-only Git commands so worktrees and submodules retain commit and status metadata.
- The output and cache directories must resolve outside the target repository.
- Binary, size, encoding, generated/test, configuration, prompt, CI/CD, container/IaC, mobile, and dependency status is audited.
- Tests and fixtures are not automatically suppressed.
- Likely secret values are not copied into evidence or logs; locations and indicator names are preserved.
- Always-applicable, absence, logic, Hydra, mobile, prompt/content, LLM, Agentic, and coverage rules are startup-validated against the machine-readable Hunter All conversion.

## Current limitations

The Phase 1 enumerators are deliberately conservative and syntax-light. They do not render Helm, decompile mobile binaries, resolve dynamic reflection/routes, understand arbitrary internal frameworks, perform complete symbol/data-flow analysis, establish source–sink–path proof, re-audit N/A decisions as triage, or make security decisions. Such areas produce PARTIAL output and must follow the profile fallback contract.

## Profile integration

Use [`profile_integration/matcher_phase_addition.txt`](profile_integration/matcher_phase_addition.txt) as the minimal matcher-phase pre-pass addition and [`profile_integration/investigation_phase_addition.txt`](profile_integration/investigation_phase_addition.txt) as the Phase 1 investigation orientation note. Neither replaces or edits any original Hunter All content. The fallback behavior is documented in [`profile_integration/fallback_contract.md`](profile_integration/fallback_contract.md).

## Tests

```bash
python3 -m unittest discover -s hunter_accelerator/tests -v
```

Tests use only the Python standard library and do not install target dependencies.
