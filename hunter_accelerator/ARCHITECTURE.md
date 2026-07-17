# Architecture

```text
Target repository
        ↓
Single-pass deterministic inventory
        ↓
Carrier and capability profile
        ↓
85-class applicability evidence
        ↓
Mandatory matcher specifications
        ↓
Logic-target enumeration
        ↓
Coverage-gap detection
        ↓
Hunter All Devin matcher and investigation phases
```

The direct script establishes a `RepositoryWorkspace` that resolves the target and rejects output/cache paths inside it. The workspace reads Git metadata with non-mutating commands only. `FileInventoryBuilder` performs one `os.walk`, rejects symlinks, hashes each read file, records skips, and passes the in-memory text to the composed per-file analyzer before discarding it.

The per-file analyzer applies path, content, dependency, carrier, negative-evidence, logic-target, and unsupported-construct detectors during that one read. It stores only bounded evidence metadata—not complete source contents—and can reuse content-addressed results for unchanged files. The aggregate layer then builds the capability profile and carrier inventory.

Applicability has four fail-closed outcomes: always-applicable, applicable, N/A with negative evidence, or unresolved. Always-applicable classes cannot enter the N/A branch. Carrier absence can produce N/A only after all configured searches finish with no evidence; relevant skips or unsupported constructs force unresolved. Prompt/instruction content is explicitly an LLM and Agentic carrier. CI workflows are explicitly Hydra carriers. Class 58 is an explicit downstream-aggregation handoff and is not implemented as Phase 1 triage.

Matcher generation emits broad specifications tagged by exact class number and OWASP mapping. Absence classes use control-location matchers. Non-source files, prompt/instruction carriers, Hydra checks 22–27, and Mobile M1–M10 receive explicit specifications. Business-sensitive operations are separately enumerated for the mandatory Hunter All logic pass; no vulnerability conclusion is attached.

Coverage checks enforce the output contract before atomic writes. Any missing applicable matcher/target, absent control-location matcher, skipped relevant file, unsupported construct, unmodeled carrier, unenumerable dynamic route, or unresolved applicability becomes a first-class gap. COMPLETE describes only deterministic preparation coverage.

No component executes target content, accesses a service, calls a model, installs dependencies, builds the target, writes to the target, or implements the later Hunter All phases.
