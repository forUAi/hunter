# Existing implementation reuse audit

The managed-session workflow is additive. It imports the following verified accelerator components through adapters instead of copying their implementation:

| Existing component | Managed use |
|---|---|
| `hunter_accelerator.workspace.RepositoryWorkspace` | Resolve the exact target, inspect Git metadata with constrained read-only commands, and establish immutability snapshots. |
| `hunter_accelerator.file_inventory.FileInventoryBuilder` and `FileRecord` | Single-walk inventory, hashing, binary/text handling, generated/vendor/test classification, and explicit skipped-file records. |
| `hunter_accelerator.analyzer.FileAnalyzer` and `AnalysisAccumulator` | Compose capability, carrier, negative-evidence, matcher-lead, logic-target, and unsupported-construct preparation once per file. |
| `hunter_accelerator.carrier_detection.CarrierDetector` | Deterministic carrier leads. Managed coverage applies a stricter class-specific activation filter and never treats generic source presence as sufficient. |
| `hunter_accelerator.dependency_detection.detect_capabilities` | Technology and security-capability hints. |
| `hunter_accelerator.matcher_generation.generate_matchers` | Bounded matcher specifications supplied as leads; their existence never requires execution and never creates a finding. |
| `hunter_accelerator.logic_targets.enumerate_logic_targets` | Business-logic target leads that must receive a child owner. |
| `hunter_accelerator.negative_evidence.NegativeEvidenceSearcher` | Class-specific deterministic searches whose absence must still be reviewed by the coverage-audit child. |
| `hunter_accelerator.taxonomy.load_and_validate_taxonomy` | The single authoritative 85-class taxonomy source and startup validation. No second taxonomy is created. |
| `hunter_accelerator.hashing` | Stable identifiers and SHA-256 hashing. |
| `hunter_accelerator.evidence.redact_text` | Bounded redaction for logs and diagnostics. |
| `hunter_accelerator.output` | Deterministic ordering and atomic-write design reference. |

The existing repository has no runtime-validation orchestration, managed-session gateway, child artifact schemas, excerpt verifier, CVSS calculator, exact-duplicate/root-cause handling, Critic application, or final completion gate. Those responsibilities are implemented only under `hunter_managed_scan/` and do not change existing accelerator commands or behavior.

The canonical taxonomy remains `hunter_accelerator/taxonomy/hunter_all_85.json` with its adjacent rule files.
