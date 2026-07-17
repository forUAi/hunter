# Phase 1 requirements trace

The supplied Hunter All Code Scan profile is authoritative and remains unmodified. This directory contains its deterministic preparation support only.

| Requirement | Phase 1 implementation |
|---|---|
| Exact classes 1–85 and OWASP mappings | `taxonomy/hunter_all_85.json`; hard-fail startup validation |
| Always-applicable classes | `always_applicable.json`; no N/A branch in applicability |
| Absence classes | `absence_classes.json`; control-location matcher generation |
| Standing logic classes and full logic review | `logic_classes.json`; targets activate 10, 11, 12, 14, 49, 50, 55, 56, 57 |
| Carrier-bound N/A | carrier inventory plus class-specific searches; unresolved on incomplete evidence |
| Negative evidence | class/carrier/pattern/file/match/skip/unsupported evidence in two artifacts |
| Non-source carriers | explicit configuration, CI, container, IaC, manifest, prompt/tool/MCP globs |
| Hydra | workflow/config/source carriers, exact registry/builders, EOL backstop, checks 22–27 |
| Mobile | Android/iOS/RN/Flutter carriers, binary handoff, explicit M1–M10 matcher coverage |
| LLM/Agentic | SDK and content carriers; SKILL/prompt/tool/MCP content activates classes 66–85 |
| Coverage gaps | all specified gap conditions are emitted and prevent COMPLETE |
| Source–sink–path, mitigation, reachability, verbatim evidence | deliberately unchanged downstream Hunter All requirements; not implemented in Phase 1 |
| Investigation, N/A re-audit, triage, validation, reporting | explicit non-goals and fallback handoff |

The conversion is a support artifact, not a rewritten profile. When any machine-readable preparation rule conflicts with the supplied profile, the profile controls and the accelerator must be corrected or ignored under the fallback contract.
