"""Recall-oriented business-logic target enumeration without vulnerability decisions."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .hashing import stable_id
from .models import FileRecord, LogicTarget

LOGIC_REVIEW_CLASSES = (10, 11, 12, 14, 49, 50, 55, 56, 57)
QUESTIONS = (
    "Is authorization enforced before the operation and scoped to the object/action?",
    "Is ownership or tenancy verified for every client-provided resource identifier?",
    "Can a client set or derive a role or permission?",
    "Are amount, limit, state, role, account and other business fields validated server-side?",
    "Can the operation race, execute twice or bypass idempotency?",
    "Is the financial or security-sensitive operation audited with tamper resistance?",
    "Are related state, ledger and audit writes atomic and consistency-preserving?",
    "Does every exception, invalid-input and downstream-failure path fail closed?",
)

SIGNALS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern, re.IGNORECASE))
    for name, pattern in (
        ("state-changing endpoint", r"@(Post|Put|Patch|Delete|Request)Mapping\b|\b(router|app)\.(post|put|patch|delete)\b|Map(Post|Put|Patch|Delete)\b|HttpMethod\.(POST|PUT|PATCH|DELETE)"),
        ("state mutation", r"\b(save|update|delete|remove|create|insert|persist|merge|commit|write|mutate|set[A-Z]\w*)\s*\("),
        ("money, amount, balance, payment or transfer operation", r"\b(amount|balance|payment|transfer|capture|refund|charge|debit|credit|price|total|currency|account)\b"),
        ("resource lookup by client-provided ID", r"findById|getById|params\.id|pathVariable|@PathVariable|request\.getParameter\s*\([^)]*id|\b(id|.*Id)\s*[,)]"),
        ("ownership or tenancy boundary", r"\b(owner|ownership|tenant|tenancy|accountId|customerId|organizationId|orgId)\b"),
        ("role or permission mutation", r"setRole|setPermission|\b(role|permission|isAdmin)\s*="),
        ("multi-step workflow or state machine", r"\b(workflow|stateMachine|transition|nextState|storyStack|saga|step\w*)\b"),
        ("retry or idempotency-sensitive operation", r"\b(retry|idempoten|deduplicat|requestId|operationId|compareAndSet)\b"),
        ("shared mutable state", r"\bstatic\s+(?!final\b)|singleton|sharedState|ConcurrentHashMap|SimpleDateFormat"),
        ("audit or ledger write", r"\b(audit\w*|ledger\w*|history|eventLog|securityEvent)\b.*\b(save|write|append|record|publish|insert)\b|\b(save|write|append|record|publish|insert)\w*\b.*\b(audit\w*|ledger\w*)\b"),
        ("transaction boundary", r"@Transactional\b|\b(transaction|beginTransaction|commit|rollback|UnitOfWork)\b"),
        ("exception or fallback path", r"\bcatch\s*\(|\bexcept\b|\brescue\b|onErrorResume|fallback|recover\s*\(|return\s+(true|null|empty)\s*;?\s*(//.*)?$"),
    )
)

DECLARATION_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        r"\b(?:public|protected|private|internal|static|async|suspend|final|override|virtual|abstract|synchronized|def|func|fun)\s+(?:[\w<>,.?\[\] ]+\s+)?(?P<name>[A-Za-z_$][\w$]*)\s*\(",
        r"\b(?:def|async\s+def)\s+(?P<name>[A-Za-z_]\w*)\s*\(",
        r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>",
        r"\b(?P<name>[A-Za-z_$][\w$]*)\s*:\s*(?:async\s*)?function\s*\(",
        r"^\s*(?:[A-Za-z_$][\w$<>,.?\[\]]*\s+)+(?P<name>[A-Za-z_$][\w$]*)\s*\(",
    )
)


@dataclass
class _TargetAccumulator:
    symbol: str
    line_start: int
    line_end: int
    signals: set[str] = field(default_factory=set)


def _symbol_from_line(line: str) -> str | None:
    for pattern in DECLARATION_PATTERNS:
        match = pattern.search(line)
        if match:
            name = str(match.group("name"))
            if name not in {"if", "for", "while", "switch", "catch", "return", "new"}:
                return name
    return None


def enumerate_logic_targets(record: FileRecord, text: str | None) -> tuple[LogicTarget, ...]:
    if text is None or not record.source_code:
        return ()
    lines = text.splitlines()
    current_symbol = "<module>"
    current_start = 1
    pending_route_signals: set[str] = set()
    targets: dict[tuple[str, int], _TargetAccumulator] = {}

    for index, line in enumerate(lines, start=1):
        line_signals = {name for name, pattern in SIGNALS if pattern.search(line)}
        declared_symbol = _symbol_from_line(line)
        route_match = re.search(
            r"\b(?:app|router)\.(post|put|patch|delete)\s*\(\s*[\"']([^\"']+)",
            line,
            re.IGNORECASE,
        )
        if route_match:
            declared_symbol = f"{route_match.group(1).upper()} {route_match.group(2)}"
        if declared_symbol:
            current_symbol = declared_symbol
            current_start = index
            line_signals.update(pending_route_signals)
            pending_route_signals.clear()
        elif line_signals and line.lstrip().startswith("@"):
            pending_route_signals.update(line_signals)
            continue
        if not line_signals:
            continue
        key = (current_symbol, current_start)
        target = targets.setdefault(
            key,
            _TargetAccumulator(
                symbol=current_symbol,
                line_start=max(1, current_start),
                line_end=min(len(lines), index + 5),
            ),
        )
        target.line_end = min(len(lines), max(target.line_end, index + 5))
        target.signals.update(line_signals)

    results: list[LogicTarget] = []
    for (_symbol, _start), target in sorted(targets.items(), key=lambda item: (item[1].line_start, item[1].symbol)):
        signals = tuple(sorted(target.signals))
        results.append(
            LogicTarget(
                target_id=stable_id(
                    "logic-target",
                    record.relative_path,
                    target.line_start,
                    target.symbol,
                    *signals,
                    length=20,
                ),
                file=record.relative_path,
                line_start=target.line_start,
                line_end=target.line_end,
                symbol=target.symbol,
                activated_classes=LOGIC_REVIEW_CLASSES,
                signals=signals,
                questions_for_devin=QUESTIONS,
                confidence="HIGH" if "state-changing endpoint" in target.signals else "MEDIUM",
            )
        )
    return tuple(results)
