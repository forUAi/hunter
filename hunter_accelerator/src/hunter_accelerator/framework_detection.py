"""Conservative framework indicators from paths, source text, and manifests."""

from __future__ import annotations

import re

FRAMEWORK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern, re.IGNORECASE))
    for name, pattern in (
        ("Spring", r"org\.springframework|spring-boot|@RestController|@Controller"),
        ("Spring WebFlux", r"spring-webflux|spring-boot-starter-webflux|RouterFunction|WebClient"),
        ("Vert.x", r"io\.vertx|vertx-web|Router\.router"),
        ("Django", r"\bdjango\b|from django"),
        ("Flask", r"\bflask\b|@app\.route"),
        ("FastAPI", r"\bfastapi\b|@(?:app|router)\.(?:get|post|put|patch|delete)"),
        ("Express", r"\bexpress\b|express\(\)"),
        ("NestJS", r"@nestjs|@Controller\("),
        ("ASP.NET", r"Microsoft\.AspNetCore|\[ApiController\]|MapGet\("),
        ("Rails", r"Rails\.application|ActionController|before_action"),
        ("React", r"\breact\b|from ['\"]react['\"]"),
        ("Angular", r"@angular/|@Component\("),
        ("GraphQL", r"\bgraphql\b|@GraphQL|type Query"),
        ("React Native", r"react-native"),
        ("Flutter", r"\bflutter\b|package:flutter"),
    )
)


def detect_frameworks(text: str) -> tuple[str, ...]:
    return tuple(sorted(name for name, pattern in FRAMEWORK_PATTERNS if pattern.search(text)))
