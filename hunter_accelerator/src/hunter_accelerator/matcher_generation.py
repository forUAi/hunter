"""Mandatory matcher specifications; these are deterministic leads, never findings."""

from __future__ import annotations

import re
from typing import Any

from .hashing import stable_id
from .models import TaxonomyBundle

ABSENCE_LOCATORS: dict[int, tuple[str, tuple[str, ...]]] = {
    10: (r"@(Get|Post|Put|Patch|Delete|Request)Mapping|\b(router|app)\.(get|post|put|patch|delete)|Map(Get|Post|Put|Patch|Delete)", ("endpoint", "authorization config")),
    18: (r"@(Post|Put|Patch|Delete)Mapping|\b(router|app)\.(post|put|patch|delete)|Map(Post|Put|Patch|Delete)", ("state-changing endpoint", "security config")),
    20: (r"SecurityFilterChain|HttpSecurity|helmet|headers|nginx|server\s*\{|response", ("web response", "security header config")),
    27: (r"@(Get|Post|Put|Patch|Delete|Request)Mapping|\b(router|app)\.(get|post|put|patch|delete)|SecurityFilterChain|permitAll", ("protected endpoint", "authentication config")),
    32: (r"WebSocket|@ServerEndpoint|socket\.io|Upgrade:\s*websocket|\bws://", ("WebSocket upgrade",)),
    35: (r"login|authenticate|authorize|payment|transfer|admin|role|permission|@(Post|Put|Patch|Delete)Mapping", ("security-sensitive operation",)),
    40: (r"SecurityFilterChain|HttpSecurity|helmet|headers|nginx|server\s*\{|<html", ("web response", "security header config")),
    48: (r"login|authenticate|password|otp|search|export|upload|@(Get|Post|Put|Patch|Delete)Mapping", ("authentication or expensive endpoint",)),
    59: (r"FROM|RUN|COPY|ADD|USER|image:|kind:\s*(Deployment|Pod|StatefulSet|DaemonSet|Job|CronJob)|docker\s+(build|push)|builder_image", ("container build or orchestration carrier",)),
    60: (r"resource\s+[\"']|AWS::|kind:\s*(Deployment|Service|Role|ClusterRole)|Microsoft\.Resources|serverless", ("infrastructure definition",)),
    62: (r"securityContext|privileged|hostNetwork|NetworkPolicy|RoleBinding|ClusterRole|iam|bucket|serverless", ("cloud or orchestration control location",)),
    84: (r"tool_call|invoke_tool|dispatch|execute|shell|filesystem|network|delete|deploy|payment|transfer|auto_approve", ("high-impact agent action",)),
}

CARRIER_GLOBS: dict[str, tuple[str, ...]] = {
    "configuration": ("**/*.properties", "**/*.yml", "**/*.yaml", "**/*.env", "**/*.ini", "**/*.toml", "**/*.json", "**/*.conf"),
    "secret-bearing configuration": ("**/*.properties", "**/*.yml", "**/*.yaml", "**/*.env", "**/*.ini", "**/*.toml", "**/*.json", "**/*.conf"),
    "CI/CD": ("**/Jenkinsfile*", "**/.github/workflows/*", "**/.gitlab-ci.yml", "**/.circleci/config.yml", "**/azure-pipelines.yml"),
    "container CI/CD": ("**/Jenkinsfile*", "**/.github/workflows/*", "**/.gitlab-ci.yml"),
    "container": ("**/Dockerfile*", "**/Containerfile*", "**/docker-compose*", "**/compose.yaml", "**/*.yml", "**/*.yaml"),
    "Kubernetes": ("**/k8s/**/*.yml", "**/k8s/**/*.yaml", "**/kubernetes/**/*.yml", "**/kubernetes/**/*.yaml", "**/manifests/**/*.yml", "**/manifests/**/*.yaml"),
    "Helm": ("**/Chart.yaml", "**/values*.yaml", "**/templates/**/*.yaml", "**/kustomization.yaml"),
    "Terraform/IaC": ("**/*.tf", "**/*.bicep", "**/*.json"),
    "cloud configuration": ("**/*.tf", "**/*.bicep", "**/*.json", "**/*.yml", "**/*.yaml"),
    "dependency manifest": ("**/pom.xml", "**/build.gradle*", "**/package-lock.json", "**/go.mod", "**/go.sum", "**/requirements.txt", "**/*.csproj", "**/Gemfile.lock"),
    "prompt or instruction": ("**/SKILL.md", "**/*.prompt", "**/*prompt*.md", "**/*prompt*.txt", "**/*prompt*.yml", "**/*prompt*.yaml", "**/*prompt*.json", "**/.cursorrules"),
    "agent tool": ("**/SKILL.md", "**/*tool*.json", "**/*function*.json", "**/*agent*.json"),
    "MCP": ("**/*mcp*.json", "**/*mcp*.yml", "**/*mcp*.yaml", "**/SKILL.md"),
    "Hydra buildpack": ("**/Jenkinsfile*", "**/.github/workflows/*", "**/.gitlab-ci.yml", "**/*buildpack*"),
    "mobile": ("**/AndroidManifest.xml", "**/*.plist", "**/*.entitlements", "**/Podfile", "**/build.gradle*", "**/*.java", "**/*.kt", "**/*.swift", "**/*.m", "**/*.mm", "**/pubspec.yaml", "**/package.json"),
    "binary mobile": ("**/*.apk", "**/*.ipa", "**/*.aab"),
    "certificate or key material": ("**/*.pem", "**/*.crt", "**/*.key", "**/*.p12", "**/*.jks"),
}

MAST_PATTERNS: dict[str, str] = {
    "M1": r"password|secret|token|api[_-]?key|SharedPreferences|Keychain|oauth|refresh_token",
    "M2": r"Podfile|build\.gradle|package\.json|pubspec\.yaml|dependency|integrity|signature",
    "M3": r"biometric|authenticate|authorization|session|permitAll|exported",
    "M4": r"intent|deep.?link|WebView|loadUrl|rawQuery|SQLite|input|output",
    "M5": r"cleartextTrafficPermitted|NSAllowsArbitraryLoads|TrustManager|hostnameVerifier|http://|pinning",
    "M6": r"uses-permission|privacy|consent|tracking|ATT|data collection",
    "M7": r"debuggable|obfuscat|minifyEnabled|root|jailbreak|debug symbol",
    "M8": r"android:exported|allowBackup|minSdk|debuggable|entitlement|permission",
    "M9": r"SharedPreferences|UserDefaults|Keychain|clipboard|external storage|logger|console\.log",
    "M10": r"MD5|SHA-?1|ECB|hardcoded|Cipher|RSA|AES|IV|key length",
}

HYDRA_PATTERNS: dict[int, str] = {
    22: r"builder_image|paas-registry/buildpacks/|rhel-|alpine-|ubi\d+-builder|ace-|ibm-business-automation|shell-pack",
    23: r"builder_image|buildpack|deploy|last[_-]?deploy|updated_at|schedule",
    24: r"(docker\.io|ghcr\.io|quay\.io|gcr\.io|artifactory\.aexp\.com)/|builder_image",
    25: r"DEBUG_FLAG",
    26: r"certificate|cert|ca-bundle|keytool|openssl|COPY\s+.*\.(crt|pem)|shell-pack",
    27: r"BYOI|bring.your.own.image|FROM|builder_image|artifactory\.aexp\.com",
}


def _literal_regex(values: list[str]) -> str:
    usable = [value for value in values if value and value != ".git history availability"]
    return "(?i)(?:" + "|".join(re.escape(value) for value in usable) + ")" if usable else r"(?!)"


def _globs_for(item: dict[str, Any]) -> list[str]:
    globs = {str(value) for value in item["target_file_globs"]}
    for carrier in item["carriers"]:
        globs.update(CARRIER_GLOBS.get(str(carrier), ()))
    if 66 <= int(item["class_number"]) <= 85:
        for carrier in ("prompt or instruction", "agent tool", "MCP"):
            globs.update(CARRIER_GLOBS[carrier])
    return sorted(globs)


def generate_matchers(taxonomy: TaxonomyBundle, decisions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_number = taxonomy.by_number
    matchers: list[dict[str, Any]] = []

    def add(number: int, family: str, regex: str, globs: list[str], kind: str, evidence: list[str], **extra: Any) -> None:
        item = by_number[number]
        matcher = {
            "matcher_id": stable_id("matcher", number, family, regex, *globs, length=24),
            "class_number": number,
            "class_name": item["class_name"],
            "owasp": item["owasp"],
            "file_globs": globs,
            "regex": regex,
            "description": item["signal_descriptions"][0],
            "matcher_family": family,
            "matcher_kind": kind,
            "absence_detection": bool(item["absence_class"]),
            "source": "hunter-accelerator",
            "mandatory": True,
            "evidence_basis": evidence[:20],
            "is_finding": False,
            "pre_filter_hint": {
                "tag_commented_out_regions": True,
                "tag_generated_files": True,
                "tag_test_files": True,
                "suppress_automatically": False,
            },
            "downstream_action": "Investigate under the unmodified Hunter All evidence, reachability and mitigation requirements.",
        }
        matcher.update(extra)
        # Refuse to emit a malformed matcher specification.
        re.compile(regex)
        matchers.append(matcher)

    for decision in decisions:
        if decision["status"] not in {"ALWAYS_APPLICABLE", "APPLICABLE"}:
            continue
        number = int(decision["class_number"])
        if number == 58:
            continue
        item = by_number[number]
        evidence = [
            str(value.get("evidence_id"))
            if value.get("evidence_id")
            else f"{value['carrier_type']} at {value['file']}" + (f":{value['line']}" if value["line"] else "")
            for value in decision["positive_matches"]
        ] or ["Hunter All always-applicable requirement"]
        globs = _globs_for(item)
        if number in taxonomy.absence_classes:
            locator, locations = ABSENCE_LOCATORS[number]
            add(number, item["mandatory_matcher_families"][0], f"(?i)(?:{locator})", globs, "CONTROL_LOCATION", evidence, control_should_exist_at=list(locations))
        else:
            for family in item["mandatory_matcher_families"]:
                add(number, str(family), _literal_regex(item["negative_evidence_searches"]), globs, "SIGNAL", evidence)

        if number == 64:
            for mast in taxonomy.carrier_rules["mobile"]["mast"]:
                mast_id = str(mast["id"])
                add(number, f"mobile-{mast_id.lower()}", f"(?i)(?:{MAST_PATTERNS[mast_id]})", globs, "MOBILE_CONTROL_LOCATION", evidence, mobile_category=mast)
        if number == 63:
            for check_id, pattern in HYDRA_PATTERNS.items():
                add(number, f"hydra-check-{check_id}", f"(?i)(?:{pattern})", globs, "HYDRA_CONTROL_LOCATION", evidence, hydra_check_id=check_id)

    matchers.sort(key=lambda value: (value["class_number"], value["matcher_family"], value["matcher_id"]))
    return matchers
