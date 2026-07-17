"""Deterministic carrier discovery over each file during the single inventory read."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from .evidence import indicator_evidence
from .models import CarrierEvidence, FileRecord, TaxonomyBundle

CONTENT_CARRIERS: tuple[tuple[str, str, re.Pattern[str]], ...] = tuple(
    (carrier, label, re.compile(pattern, re.IGNORECASE | re.MULTILINE))
    for carrier, label, pattern in (
        ("HTTP/API route", "HTTP route/controller", r"@(Get|Post|Put|Patch|Delete|Request)Mapping\b|\b(app|router)\.(get|post|put|patch|delete)\b|Map(Get|Post|Put|Patch|Delete)\b|\.route\s*\("),
        ("database/data-access", "database or ORM call", r"createNativeQuery|jdbcTemplate|cluster\.query|findById|repository\.(save|find|delete)|cursor\.execute|sequelize|knex\.|mongoose|EntityManager|DbContext|SQLAlchemy"),
        ("outbound HTTP", "outbound HTTP client", r"RestTemplate|WebClient|HttpClient|OkHttp|URLConnection|\baxios\b|\bfetch\s*\(|\brequests\.(get|post|put|delete)|http\.Get\s*\("),
        ("file/archive", "file, upload, or archive operation", r"MultipartFile|IFormFile|File(Input|Output)Stream|Paths\.get|new\s+File\b|Zip(Input|Output|Entry)|extractall|path\.join|fs\.(read|write|unlink)|upload"),
        ("deserialization", "deserialization or parser", r"ObjectInputStream|readObject\s*\(|pickle\.load|yaml\.load|ObjectMapper\.(readValue|convertValue)|DocumentBuilderFactory|XMLInputFactory|JSON\.parse"),
        ("cryptography", "cryptographic API or algorithm", r"javax\.crypto|java\.security|System\.Security\.Cryptography|\bCipher\b|\bRSA\b|\bECDSA\b|\bECDH\b|\bAES\b|\bSHA-?\d*\b|\bTLSv?\d|ML-KEM|ML-DSA|SLH-DSA|bouncycastle|pycryptodome"),
        ("authentication", "authentication control", r"authenticate|authentication|SecurityFilterChain|passport|login|signIn|permission_required"),
        ("authorization", "authorization control", r"PreAuthorize|RolesAllowed|@Secured|\[Authorize|authorize\b|permission|requireAuth|canActivate|AuthGuard"),
        ("session/JWT/OAuth", "session, JWT, or OAuth", r"\bsession\b|\bcookie\b|\bJWT\b|jsonwebtoken|\bjose\b|oauth|openid|oidc|PKCE|redirect_uri"),
        ("logging", "logging or audit API", r"\blogger\b|\blog\.(debug|info|warn|error)|console\.log|slf4j|log4j|logback|winston|serilog|structlog|\baudit\b"),
        ("cloud SDK", "cloud SDK", r"aws-sdk|boto3|software\.amazon\.awssdk|azure\.identity|google-cloud|com\.google\.cloud"),
        ("cloud configuration", "cloud or serverless configuration", r"provider\s+[\"'](aws|azurerm|google)|AWS::|serverless\.ya?ml|service:\s*[^\n]+\n\s*provider:|kind:\s*(Bucket|Function)"),
        ("LLM SDK", "LLM SDK or framework", r"\bopenai\b|anthropic|bedrock|vertexai|azure-openai|langchain|langgraph|llama[_-]?index|semantic[_-]?kernel|autogen|crewai|\bdspy\b"),
        ("agent tool", "agent or tool definition", r"tool_call|invoke_tool|tool_registry|function_call|@tool\b|create_react_agent|AgentExecutor|CrewAI|autogen|handoff|subagent"),
        ("MCP", "MCP server or client", r"\bmcpServers\b|modelcontextprotocol|MCPServer|MCPClient|\bmcp\b"),
        ("agent memory", "agent memory store", r"agent[_-]?memory|memory\.save|save_context|checkpoint|checkpointer|context_store|conversation_history"),
        ("vector database", "vector or embedding store", r"pinecone|weaviate|chromadb|\bchroma\b|pgvector|faiss|milvus|qdrant|similarity_search|embedding"),
        ("Hydra buildpack", "Hydra buildpack marker", r"builder_image|paas-registry/buildpacks/|amex-eng/buildpacks-(stacks|builders)|amex-eng/shell-pack|DEBUG_FLAG|shell-pack|rhel-(tomcat|nginx|python|nodejs|jdk|jboss|go|dotnet|ruby|process-server)|alpine-(jdk|nodejs|python|dotnet|r42|lite|builder)|ubi(8|9|10)-builder|ace-(python|rpa|jdk)"),
        ("container CI/CD", "container command in CI/CD", r"docker\s+(build|push)|kaniko|buildah|trivy|grype|cosign\s+(sign|verify)|--sbom|--provenance"),
        ("WebSocket", "WebSocket endpoint or upgrade", r"WebSocket|@ServerEndpoint|socket\.io|\bws://|Upgrade:\s*websocket"),
        ("GraphQL", "GraphQL schema or resolver", r"\bgraphql\b|@GraphQL|type\s+(Query|Mutation)|\bResolver\b"),
        ("internal framework", "custom or internal framework marker", r"(?i)internal[-_. ](auth|security|framework)|company[-_. ](auth|security)|custom[-_. ](auth|security)"),
    )
)

SECRET_EXTENSIONS = frozenset({".pem", ".crt", ".cer", ".key", ".p12", ".pfx", ".jks"})
TEMPLATE_EXTENSIONS = frozenset({".html", ".htm", ".jsp", ".ftl", ".hbs", ".mustache", ".jinja", ".jinja2"})


class CarrierDetector:
    def __init__(self, taxonomy: TaxonomyBundle) -> None:
        classes_by_carrier: dict[str, set[int]] = {}
        for item in taxonomy.classes:
            for carrier in item["carriers"]:
                classes_by_carrier.setdefault(str(carrier), set()).add(int(item["class_number"]))
        # Hunter All explicitly treats content/instruction carriers as a surface for all AI classes.
        for carrier in ("prompt or instruction", "agent tool", "MCP"):
            classes_by_carrier.setdefault(carrier, set()).update(range(66, 86))
        classes_by_carrier.setdefault("container CI/CD", set()).add(59)
        classes_by_carrier.setdefault("cloud SDK", set()).update({60, 61, 62})
        self.classes_by_carrier = {
            carrier: tuple(sorted(numbers)) for carrier, numbers in classes_by_carrier.items()
        }

    def _evidence(
        self,
        carrier_type: str,
        file: str,
        line: int | None,
        label: str,
        method: str,
        confidence: str = "HIGH",
    ) -> CarrierEvidence:
        return CarrierEvidence(
            carrier_type=carrier_type,
            file=file,
            line=line,
            classes_activated=self.classes_by_carrier.get(carrier_type, ()),
            evidence=indicator_evidence(label),
            discovery_method=method,
            confidence=confidence,
        )

    @staticmethod
    def _line(text: str, offset: int) -> int:
        return text.count("\n", 0, offset) + 1

    def detect(self, record: FileRecord, text: str | None) -> tuple[CarrierEvidence, ...]:
        path = PurePosixPath(record.relative_path)
        lower = record.relative_path.lower()
        lower_name = path.name.lower()
        extension = path.suffix.lower()
        parts = {part.lower() for part in path.parts}
        results: list[CarrierEvidence] = []

        def add(carrier: str, label: str, method: str = "path", line: int | None = None, confidence: str = "HIGH") -> None:
            results.append(self._evidence(carrier, record.relative_path, line, label, method, confidence))

        if record.source_code:
            add("source code", f"source file {extension or '<none>'}")
        if record.configuration:
            add("configuration", f"configuration file {path.name}")
            add("secret-bearing configuration", f"configuration may carry named secrets: {path.name}")
        if record.dependency_manifest:
            add("dependency manifest", f"dependency manifest {path.name}")
        if record.ci_cd:
            add("CI/CD", f"CI/CD file {record.relative_path}")
            # Hunter All class 63 ground truth: Jenkins/GitHub workflow presence is itself a Hydra carrier.
            if lower_name.startswith("jenkinsfile") or lower.startswith(".github/workflows/"):
                add("Hydra buildpack", f"Hydra carrier workflow {record.relative_path}")
        if record.prompt_content:
            add("prompt or instruction", f"prompt/instruction carrier {path.name}")
            if any(token in lower_name for token in ("tool", "function")):
                add("agent tool", f"tool/function manifest {path.name}")
            if "mcp" in lower_name:
                add("MCP", f"MCP manifest {path.name}")
        if lower_name.startswith(("dockerfile", "containerfile", "docker-compose")) or lower_name == "compose.yaml":
            add("container", f"container definition {path.name}")
        is_helm = "helm" in parts or "charts" in parts or lower_name in {"chart.yaml", "kustomization.yaml"}
        is_kubernetes = bool(parts & {"k8s", "kubernetes", "manifests", "deploy"}) and extension in {".yaml", ".yml"}
        if is_helm:
            add("Helm", f"Helm/Kustomize carrier {record.relative_path}")
            add("container", f"orchestration carrier {record.relative_path}")
        if is_kubernetes:
            add("Kubernetes", f"Kubernetes path carrier {record.relative_path}")
            add("container", f"orchestration carrier {record.relative_path}")
        if extension in {".tf", ".bicep"}:
            add("Terraform/IaC", f"infrastructure definition {path.name}")
            add("cloud configuration", f"infrastructure cloud configuration {path.name}")
        if extension in SECRET_EXTENSIONS:
            add("certificate or key material", f"cryptographic material file {path.name}")
            add("cryptography", f"cryptographic material file {path.name}")
        if extension in TEMPLATE_EXTENSIONS or "templates" in parts:
            add("template", f"template carrier {record.relative_path}")
        if extension in {".graphql", ".gql"}:
            add("GraphQL", f"GraphQL document {path.name}")
        if lower_name in {"license", "license.md", "license.txt", "copying"}:
            add("license", f"license declaration {path.name}")
        if record.mobile:
            add("binary mobile" if record.binary and extension in {".apk", ".ipa", ".aab"} else "mobile", f"mobile carrier {record.relative_path}")

        if text is not None:
            if extension in {".yaml", ".yml"} and re.search(
                r"(?m)^\s*kind:\s*(Deployment|Pod|StatefulSet|DaemonSet|Job|CronJob|ReplicaSet|Role|ClusterRole|RoleBinding|ServiceAccount|NetworkPolicy|PeerAuthentication|DestinationRule|AuthorizationPolicy|VirtualService|Gateway)\b",
                text,
                re.IGNORECASE,
            ):
                add("Kubernetes", "Kubernetes or service-mesh kind", "content")
                add("container", "Kubernetes orchestration object", "content")
            if re.search(r"com\.android\.(application|library)|android\s*\{|react-native|package:flutter", text, re.IGNORECASE):
                add("mobile", "mobile build or framework indicator", "content")
            for carrier, label, pattern in CONTENT_CARRIERS:
                match = pattern.search(text)
                if match and (carrier != "container CI/CD" or record.ci_cd):
                    add(carrier, label, "content", self._line(text, match.start()))

        deduplicated: dict[tuple[str, str, int | None], CarrierEvidence] = {}
        for evidence in results:
            key = (evidence.carrier_type, evidence.file, evidence.line)
            deduplicated.setdefault(key, evidence)
        return tuple(deduplicated[key] for key in sorted(deduplicated, key=lambda item: (item[0], item[1], item[2] or 0)))


def carrier_from_json(value: dict[str, Any]) -> CarrierEvidence:
    return CarrierEvidence(
        carrier_type=str(value["carrier_type"]),
        file=str(value["file"]),
        line=int(value["line"]) if value.get("line") is not None else None,
        classes_activated=tuple(int(item) for item in value.get("classes_activated", [])),
        evidence=str(value.get("evidence", "")),
        discovery_method=str(value.get("discovery_method", "unknown")),
        confidence=str(value.get("confidence", "MEDIUM")),
    )
