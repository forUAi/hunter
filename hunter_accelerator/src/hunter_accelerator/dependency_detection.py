"""Transitive capability indicators from dependency manifests and source text."""

from __future__ import annotations

import re

CAPABILITY_PATTERNS: dict[str, tuple[tuple[str, str], ...]] = {
    "database_technologies": (
        ("Couchbase", r"couchbase"), ("PostgreSQL", r"postgres|pgvector"), ("MySQL", r"mysql"),
        ("MongoDB", r"mongo"), ("Redis", r"redis"), ("DynamoDB", r"dynamodb"), ("SQL Server", r"sqlserver|mssql"),
    ),
    "orms_and_data_clients": (
        ("Hibernate/JPA", r"hibernate|jakarta\.persistence|javax\.persistence"), ("Couchbase SDK", r"couchbase"),
        ("Sequelize", r"sequelize"), ("Knex", r"\bknex\b"), ("Mongoose", r"mongoose"),
        ("Entity Framework", r"entityframework|microsoft\.entityframeworkcore"), ("SQLAlchemy", r"sqlalchemy"),
    ),
    "outbound_http_clients": (
        ("Spring WebClient", r"webclient|spring-webflux"), ("RestTemplate", r"resttemplate"),
        ("OkHttp", r"okhttp"), ("Axios", r"axios"), ("Python requests", r"\brequests\b"),
        ("Go net/http", r"net/http|http\.get"), (".NET HttpClient", r"httpclient"),
    ),
    "authentication_technologies": (
        ("Spring Security", r"spring-security|securityfilterchain"), ("OAuth/OIDC", r"oauth|openid|oidc"),
        ("JWT", r"jsonwebtoken|\bjose\b|\bjwt\b"), ("Passport", r"passport"),
    ),
    "authorization_technologies": (
        ("Spring Method Security", r"preauthorize|rolesallowed|@secured"), ("ASP.NET Authorization", r"\[authorize|iauthorization"),
        ("Django Permissions", r"permission_required"), ("Route Guards", r"requireauth|canactivate|authguard"),
    ),
    "logging_technologies": (
        ("SLF4J/Logback", r"slf4j|logback"), ("Log4j", r"log4j"), ("Winston", r"winston"),
        ("Python logging", r"\bimport logging\b|structlog"), ("Serilog", r"serilog"),
    ),
    "cryptographic_technologies": (
        ("Java Cryptography", r"javax\.crypto|java\.security|bouncycastle"), ("Python cryptography", r"pycryptodome|\bcryptography\b"),
        ("Node crypto", r"node-forge|require\(['\"]crypto|from ['\"]crypto"), (".NET Cryptography", r"system\.security\.cryptography"),
    ),
    "cloud_technologies": (
        ("AWS", r"aws-sdk|boto3|software\.amazon\.awssdk|provider\s+[\"']aws"),
        ("Azure", r"azure-sdk|azure\.identity|provider\s+[\"']azurerm"),
        ("Google Cloud", r"google-cloud|com\.google\.cloud|provider\s+[\"']google"),
    ),
    "llm_technologies": (
        ("OpenAI", r"\bopenai\b|azure-openai"), ("Anthropic", r"anthropic"), ("Bedrock", r"bedrock"),
        ("Vertex AI", r"vertexai|vertex ai"), ("LangChain", r"langchain"), ("LangGraph", r"langgraph"),
        ("LlamaIndex", r"llamaindex|llama_index"), ("Semantic Kernel", r"semantic-kernel|semantic_kernel"),
        ("AutoGen", r"autogen"), ("CrewAI", r"crewai"), ("DSPy", r"\bdspy\b"),
    ),
    "vector_and_embedding_technologies": (
        ("Pinecone", r"pinecone"), ("Weaviate", r"weaviate"), ("Chroma", r"chromadb|\bchroma\b"),
        ("pgvector", r"pgvector"), ("FAISS", r"faiss"), ("Milvus", r"milvus"), ("Qdrant", r"qdrant"),
    ),
    "agent_technologies": (
        ("LangGraph agents", r"langgraph|create_react_agent"), ("AutoGen agents", r"autogen"),
        ("CrewAI agents", r"crewai"), ("Semantic Kernel agents", r"semantic[_-]?kernel"),
        ("MCP", r"modelcontextprotocol|mcpservers|mcpserver|mcpclient"),
    ),
    "file_archive_operations": (
        ("File I/O", r"fileinputstream|fileoutputstream|paths\.get|new\s+file|fs\.(read|write)|open\s*\("),
        ("Archive handling", r"zipentry|zipinputstream|tarfile|extractall|archive"),
        ("File upload", r"multipartfile|iformfile|multer|fileupload|upload"),
    ),
    "internal_framework_indicators": (
        ("Internal authentication", r"internalauth|customauth|companyauth"),
        ("Internal repository", r"internalrepository|customorm|dynamicrepository"),
        ("Internal build", r"custombuild|internalbuild|companybuild"),
    ),
}

COMPILED_CAPABILITIES = {
    key: tuple((name, re.compile(pattern, re.IGNORECASE)) for name, pattern in entries)
    for key, entries in CAPABILITY_PATTERNS.items()
}


def detect_capabilities(text: str) -> dict[str, set[str]]:
    return {
        category: {name for name, pattern in entries if pattern.search(text)}
        for category, entries in COMPILED_CAPABILITIES.items()
    }
