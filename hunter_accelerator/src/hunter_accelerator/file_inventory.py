"""Single-walk, streaming, auditable repository inventory."""

from __future__ import annotations

import os
import stat as stat_module
from collections.abc import Callable
from pathlib import Path, PurePosixPath

from .framework_detection import detect_frameworks
from .hashing import sha256_bytes, stable_json_hash
from .ignore_rules import ignored_directory_reason
from .language_detection import SOURCE_EXTENSIONS, detect_languages
from .models import FileRecord, SkippedEntry
from .workspace import RepositoryWorkspace

CONFIG_EXTENSIONS = frozenset({".properties", ".yml", ".yaml", ".env", ".ini", ".toml", ".json", ".conf", ".xml"})
SECRET_MATERIAL_EXTENSIONS = frozenset({".pem", ".crt", ".cer", ".key", ".p12", ".pfx", ".jks"})
DEPENDENCY_NAMES = frozenset(
    {
        "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
        "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
        "requirements.txt", "pyproject.toml", "poetry.lock", "pipfile", "pipfile.lock", "go.mod", "go.sum",
        "cargo.toml", "cargo.lock", "build.sbt", "plugins.sbt", "gemfile", "gemfile.lock", "podfile",
        "podfile.lock", "packages.lock.json", "nuget.config", "pubspec.yaml", "pubspec.lock",
    }
)
BINARY_EXTENSIONS = frozenset({".apk", ".ipa", ".aab", ".jar", ".war", ".dll", ".exe", ".so", ".dylib", ".class"})


def _path_flags(relative_path: str) -> dict[str, bool]:
    path = PurePosixPath(relative_path)
    lower = relative_path.lower()
    name = path.name
    lower_name = name.lower()
    extension = path.suffix.lower()
    parts = {part.lower() for part in path.parts}
    dependency = lower_name in DEPENDENCY_NAMES or extension in {".csproj", ".fsproj", ".vbproj"}
    ci_cd = (
        lower.startswith(".github/workflows/")
        or lower_name.startswith("jenkinsfile")
        or lower_name in {".gitlab-ci.yml", "azure-pipelines.yml"}
        or lower == ".circleci/config.yml"
    )
    helm = "helm" in parts or "charts" in parts or lower_name in {"chart.yaml", "kustomization.yaml"}
    kubernetes = bool(parts & {"k8s", "kubernetes", "manifests", "deploy"}) and extension in {".yaml", ".yml"}
    container_iac = (
        lower_name.startswith("dockerfile")
        or lower_name.startswith("containerfile")
        or lower_name.startswith("docker-compose")
        or lower_name == "compose.yaml"
        or extension in {".tf", ".bicep"}
        or helm
        or kubernetes
        or ci_cd
    )
    prompt = (
        name == "SKILL.md"
        or lower_name == ".cursorrules"
        or extension == ".prompt"
        or "prompt" in lower_name
        or (extension in {".json", ".yaml", ".yml"} and any(token in lower_name for token in ("tool", "function", "mcp", "agent")))
    )
    mobile = (
        lower_name == "androidmanifest.xml"
        or extension in {".plist", ".entitlements", ".apk", ".ipa", ".aab", ".swift", ".m", ".mm"}
        or lower_name == "podfile"
        or "android" in parts
        or lower_name == "pubspec.yaml"
    )
    configuration = extension in CONFIG_EXTENSIONS or lower_name in {".env", "procfile", "manifest.yml", ".gitlab-ci.yml"}
    source_code = extension in SOURCE_EXTENSIONS
    test = bool(parts & {"test", "tests", "spec", "specs", "fixture", "fixtures", "__tests__"}) or lower_name.startswith("test_")
    generated = bool(parts & {"generated", "gen", "dist", "target", "coverage"}) or ".min." in lower_name
    security_relevant = any((configuration, source_code, prompt, ci_cd, container_iac, mobile, dependency)) or extension in SECRET_MATERIAL_EXTENSIONS
    return {
        "configuration": configuration,
        "source_code": source_code,
        "prompt_content": prompt,
        "ci_cd": ci_cd,
        "container_iac": container_iac,
        "mobile": mobile,
        "dependency_manifest": dependency,
        "test": test,
        "generated": generated,
        "security_relevant": security_relevant,
    }


def _carrier_hints(flags: dict[str, bool], relative_path: str) -> tuple[str, ...]:
    """Infer conservative carrier types for a file that could not be read."""
    path = PurePosixPath(relative_path)
    lower = relative_path.lower()
    lower_name = path.name.lower()
    extension = path.suffix.lower()
    hints: set[str] = set()
    if flags["source_code"]:
        hints.add("source code")
    if flags["configuration"]:
        hints.update({"configuration", "secret-bearing configuration"})
    if flags["ci_cd"]:
        hints.update({"CI/CD", "Hydra buildpack"})
    if flags["container_iac"]:
        hints.add("container")
    if extension in {".tf", ".bicep"}:
        hints.add("Terraform/IaC")
    if "helm" in lower or "charts" in lower:
        hints.add("Helm")
    if any(part in {"k8s", "kubernetes", "manifests", "deploy"} for part in path.parts):
        hints.add("Kubernetes")
    if flags["mobile"]:
        hints.add("binary mobile" if extension in {".apk", ".ipa", ".aab"} else "mobile")
    if flags["prompt_content"]:
        hints.update({"prompt or instruction", "agent tool", "MCP"})
    if flags["dependency_manifest"]:
        hints.add("dependency manifest")
    if extension in SECRET_MATERIAL_EXTENSIONS:
        hints.add("certificate or key material")
    if lower_name in {"license", "license.md", "license.txt", "copying"}:
        hints.add("license")
    return tuple(sorted(hints))


class FileInventoryBuilder:
    def __init__(self, workspace: RepositoryWorkspace, max_file_size: int, max_total_bytes: int) -> None:
        self.workspace = workspace
        self.max_file_size = max_file_size
        self.max_total_bytes = max_total_bytes
        self.records: list[FileRecord] = []
        self.skipped: list[SkippedEntry] = []
        self.bytes_scanned = 0
        self.walk_count = 0

    def _record_directory_skip(
        self,
        path: Path,
        relative: str,
        reason: str,
        security_relevant_override: bool | None = None,
    ) -> None:
        flags = _path_flags(relative)
        security_relevant = flags["security_relevant"] if security_relevant_override is None else security_relevant_override
        self.skipped.append(
            SkippedEntry(
                relative,
                "directory",
                reason,
                security_relevant,
                carrier_hints=() if security_relevant_override else _carrier_hints(flags, relative),
            )
        )

    def scan(self, processor: Callable[[FileRecord, str | None], None]) -> tuple[list[FileRecord], list[SkippedEntry]]:
        if self.walk_count:
            raise RuntimeError("repository inventory may only be walked once")
        self.walk_count += 1
        root = self.workspace.root
        def on_walk_error(error: OSError) -> None:
            filename = Path(error.filename) if error.filename else root
            try:
                relative = filename.relative_to(root).as_posix()
            except ValueError:
                relative = "<outside-target>"
            self.skipped.append(
                SkippedEntry(relative, "directory", "directory traversal failed", True, carrier_hints=())
            )

        for current, directory_names, file_names in os.walk(
            root,
            topdown=True,
            onerror=on_walk_error,
            followlinks=False,
        ):
            current_path = Path(current)
            kept_directories: list[str] = []
            for directory_name in sorted(directory_names):
                path = current_path / directory_name
                relative = path.relative_to(root).as_posix()
                if path.is_symlink():
                    try:
                        target = path.resolve(strict=True)
                        escaped = not target.is_relative_to(root)
                    except OSError:
                        escaped = True
                    reason = "symlink directory escapes target repository" if escaped else "symlink directory not followed"
                    self._record_directory_skip(path, relative, reason, security_relevant_override=True)
                    continue
                ignored = ignored_directory_reason(directory_name)
                if ignored:
                    self._record_directory_skip(path, relative, ignored)
                    continue
                kept_directories.append(directory_name)
            directory_names[:] = kept_directories
            for file_name in sorted(file_names):
                path = current_path / file_name
                relative = path.relative_to(root).as_posix()
                flags = _path_flags(relative)
                try:
                    stat = path.lstat()
                except OSError:
                    self.skipped.append(
                        SkippedEntry(
                            relative,
                            "file",
                            "metadata read failed",
                            flags["security_relevant"],
                            carrier_hints=_carrier_hints(flags, relative),
                        )
                    )
                    continue
                if path.is_symlink():
                    try:
                        target = path.resolve(strict=True)
                        escaped = not target.is_relative_to(root)
                    except OSError:
                        escaped = True
                    reason = "symlink file escapes target repository" if escaped else "symlink file not followed"
                    self.skipped.append(
                        SkippedEntry(
                            relative,
                            "file",
                            reason,
                            flags["security_relevant"],
                            stat.st_size,
                            _carrier_hints(flags, relative),
                        )
                    )
                    continue
                if not path.is_file():
                    self.skipped.append(
                        SkippedEntry(
                            relative,
                            "file",
                            "not a regular file",
                            flags["security_relevant"],
                            stat.st_size,
                            _carrier_hints(flags, relative),
                        )
                    )
                    continue
                if stat.st_size > self.max_file_size:
                    self.skipped.append(
                        SkippedEntry(
                            relative,
                            "file",
                            "file exceeds max-file-size",
                            flags["security_relevant"],
                            stat.st_size,
                            _carrier_hints(flags, relative),
                        )
                    )
                    continue
                if self.bytes_scanned + stat.st_size > self.max_total_bytes:
                    self.skipped.append(
                        SkippedEntry(
                            relative,
                            "file",
                            "scan exceeds max-total-bytes",
                            flags["security_relevant"],
                            stat.st_size,
                            _carrier_hints(flags, relative),
                        )
                    )
                    continue
                descriptor: int | None = None
                try:
                    open_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                    descriptor = os.open(path, open_flags)
                    opened_stat = os.fstat(descriptor)
                    if not stat_module.S_ISREG(opened_stat.st_mode):
                        raise OSError("opened path is not a regular file")
                    if opened_stat.st_size > self.max_file_size:
                        raise OverflowError("file exceeds max-file-size")
                    if self.bytes_scanned + opened_stat.st_size > self.max_total_bytes:
                        raise MemoryError("scan exceeds max-total-bytes")
                    with os.fdopen(descriptor, "rb") as handle:
                        descriptor = None
                        data = handle.read(self.max_file_size + 1)
                    if len(data) > self.max_file_size:
                        raise OverflowError("file exceeds max-file-size")
                    if self.bytes_scanned + len(data) > self.max_total_bytes:
                        raise MemoryError("scan exceeds max-total-bytes")
                except (OSError, OverflowError, MemoryError) as exc:
                    if descriptor is not None:
                        os.close(descriptor)
                    reason = (
                        str(exc)
                        if isinstance(exc, (OverflowError, MemoryError))
                        else "content read failed or path changed during read"
                    )
                    self.skipped.append(
                        SkippedEntry(
                            relative,
                            "file",
                            reason,
                            flags["security_relevant"],
                            stat.st_size,
                            _carrier_hints(flags, relative),
                        )
                    )
                    continue
                self.bytes_scanned += len(data)
                extension = PurePosixPath(relative).suffix.lower()
                binary = b"\x00" in data[:8192] or extension in BINARY_EXTENSIONS
                text: str | None = None
                encoding_errors = 0
                line_count = 0
                frameworks: tuple[str, ...] = ()
                if not binary:
                    text = data.decode("utf-8", errors="replace")
                    encoding_errors = text.count("\ufffd")
                    line_count = text.count("\n") + (1 if text else 0)
                    frameworks = detect_frameworks(text)
                record = FileRecord(
                    relative_path=relative,
                    extension=extension,
                    size=len(data),
                    content_hash=sha256_bytes(data),
                    binary=binary,
                    generated=flags["generated"],
                    test=flags["test"],
                    configuration=flags["configuration"],
                    source_code=flags["source_code"],
                    prompt_content=flags["prompt_content"],
                    ci_cd=flags["ci_cd"],
                    container_iac=flags["container_iac"],
                    mobile=flags["mobile"],
                    dependency_manifest=flags["dependency_manifest"],
                    security_relevant=flags["security_relevant"],
                    language_hints=detect_languages(relative),
                    framework_hints=frameworks,
                    line_count=line_count,
                    encoding_errors=encoding_errors,
                )
                self.records.append(record)
                processor(record, text)
        self.records.sort(key=lambda item: item.relative_path)
        self.skipped.sort(key=lambda item: (item.relative_path, item.entry_type, item.reason))
        return self.records, self.skipped

    @property
    def manifest_hash(self) -> str:
        return stable_json_hash([record.as_json() for record in self.records])
