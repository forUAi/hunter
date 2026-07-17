"""Build-system and package-manager inference from repository paths."""

from __future__ import annotations

from pathlib import PurePosixPath


def detect_build(relative_path: str) -> tuple[set[str], set[str]]:
    name = PurePosixPath(relative_path).name.lower()
    builds: set[str] = set()
    managers: set[str] = set()
    if name == "pom.xml":
        builds.add("Maven")
        managers.add("Maven")
    if name in {"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}:
        builds.add("Gradle")
        managers.add("Gradle")
    if name in {"package.json", "package-lock.json", "npm-shrinkwrap.json"}:
        builds.add("npm")
        managers.add("npm")
    if name in {"pnpm-lock.yaml", "pnpm-workspace.yaml"}:
        builds.add("pnpm")
        managers.add("pnpm")
    if name == "yarn.lock":
        builds.add("Yarn")
        managers.add("Yarn")
    if name in {"requirements.txt", "pyproject.toml", "poetry.lock", "pipfile", "pipfile.lock"}:
        builds.add("Python packaging")
        managers.add("Poetry" if "poetry" in name else "pip")
    if name in {"go.mod", "go.sum"}:
        builds.add("Go modules")
        managers.add("Go modules")
    if name == "cargo.toml" or name == "cargo.lock":
        builds.add("Cargo")
        managers.add("Cargo")
    if name.endswith((".csproj", ".fsproj", ".vbproj")) or name in {"packages.lock.json", "nuget.config"}:
        builds.add(".NET")
        managers.add("NuGet")
    if name in {"build.sbt", "plugins.sbt"}:
        builds.add("sbt")
        managers.add("sbt")
    if name in {"gemfile", "gemfile.lock"}:
        builds.add("Bundler")
        managers.add("Bundler")
    return builds, managers
