from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hunter_accelerator.build_detection import detect_build
from hunter_accelerator.file_inventory import FileInventoryBuilder
from hunter_accelerator.workspace import RepositoryWorkspace


class InventoryTests(unittest.TestCase):
    def test_languages_builds_and_security_carriers(self) -> None:
        with tempfile.TemporaryDirectory() as repo_name, tempfile.TemporaryDirectory() as output_name:
            root = Path(repo_name)
            for name in ("A.java", "b.js", "c.ts", "d.py", "e.go", "f.cs"):
                (root / name).write_text("// source", encoding="utf-8")
            for name in ("pom.xml", "build.gradle", "package.json", "requirements.txt", "go.mod", "app.csproj"):
                (root / name).write_text("dependency", encoding="utf-8")
            (root / ".env").write_text("TOKEN=example", encoding="utf-8")
            (root / "SKILL.md").write_text("tool instructions", encoding="utf-8")
            (root / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
            (root / "Dockerfile").write_text("FROM scratch", encoding="utf-8")
            (root / "main.tf").write_text('provider "aws" {}', encoding="utf-8")
            workflow = root / ".github" / "workflows"
            workflow.mkdir(parents=True)
            (workflow / "ci.yml").write_text("jobs: {}", encoding="utf-8")
            workspace = RepositoryWorkspace(root, Path(output_name), Path(output_name) / "cache")
            inventory = FileInventoryBuilder(workspace, 4096, 100_000)
            records, _ = inventory.scan(lambda _record, _text: None)
            languages = {language for record in records for language in record.language_hints}
            self.assertTrue({"Java", "JavaScript", "TypeScript", "Python", "Go", "C#"}.issubset(languages))
            by_name = {record.relative_path: record for record in records}
            self.assertTrue(by_name[".env"].configuration)
            self.assertTrue(by_name["SKILL.md"].prompt_content)
            self.assertTrue(by_name["AndroidManifest.xml"].mobile)
            self.assertTrue(by_name["Dockerfile"].container_iac)
            self.assertTrue(by_name[".github/workflows/ci.yml"].ci_cd)
            builds = set().union(*(detect_build(name)[0] for name in by_name))
            self.assertTrue({"Maven", "Gradle", "npm", "Python packaging", "Go modules", ".NET"}.issubset(builds))


if __name__ == "__main__":
    unittest.main()
