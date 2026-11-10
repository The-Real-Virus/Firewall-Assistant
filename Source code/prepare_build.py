"""Create an isolated build checkout from the public repository layout."""

import argparse
import shutil
import subprocess
from pathlib import Path

SOURCE = Path(__file__).resolve().parent
REPOSITORY = SOURCE.parent
SOURCE_DIRECTORIES = ("src", "tests", "scripts", "packaging", "examples")
SOURCE_FILES = (".editorconfig", ".gitattributes", ".gitignore", "MANIFEST.in", "pyproject.toml")
LOCKS = ("requirements.txt", "requirements-desktop-ai.txt", "requirements-dev.txt")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "destination", type=Path, help="An unused directory outside this repository"
    )
    destination = parser.parse_args().destination.resolve()
    if destination.is_relative_to(REPOSITORY):
        parser.error("Choose a build directory outside this repository")
    if shutil.which("git") is None:
        parser.error("Git must be available on PATH to record the local build inputs")
    destination.mkdir(parents=True, exist_ok=False)

    generated = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", ".ruff_cache")
    for name in SOURCE_DIRECTORIES:
        shutil.copytree(SOURCE / name, destination / name, ignore=generated)
    for name in SOURCE_FILES:
        shutil.copyfile(SOURCE / name, destination / name)
    docs = REPOSITORY / "Docs"
    shutil.copytree(docs, destination / "docs")
    for name in LOCKS:
        shutil.copyfile(docs / name, destination / name)
    shutil.copyfile(REPOSITORY / "readme.md", destination / "README.md")
    shutil.copyfile(REPOSITORY / "Documentation.docx", destination / "docs/Documentation.docx")

    git = [
        "git",
        "-C",
        str(destination),
        "-c",
        "user.name=Firewall Assistant build",
        "-c",
        "user.email=local-build@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "core.hooksPath=.git/disabled-hooks",
    ]
    subprocess.run([*git, "init", "--initial-branch=main"], check=True)
    subprocess.run([*git, "add", "--force", "--all"], check=True)
    subprocess.run([*git, "commit", "--quiet", "-m", "Record build inputs"], check=True)
    print(f"Build workspace: {destination}")


if __name__ == "__main__":
    main()
