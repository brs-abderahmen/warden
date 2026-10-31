"""Collect tool descriptions from public MCP server repositories on GitHub.

Repository files are only read as text and parsed. Nothing downloaded is ever executed.
Usage: python scanner/collect_tools.py <output.jsonl> [--pages 3]
"""

import argparse
import ast
import io
import json
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

GH = shutil.which("gh") or r"C:\Program Files\GitHub CLI\gh.exe"
LICENSES = {"mit", "apache-2.0", "bsd-2-clause", "bsd-3-clause", "isc", "unlicense", "0bsd"}
LANGUAGES = ("Python", "TypeScript", "JavaScript", "Go")
MAX_REPO_KB = 60_000
MAX_FILE_BYTES = 300_000
MIN_DESCRIPTION = 15
SKIP_PARTS = {"node_modules", "dist", "build", "vendor", "__pycache__", "test", "tests", "__tests__"}

STRING = r"""(?:"((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)'|`((?:[^`\\$]|\\.)*)`)"""
SOURCE_PATTERNS = [
    re.compile(r"\.tool\(\s*" + STRING + r"\s*,\s*" + STRING),
    re.compile(r"registerTool\(\s*" + STRING + r"\s*,\s*\{[^{}]*?description:\s*" + STRING, re.S),
    re.compile(r"\bname:\s*" + STRING + r"\s*,\s*(?:title:\s*" + STRING + r"\s*,\s*)?description:\s*" + STRING),
]
SCHEMA_NEARBY = re.compile(r"\b(?:inputSchema|input_schema|parameters)\b")
GO_PATTERN = re.compile(r"mcp\.NewTool\(\s*\"([^\"]+)\"\s*,\s*mcp\.WithDescription\(\s*\"((?:[^\"\\]|\\.)*)\"")


def gh_json(*args: str) -> dict:
    output = subprocess.run([GH, "api", *args], capture_output=True, check=True).stdout
    return json.loads(output)


def search_repositories(pages: int) -> list[dict]:
    repositories = {}
    for language in LANGUAGES:
        for page in range(1, pages + 1):
            query = f"q=topic:mcp-server+language:{language}&sort=stars&per_page=100&page={page}"
            for item in gh_json(f"search/repositories?{query}").get("items", []):
                repositories[item["full_name"]] = item
    return list(repositories.values())


def is_permitted(repo: dict) -> bool:
    license_info = repo.get("license") or {}
    key = (license_info.get("key") or "").lower()
    return key in LICENSES and not repo.get("fork") and repo.get("size", 0) <= MAX_REPO_KB


def string_value(match: re.Match, start: int) -> str | None:
    return next((match.group(i) for i in range(start, start + 3) if match.group(i) is not None), None)


def unescape(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("\\n", " ").replace('\\"', '"').replace("\\'", "'")).strip()


def parse_python(source: str) -> list[tuple[str, str]]:
    tools = []
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return tools
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if isinstance(target, ast.Attribute) and target.attr == "tool":
                    tools.append((node.name, ast.get_docstring(node) or ""))
        elif isinstance(node, ast.Call):
            name = getattr(node.func, "id", getattr(node.func, "attr", ""))
            if name in ("Tool", "ToolDefinition"):
                fields = {
                    item.arg: item.value.value
                    for item in node.keywords
                    if item.arg and isinstance(item.value, ast.Constant) and isinstance(item.value.value, str)
                }
                if "name" in fields and "description" in fields:
                    tools.append((fields["name"], fields["description"]))
    return tools


def parse_source(source: str) -> list[tuple[str, str]]:
    tools = []
    for index, pattern in enumerate(SOURCE_PATTERNS):
        for match in pattern.finditer(source):
            # A bare name and description pair only counts next to a tool input schema.
            if index == 2 and not SCHEMA_NEARBY.search(source, match.end(), match.end() + 800):
                continue
            description_start = {0: 4, 1: 4, 2: 7}[index]
            name, description = string_value(match, 1), string_value(match, description_start)
            if name and description:
                tools.append((name, description))
    return tools


def parse_go(source: str) -> list[tuple[str, str]]:
    return [(match.group(1), match.group(2)) for match in GO_PATTERN.finditer(source)]


PARSERS = {
    ".py": parse_python,
    ".ts": parse_source,
    ".js": parse_source,
    ".mjs": parse_source,
    ".go": parse_go,
}


def extract_tools(archive: bytes) -> list[dict]:
    found = []
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        for info in zipped.infolist():
            path = Path(info.filename)
            parser = PARSERS.get(path.suffix)
            if parser is None or info.file_size > MAX_FILE_BYTES:
                continue
            if SKIP_PARTS.intersection(part.lower() for part in path.parts):
                continue
            source = zipped.read(info).decode("utf-8", errors="ignore")
            for name, description in parser(source):
                cleaned = unescape(description)
                if len(cleaned) >= MIN_DESCRIPTION:
                    found.append({"file": "/".join(path.parts[1:]), "name": name, "description": cleaned})
    return found


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--pages", type=int, default=3)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()

    repositories = [repo for repo in search_repositories(args.pages) if is_permitted(repo)]
    repositories.sort(key=lambda repo: repo.get("stargazers_count", 0), reverse=True)
    if args.limit:
        repositories = repositories[: args.limit]
    print(f"{len(repositories)} repositories to scan", flush=True)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    seen = set()
    total = 0
    with args.output.open("w", encoding="utf-8") as out:
        for index, repo in enumerate(repositories, start=1):
            name = repo["full_name"]
            try:
                archive = subprocess.run(
                    [GH, "api", f"repos/{name}/zipball"], capture_output=True, check=True, timeout=180
                ).stdout
                tools = extract_tools(archive)
            except (subprocess.SubprocessError, zipfile.BadZipFile, OSError) as error:
                print(f"skip {name}: {type(error).__name__}", flush=True)
                continue
            for tool in tools:
                if tool["description"] in seen:
                    continue
                seen.add(tool["description"])
                record = {"repo": name, "license": repo["license"]["key"], "stars": repo["stargazers_count"], **tool}
                out.write(json.dumps(record, ensure_ascii=False) + "\n")
                total += 1
            out.flush()
            if index % 25 == 0:
                print(f"{index}/{len(repositories)} repos, {total} unique descriptions", flush=True)
    print(f"done: {total} unique descriptions", flush=True)


if __name__ == "__main__":
    sys.exit(main())
