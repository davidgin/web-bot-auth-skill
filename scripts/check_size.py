# SPDX-License-Identifier: Apache-2.0
"""Size gate: file and function length limits with a shrink-only baseline.

Run from the repo root: python scripts/check_size.py
Rules are in AGENTS.md. Baseline entries ("file::qualname": max_lines) may only
shrink; update scripts/size_baseline.json downward as functions are split.
"""
import ast
import json
import sys
from pathlib import Path

MAX_FILE_LINES = 1000
MAX_FUNC_LINES = 50
# web_bot_auth.py must stay a single vendorable file, so it gets a higher cap.
FILE_LIMIT_OVERRIDES = {"web_bot_auth.py": 1100}

REPO = Path(__file__).resolve().parent.parent
TARGET = REPO / "web-bot-auth" / "scripts"
BASELINE = Path(__file__).resolve().parent / "size_baseline.json"


def _functions(tree):
    """Yield (qualname, length) for every function and method."""
    def walk(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = prefix + child.name
                yield name, child.end_lineno - child.lineno + 1
                yield from walk(child, name + ".")
            elif isinstance(child, ast.ClassDef):
                yield from walk(child, prefix + child.name + ".")
            else:
                yield from walk(child, prefix)
    yield from walk(tree, "")


def measure(root):
    """Return {key: length} for functions, and {name: lines} for files."""
    funcs, files = {}, {}
    for path in sorted(Path(root).rglob("*.py")):
        if path.name.startswith("test_"):
            continue
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8")
        files[rel] = len(text.splitlines())
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:
            funcs[rel] = exc
            continue
        for qual, length in _functions(tree):
            funcs[f"{rel}::{qual}"] = length
    return funcs, files


def check(root, baseline):
    """Return a list of violation messages (empty means pass)."""
    funcs, files = measure(root)
    violations = []
    for rel, lines in files.items():
        limit = FILE_LIMIT_OVERRIDES.get(Path(rel).name, MAX_FILE_LINES)
        if lines > limit:
            violations.append(f"{rel}: {lines} lines exceeds file limit {limit}")
    for key, length in funcs.items():
        if isinstance(length, SyntaxError):
            violations.append(f"{key}: cannot parse ({length})")
            continue
        limit = max(MAX_FUNC_LINES, baseline.get(key, 0))
        if length > limit:
            kind = "baseline" if key in baseline else "limit"
            violations.append(f"{key}: {length} lines exceeds {kind} {limit}")
    return violations


def main():
    baseline = json.loads(BASELINE.read_text()) if BASELINE.exists() else {}
    violations = check(TARGET, baseline)
    for v in violations:
        print(f"SIZE VIOLATION: {v}")
    if violations:
        print(f"{len(violations)} violation(s)")
        return 1
    print("size gate: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
