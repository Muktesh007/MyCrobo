"""Repository walking and a small lexer that works across languages.

No language gets a parser. Each file is split, line by line, into code, strings
and comments using only its comment and quote syntax, which is what lets the same
rules run on any stack. Unknown file types fall back to a conservative profile.
"""

from __future__ import annotations

import fnmatch
import os
import re
from functools import lru_cache
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

MAX_FILE_BYTES = 1_000_000

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor", "third_party",
    "dist", "build", "out", "target", "bin", "obj", "coverage", "htmlcov", "__pycache__",
    ".venv", "venv", "env", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".next", ".nuxt", ".svelte-kit", ".turbo", ".gradle", ".idea", ".vscode", ".terraform",
    "Pods", "DerivedData", ".dart_tool", "graphify-out",
}
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock",
    "uv.lock", "Cargo.lock", "composer.lock", "Gemfile.lock", "go.sum", "pubspec.lock",
}


@dataclass(frozen=True)
class Syntax:
    name: str
    line: Tuple[str, ...] = ()
    block: Tuple[Tuple[str, str], ...] = ()
    quotes: Tuple[str, ...] = ('"', "'")
    multiline_quotes: Tuple[str, ...] = ()
    hash_needs_space: bool = False


C_LIKE = Syntax("c-like", ("//",), (("/*", "*/"),), ('"', "'"), ("`",))
PYTHON = Syntax("python", ("#",), (), ('"', "'"), ('"""', "'''"), True)
HASH = Syntax("hash", ("#",), (), ('"', "'"), (), True)
RUBY = Syntax("ruby", ("#",), (("=begin", "=end"),), ('"', "'"), (), True)
PHP = Syntax("php", ("//", "#"), (("/*", "*/"),), ('"', "'"), (), True)
DASH = Syntax("dash", ("--",), (("/*", "*/"),), ('"', "'"))
LUA = Syntax("lua", ("--",), (("--[[", "]]"),), ('"', "'"))
HASKELL = Syntax("haskell", ("--",), (("{-", "-}"),), ('"',))
MARKUP = Syntax("markup", (), (("<!--", "-->"),), ())
CSS = Syntax("css", (), (("/*", "*/"),), ('"', "'"))
JSONISH = Syntax("json", (), (), ('"',))
PLAIN = Syntax("plain", (), (), ())
UNKNOWN = Syntax("unknown", ("#", "//", "--"), (), ('"',), (), True)

# extension -> (language label, syntax, kind)
_CODE = {
    "c-like": ("c h cc cpp cxx hpp hh cs java js jsx mjs cjs ts tsx go rs swift kt kts scala "
               "dart sol groovy m mm zig v", C_LIKE),
    "python": ("py pyi pyw", PYTHON),
    "hash": ("sh bash zsh fish ps1 pl pm r jl ex exs nim cr tf", HASH),
    "ruby": ("rb rake", RUBY),
    "php": ("php", PHP),
    "dash": ("sql", DASH),
    "lua": ("lua", LUA),
    "haskell": ("hs elm", HASKELL),
    "markup": ("html htm vue svelte astro", MARKUP),
}
EXTENSIONS: Dict[str, Tuple[str, Syntax, str]] = {}
for _family, (_exts, _syntax) in _CODE.items():
    for _ext in _exts.split():
        EXTENSIONS["." + _ext] = (_ext, _syntax, "code")
for _ext in "yaml yml toml ini cfg conf properties env tfvars hcl".split():
    EXTENSIONS["." + _ext] = (_ext, HASH, "config")
for _ext in "css scss less".split():
    EXTENSIONS["." + _ext] = (_ext, CSS, "config")
for _ext in "xml svg plist csproj".split():
    EXTENSIONS["." + _ext] = (_ext, MARKUP, "config")
EXTENSIONS[".json"] = ("json", JSONISH, "config")
for _ext in "md mdx rst txt adoc".split():
    EXTENSIONS["." + _ext] = (_ext, PLAIN, "doc")

SPECIAL_NAMES = {
    "dockerfile": ("dockerfile", HASH, "code"),
    "makefile": ("make", HASH, "code"),
    "rakefile": ("rb", RUBY, "code"),
    "gemfile": ("rb", RUBY, "config"),
    "jenkinsfile": ("groovy", C_LIKE, "code"),
}
SHEBANGS = (("python", ("py", PYTHON)), ("node", ("js", C_LIKE)), ("ruby", ("rb", RUBY)),
            ("sh", ("sh", HASH)), ("perl", ("pl", HASH)))

_TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "testdata", "fixtures", "e2e",
              "__mocks__", "mocks", "testing"}
_TEST_NAME = re.compile(r"(^test_|_test\.|\.test\.|\.spec\.|_spec\.|Tests?\.[a-z]+$)")


@dataclass
class LineView:
    code: str  # code with string contents removed and comments stripped
    code_str: str  # code and strings, comments stripped
    comment: str


@dataclass
class SourceFile:
    path: str
    abs_path: str
    text: str
    language: str
    syntax: Syntax
    kind: str
    is_test: bool
    lines: List[str] = field(default_factory=list)
    views: List[LineView] = field(default_factory=list)

    @property
    def ext(self) -> str:
        return os.path.splitext(self.path)[1].lower()

    def masked(self) -> str:
        return "\n".join(v.code for v in self.views)


@lru_cache(maxsize=None)
def _delimiters(syntax: Syntax) -> "re.Pattern[str]":
    tokens = list(syntax.line) + [b[0] for b in syntax.block]
    tokens += list(syntax.quotes) + list(syntax.multiline_quotes)
    return re.compile("|".join(re.escape(t) for t in tokens) or r"(?!)")


def lex(lines: Sequence[str], syntax: Syntax) -> List[LineView]:
    views: List[LineView] = []
    block_end: Optional[str] = None
    multi_end: Optional[str] = None
    openers = sorted(syntax.multiline_quotes, key=len, reverse=True)
    delimiters = _delimiters(syntax)

    for raw in lines:
        code: List[str] = []
        full: List[str] = []
        comment: List[str] = []
        quote: Optional[str] = None
        i, n = 0, len(raw)
        while i < n:
            if block_end:
                j = raw.find(block_end, i)
                comment.append(raw[i:] if j < 0 else raw[i:j])
                if j < 0:
                    break
                i = j + len(block_end)
                block_end = None
                continue
            if multi_end or quote:
                end = multi_end or quote
                closing = raw.find(end, i)
                escape = raw.find("\\", i)
                if escape >= 0 and (closing < 0 or escape < closing):
                    full.append(raw[i:escape + 2])
                    i = escape + 2
                elif closing >= 0:
                    full.append(raw[i:closing] + end)
                    code.append(end)
                    i = closing + len(end)
                    multi_end = quote = None
                else:
                    full.append(raw[i:])
                    i = n
                continue
            match = delimiters.search(raw, i)
            if match is None:
                code.append(raw[i:])
                full.append(raw[i:])
                break
            if match.start() > i:
                code.append(raw[i:match.start()])
                full.append(raw[i:match.start()])
                i = match.start()
            ch = raw[i]
            opened = next((b for b in syntax.block if raw.startswith(b[0], i)), None)
            if opened:
                block_end = opened[1]
                i += len(opened[0])
                continue
            token = next((t for t in syntax.line if raw.startswith(t, i)), None)
            if token and not (token == "#" and syntax.hash_needs_space
                              and i > 0 and not raw[i - 1].isspace()):
                comment.append(raw[i + len(token):])
                break
            multi = next((q for q in openers if raw.startswith(q, i)), None)
            if multi:
                multi_end = multi
                full.append(multi)
                code.append(multi)
                i += len(multi)
                continue
            if ch in syntax.quotes:
                quote = ch
                full.append(ch)
                code.append(ch)
                i += 1
                continue
            full.append(ch)
            code.append(ch)
            i += 1
        views.append(LineView("".join(code), "".join(full), "".join(comment)))
    return views


def classify(rel_path: str, first_line: str) -> Tuple[str, Syntax, str]:
    name = os.path.basename(rel_path)
    lower = name.lower()
    if lower == ".env" or lower.startswith(".env."):
        return "env", HASH, "config"
    for special, profile in SPECIAL_NAMES.items():
        if lower == special or lower.startswith(special + "."):
            return profile
    ext = os.path.splitext(lower)[1]
    if ext in EXTENSIONS:
        return EXTENSIONS[ext]
    if first_line.startswith("#!"):
        for needle, (language, syntax) in SHEBANGS:
            if needle in first_line:
                return language, syntax, "code"
    return "other", UNKNOWN, "other"


def is_test_path(rel_path: str) -> bool:
    parts = rel_path.split("/")
    return any(p.lower() in _TEST_DIRS for p in parts[:-1]) or bool(_TEST_NAME.search(parts[-1]))


def _read_ignore_file(path: str) -> List[str]:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            rows = [line.strip() for line in handle]
    except OSError:
        return []
    return [r for r in rows if r and not r.startswith(("#", "!"))]


def is_ignored(rel_path: str, patterns: Sequence[str]) -> bool:
    parts = rel_path.split("/")
    for pattern in patterns:
        clean = pattern.rstrip("/")
        if "/" in clean:
            clean = clean.lstrip("/")
            if fnmatch.fnmatch(rel_path, clean) or rel_path.startswith(clean + "/"):
                return True
        elif any(fnmatch.fnmatch(part, clean) for part in parts):
            return True
    return False


def _looks_generated(lines: Sequence[str]) -> bool:
    head = "\n".join(lines[:5]).lower()
    if "@generated" in head or "do not edit" in head or "auto-generated" in head:
        return True
    return bool(lines) and len(lines) <= 5 and max(len(l) for l in lines) > 2000


@dataclass
class Repository:
    root: str
    sources: List[SourceFile]
    all_paths: List[str]
    has_tests: bool = False

    def source(self, rel_path: str) -> Optional[SourceFile]:
        return next((s for s in self.sources if s.path == rel_path), None)


def load_repository(root: str) -> Repository:
    root = os.path.realpath(root)
    patterns = (_read_ignore_file(os.path.join(root, ".gitignore"))
                + _read_ignore_file(os.path.join(root, ".slopsweepignore")))
    sources: List[SourceFile] = []
    all_paths: List[str] = []
    has_tests = False
    for directory, subdirs, names in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(directory, root).replace(os.sep, "/")
        prefix = "" if rel_dir == "." else rel_dir + "/"
        kept = []
        for sub_dir in sorted(subdirs):
            if sub_dir in SKIP_DIRS:
                continue
            if is_ignored(prefix + sub_dir, patterns):
                has_tests = has_tests or is_test_path(f"{prefix}{sub_dir}/file")
            else:
                kept.append(sub_dir)
        subdirs[:] = kept
        for name in sorted(names):
            rel_path = prefix + name
            abs_path = os.path.join(directory, name)
            has_tests = has_tests or is_test_path(rel_path)
            if os.path.islink(abs_path) or is_ignored(rel_path, patterns):
                continue
            all_paths.append(rel_path)
            if name not in SKIP_FILES and not name.endswith((".min.js", ".min.css", ".map")):
                source = _load_source(rel_path, abs_path)
                if source:
                    sources.append(source)
    return Repository(root, sources, all_paths, has_tests)


def _load_source(rel_path: str, abs_path: str) -> Optional[SourceFile]:
    try:
        if os.path.getsize(abs_path) > MAX_FILE_BYTES:
            return None
        with open(abs_path, "rb") as handle:
            data = handle.read()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    text = data.decode("utf-8", errors="replace").lstrip("﻿")
    lines = text.splitlines()
    if _looks_generated(lines):
        return None
    language, syntax, kind = classify(rel_path, lines[0] if lines else "")
    return SourceFile(rel_path, abs_path, text, language, syntax, kind, is_test_path(rel_path),
                      lines, lex(lines, syntax))
