"""Runs line rules and structural checks over a repository."""

from __future__ import annotations

import hashlib
import os
import re
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .models import Finding, ScanResult
from .rules import RULES, Rule, redact
from .source import Repository, SourceFile, load_repository

IGNORE_MARK = re.compile(r"slopsweep:\s*ignore(?:=([\w,]+))?")
COLLAPSE = {"SLP006": 1, "SLP008": 1, "SLP009": 1, "END002": 1, "END003": 1, "END008": 1,
            "SEC022": 1, "SLP004": 3}
BRACE_EXTS = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".cs", ".java", ".js", ".jsx", ".mjs",
              ".cjs", ".ts", ".tsx", ".go", ".rs", ".swift", ".kt", ".scala", ".dart", ".php"}
UNREACHABLE_EXTS = BRACE_EXTS | {".py"}
WINDOW = 8
_GUARD_WORDS = re.compile(r"unknown|unsupported|not supported|subclass|overrid|abstract|must implement")
_BROAD_EXCEPT = re.compile(r"^\s*except\s*(?::|\(?\s*(?:Base)?Exception\b)")
_NOT_LOGIC = re.compile(r"^(?:import\b|from\b|using\b|#include\b|package\b|require\b|@|[)\]}])|[,(\[{]$")


def snippet(line: str) -> str:
    return redact(line.strip())[:160]


def _suppressed(src: SourceFile, index: int, rule_id: str) -> bool:
    for i in (index, index - 1):
        if 0 <= i < len(src.lines):
            match = IGNORE_MARK.search(src.lines[i])
            if match and (not match.group(1) or rule_id in match.group(1).split(",")):
                return True
    return False


def _class_is_abstract(src: SourceFile, index: int) -> bool:
    window = src.views[max(0, index - 6):index + 1]
    if any("abstractmethod" in v.code or "overload" in v.code for v in window):
        return True
    indent = len(src.lines[index]) - len(src.lines[index].lstrip())
    for i in range(index - 1, -1, -1):
        code = src.views[i].code
        if not code.strip():
            continue
        current = len(code) - len(code.lstrip())
        if current < indent:
            if code.lstrip().startswith("class "):
                return bool(re.search(r"ABC|Protocol|Interface|Base|Abstract", code))
            indent = current
            if current == 0:
                return False
    return False


def _is_deliberate_guard(src: SourceFile, index: int) -> bool:
    if src.language.startswith("py") and _class_is_abstract(src, index):
        return True
    return bool(_GUARD_WORDS.search(" ".join(src.lines[index:index + 2]).lower()))


def _scope_text(src: SourceFile, index: int, scope: str) -> str:
    view = src.views[index]
    return {"code": view.code, "strings": view.code_str, "comment": view.comment,
            "raw": src.lines[index]}[scope]


def _rule_applies(rule: Rule, src: SourceFile) -> bool:
    if src.kind not in rule.kinds:
        return False
    if rule.only_tests and not src.is_test:
        return False
    if rule.skip_tests and src.is_test:
        return False
    if rule.id == "SEC023":
        return src.language == "dockerfile"
    return True


def scan_lines(src: SourceFile) -> Iterable[Finding]:
    rules = [rule for rule in RULES if _rule_applies(rule, src)]
    for index, raw in enumerate(src.lines):
        if len(raw) > 5000:
            continue
        for rule in rules:
            match = rule.pattern.search(_scope_text(src, index, rule.scope))
            if not match:
                continue
            if rule.secret_group and rule.validate:
                if not rule.validate(match.group(rule.secret_group)):
                    continue
            elif rule.validate and not rule.validate(match.group(0)):
                continue
            if _suppressed(src, index, rule.id):
                continue
            if rule.id == "GAP001" and _is_deliberate_guard(src, index):
                continue
            yield Finding(rule.id, rule.category, rule.severity, rule.confidence, src.path,
                          index + 1, rule.title, fix=rule.fix, snippet=snippet(raw))


def _make(rule, category, severity, confidence, src, index, title, detail, fix) -> Finding:
    return Finding(rule, category, severity, confidence, src.path, index + 1, title, detail, fix,
                   snippet(src.lines[index]) if 0 <= index < len(src.lines) else "")


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset)


# Structural checks --------------------------------------------------------------------

_BRACE_STUB = re.compile(
    r"(?:\bfunction\s+[\w$]+\s*\([^)]*\)(?:\s*:\s*[\w<>\[\]|, ]+)?"
    r"|\bfunc\s+(?:\([^)]*\)\s*)?\w+\s*\([^)]*\)[^{\n]*"
    r"|\bfn\s+\w+\s*(?:<[^>]*>)?\([^)]*\)[^{\n]*"
    r"|\b(?:public|private|protected|internal|static)\s+(?:[\w<>\[\],.?]+\s+)+\w+\s*\([^)]*\)(?:\s*throws\s+[\w., ]+)?)"
    r"\s*\{\s*\}"
)
_BRACE_SWALLOW = re.compile(
    r"\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}|\.catch\s*\(\s*(?:\([^)]*\)|\w+)\s*=>\s*\{\s*\}\s*\)"
    r"|\bif\s+err\s*!=\s*nil\s*\{\s*\}"
)


def check_brace_blocks(src: SourceFile) -> Iterable[Finding]:
    if src.ext not in BRACE_EXTS:
        return
    text = src.masked()
    if not src.is_test:
        for match in _BRACE_STUB.finditer(text):
            index = _line_of(text, match.start())
            if not _suppressed(src, index, "GAP010"):
                yield _make("GAP010", "gap", "medium", "medium", src, index,
                            "Stub function with no body",
                            "The function is declared but does nothing.",
                            "Implement it or delete it.")
    for match in _BRACE_SWALLOW.finditer(text):
        index = _line_of(text, match.start())
        if not _suppressed(src, index, "GAP011"):
            yield _make("GAP011", "gap", "high", "high", src, index, "Error swallowed",
                        "The failure is caught and dropped without any handling.",
                        "Handle it, log it, or let it propagate.")


def _python_body(src: SourceFile, start: int, indent: int) -> List[int]:
    body = []
    for i in range(start, len(src.views)):
        raw = src.lines[i]
        if not raw.strip():
            continue
        if len(raw) - len(raw.lstrip()) <= indent and src.views[i].code.strip():
            break
        body.append(i)
    return body


def _is_docstring(code: str) -> bool:
    return not code.strip() or not code.strip().strip("\"'")


def check_python_blocks(src: SourceFile) -> Iterable[Finding]:
    if not src.language.startswith("py"):
        return
    for index, view in enumerate(src.views):
        code = view.code
        handler = re.match(r"(\s*)except\b.*:\s*(pass|continue|\.\.\.)?\s*$", code)
        if handler:
            body = _python_body(src, index + 1, len(handler.group(1)))
            statements = [src.views[i].code.strip() for i in body if src.views[i].code.strip()]
            if (handler.group(2) or (len(statements) == 1 and statements[0] in ("pass", "continue", "...")))\
                    and not _suppressed(src, index, "GAP011"):
                severity = "high" if _BROAD_EXCEPT.match(code) else "low"
                yield _make("GAP011", "gap", severity, "high", src, index, "Error swallowed",
                            "The exception is caught and dropped without any handling.",
                            "Handle it, log it, or let it propagate.")
        func = re.match(r"(\s*)(?:async\s+)?def\s+(\w+)\s*\(", code)
        if not func or src.is_test or src.ext == ".pyi" or func.group(2).startswith("__"):
            continue
        end = index
        while end < min(index + 12, len(src.views) - 1) and not src.views[end].code.rstrip().endswith(":"):
            if re.search(r":\s*(pass|\.\.\.)\s*$", src.views[end].code):
                break
            end += 1
        if re.search(r":\s*\.\.\.\s*$", src.views[end].code):
            continue  # `...` is the conventional body of a typed declaration
        inline = re.search(r":\s*pass\s*$", src.views[end].code)
        body = _python_body(src, end + 1, len(func.group(1)))
        statements = [src.views[i].code.strip() for i in body
                      if not _is_docstring(src.views[i].code)]
        is_stub = bool(inline) or (bool(body) and (not statements or statements == ["pass"]))
        if is_stub and not _class_is_abstract(src, index) and not _suppressed(src, index, "GAP010"):
            yield _make("GAP010", "gap", "medium", "high", src, index,
                        "Stub function with no body",
                        f"`{func.group(2)}` is declared but does nothing.",
                        "Implement it or delete it.")


_CODEISH = re.compile(
    r"^(?:def |class |if\s*\(|if .*:$|for\s*\(|for .*:$|while\s*\(|return\b|import |from \S+ import"
    r"|const |let |var |function\b|public |private |func |fn |#include)"
    r"|[;{}]\s*$|^[\w][\w.\[\]]*\s*=\s*[^=\s]|^[\w][\w.]*\([^)]*\)\s*;?$"
)


def check_commented_code(src: SourceFile) -> Iterable[Finding]:
    if src.kind != "code":
        return
    run: List[int] = []
    for index in range(len(src.views) + 1):
        view = src.views[index] if index < len(src.views) else None
        text = view.comment.strip().lstrip("*").strip() if view else ""
        if view and not view.code.strip() and text and _CODEISH.search(text):
            run.append(index)
            continue
        if len(run) >= 3 and not _suppressed(src, run[0], "END010"):
            yield _make("END010", "loose-end", "low", "medium", src, run[0], "Commented-out code",
                        f"{len(run)} consecutive lines of disabled code.",
                        "Delete it. Version control keeps the history.")
        run = []


_TERMINAL = re.compile(r"^\s*(?:return\b|raise\b|throw\b|break\b|continue\b)")
_NOT_DEAD = re.compile(r"^\s*(?:[})\]]|case\b|default\b|else\b|elif\b|except\b|finally\b|catch\b|#|@|\w+:\s*$)")


def check_unreachable(src: SourceFile) -> Iterable[Finding]:
    if src.ext not in UNREACHABLE_EXTS:
        return
    views = src.views
    for index, view in enumerate(views[:-1]):
        code = view.code.rstrip()
        if not _TERMINAL.match(code) or re.search(r"\b(?:if|unless)\b", code):
            continue
        if code.endswith(("(", "[", "{", ",", "+", "-", "*", "/", "&", "|", "=", ".", "\\", "?", ":")):
            continue
        if code.count("(") != code.count(")") or code.count("[") != code.count("]"):
            continue
        if code.count("{") != code.count("}"):
            continue
        follower = next((i for i in range(index + 1, len(views)) if views[i].code.strip()), None)
        if follower is None or _NOT_DEAD.match(views[follower].code):
            continue
        if views[follower].code.lstrip().startswith("yield") or "unreachable" in src.lines[follower]:
            continue
        indent = len(code) - len(code.lstrip())
        next_code = views[follower].code
        if len(next_code) - len(next_code.lstrip()) == indent and not _suppressed(src, follower, "END011"):
            yield _make("END011", "loose-end", "medium", "high", src, follower, "Unreachable code",
                        f"Line {index + 1} always exits first.", "Delete it or fix the control flow.")


_STOPWORDS = {"the", "a", "an", "to", "of", "this", "that", "is", "it", "we", "and", "for", "in",
              "on", "with", "by", "then", "now", "from", "our", "new"}


def _words(text: str) -> Set[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text).replace("_", " ").lower()
    return {w[:-1] if w.endswith("s") and len(w) > 3 else w for w in re.findall(r"[a-z]{2,}", spaced)}


def check_narration(src: SourceFile) -> Iterable[Finding]:
    if src.kind != "code" or src.is_test:
        return
    for index, view in enumerate(src.views[:-1]):
        following = src.views[index + 1].code
        if view.code.strip() or not view.comment.strip() or not following.strip():
            continue
        said = _words(view.comment) - _STOPWORDS
        if len(said) < 2 or len(said) > 8:
            continue
        if len(said & _words(following)) / len(said) >= 0.75:
            yield _make("SLP004", "slop", "low", "low", src, index, "Comments restate the code",
                        "The comment repeats what the next line already says.",
                        "Delete it, or explain why the code does this.")


_PY_IMPORT = re.compile(r"^\s*from\s+(\.*)([\w.]*)\s+import\b")
_JS_IMPORT = re.compile(r"(?:\bfrom\s+|\brequire\s*\(\s*|\bimport\s*\(\s*|^\s*import\s+)[\"'`](\.{1,2}/[^\"'`]+)[\"'`]")
_C_INCLUDE = re.compile(r"^\s*#\s*include\s+\"([^\"]+)\"")
_MD_LINK = re.compile(r"\]\((?![a-z][a-z0-9+.-]*:|#|/|<)([^)\s#?]+)")
_JS_EXTS = ("", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".vue", ".svelte", ".d.ts",
            "/index.js", "/index.ts", "/index.tsx", "/index.jsx")


def _exists(root: str, rel: str) -> bool:
    return os.path.exists(os.path.join(root, rel.replace("/", os.sep)))


def _python_module_exists(root: str, base: str, module: str) -> bool:
    rel = os.path.normpath(os.path.join(base, *module.split("."))).replace(os.sep, "/")
    return _exists(root, rel + ".py") or _exists(root, rel + ".pyi") or _exists(root, rel)


def check_imports(repo: Repository) -> Iterable[Finding]:
    root = repo.root
    basenames = {p.rsplit("/", 1)[-1] for p in repo.all_paths}
    title = "Import points at a missing file"
    fix = "Add the missing module or correct the path. Generated code often invents these."
    for src in repo.sources:
        directory = os.path.dirname(src.path)
        for index, view in enumerate(src.views):
            missing = None
            if src.language.startswith("py"):
                match = _PY_IMPORT.match(view.code)
                if match and match.group(2):
                    dots, module = match.groups()
                    if dots:
                        base = directory
                        for _ in range(len(dots) - 1):
                            base = os.path.dirname(base)
                        if not _python_module_exists(root, base, module):
                            missing = dots + module
                    elif "." in module:
                        top = module.split(".")[0]
                        for base in ("", "src"):
                            prefix = os.path.join(base, top) if base else top
                            if _exists(root, prefix.replace(os.sep, "/")):
                                if not _python_module_exists(root, base, module):
                                    missing = module
                                break
            elif src.ext in (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte"):
                match = _JS_IMPORT.search(view.code_str)
                if match:
                    target = os.path.normpath(os.path.join(directory, match.group(1).split("?")[0]))
                    target = target.replace(os.sep, "/")
                    stem = re.sub(r"\.(?:js|jsx|mjs|cjs)$", "", target)
                    if not any(_exists(root, target + e) or _exists(root, stem + e) for e in _JS_EXTS):
                        missing = match.group(1)
            elif src.ext in (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"):
                match = _C_INCLUDE.match(view.code_str)
                if match and match.group(1).rsplit("/", 1)[-1] not in basenames:
                    missing = match.group(1)
            if missing and not _suppressed(src, index, "GAP012"):
                yield _make("GAP012", "gap", "high", "high", src, index, title,
                            f"`{missing}` does not resolve inside this repository.", fix)
        if src.ext in (".md", ".mdx"):
            fenced = False
            for index, line in enumerate(src.lines):
                if line.lstrip().startswith("```"):
                    fenced = not fenced
                    continue
                if fenced:
                    continue
                for target in _MD_LINK.findall(line):
                    rel = os.path.normpath(os.path.join(directory, target)).replace(os.sep, "/")
                    if not rel.startswith("..") and not _exists(root, rel):
                        yield _make("GAP013", "gap", "low", "high", src, index,
                                    "Broken documentation link", f"`{target}` does not exist.",
                                    "Fix the link or add the file.")


_ENV_USE = re.compile(
    r"os\.environ\s*\[\s*[\"'](\w+)|os\.(?:environ\.get|getenv)\s*\(\s*[\"'](\w+)"
    r"|process\.env\.([A-Z_][A-Z0-9_]+)|process\.env\[[\"'](\w+)"
    r"|\bos\.Getenv\(\"(\w+)|System\.getenv\(\"(\w+)|\benv::var\(\"(\w+)|\bENV\[[\"'](\w+)"
)
_COMMON_ENV = {"PATH", "HOME", "USER", "PWD", "SHELL", "TMPDIR", "TEMP", "TMP", "LANG", "CI",
               "NODE_ENV", "TERM", "HOSTNAME", "DEBUG"}


def check_env_docs(repo: Repository) -> Iterable[Finding]:
    used: Dict[str, Tuple[SourceFile, int]] = {}
    for src in repo.sources:
        if src.kind != "code" or src.is_test:
            continue
        for index, view in enumerate(src.views):
            for groups in _ENV_USE.findall(view.code_str):
                name = next(g for g in groups if g)
                if name not in _COMMON_ENV:
                    used.setdefault(name, (src, index))
    if not used:
        return
    docs = "\n".join(s.text for s in repo.sources if s.kind in ("doc", "config"))
    for name, (src, index) in sorted(used.items()):
        if not re.search(r"\b" + re.escape(name) + r"\b", docs):
            yield _make("GAP014", "gap", "low", "medium", src, index,
                        "Environment variable undocumented",
                        f"`{name}` is read here but appears in no docs or config.",
                        "Add it to the README or an .env.example file.")


def check_duplicates(repo: Repository) -> Iterable[Finding]:
    """Report one finding per pair of files that share substantive logic."""
    seen: Dict[str, Tuple[SourceFile, int]] = {}
    pairs: Dict[Tuple[str, str], List] = {}
    for src in repo.sources:
        if src.kind != "code" or src.is_test:
            continue
        rows = []
        for index, view in enumerate(src.views):
            norm = " ".join(view.code.split())
            if len(norm) > 8 and not _NOT_LOGIC.search(norm):
                rows.append((index, norm))
        previous = -WINDOW
        for pos in range(len(rows) - WINDOW + 1):
            text = "\n".join(row[1] for row in rows[pos:pos + WINDOW])
            digest = hashlib.sha256(text.encode()).hexdigest()
            line = rows[pos][0]
            other, other_line = seen.setdefault(digest, (src, line))
            if other is src and line - other_line < WINDOW:
                continue
            pair = pairs.setdefault((other.path, src.path), [src, line, other, other_line, 0])
            pair[4] += min(WINDOW, pos - previous)
            previous = pos
    for src, line, other, other_line, count in pairs.values():
        yield _make("SLP010", "slop", "medium", "high", src, line, "Duplicated code block",
                    f"About {count} lines repeat {other.path} (first match at line {other_line + 1}).",
                    "Extract the shared logic.")


_LEFTOVER = re.compile(r"(?:\.(?:bak|orig|rej|swp|swo|tmp|old)$|~$|^\.DS_Store$|^Thumbs\.db$|\.log$)", re.I)
_SENSITIVE = re.compile(r"(?:^\.env(?:\.(?!example|sample|template|dist)\w+)?$|\.(?:pem|key|p12|pfx|jks)$"
                        r"|^id_(?:rsa|dsa|ed25519|ecdsa)$|^credentials(?:\.json)?$|\.tfstate$)", re.I)
_VERSIONED = re.compile(r"(?:[_ -](?:final|copy|new|old|backup|fixed|v\d+)|\s\(\d+\))\.\w+$", re.I)


def is_sensitive_path(rel_path: str) -> bool:
    return bool(_SENSITIVE.search(rel_path.rsplit("/", 1)[-1]))


def check_repository(repo: Repository) -> Iterable[Finding]:
    def repo_finding(rule, category, severity, path, title, detail, fix, confidence="high"):
        return Finding(rule, category, severity, confidence, path, 0, title, detail, fix)

    names = {p.lower() for p in repo.all_paths if "/" not in p}
    code = [s for s in repo.sources if s.kind == "code"]
    for path in repo.all_paths:
        name = path.rsplit("/", 1)[-1]
        if is_sensitive_path(path) and "/fixtures/" not in "/" + path:
            yield repo_finding("SEC030", "security", "critical", path, "Sensitive file committed",
                               "This file type usually holds credentials.",
                               "Remove it, rotate what it holds, and add it to .gitignore.")
        elif _LEFTOVER.search(name):
            yield repo_finding("END012", "loose-end", "low", path, "Leftover file committed",
                               "Editor, merge or runtime output is in the repository.",
                               "Delete it and add the pattern to .gitignore.")
        elif _VERSIONED.search(name):
            yield repo_finding("SLP011", "slop", "low", path, "Version-suffixed file name",
                               "Version control should hold old versions, not file names.",
                               "Keep one canonical file.", "medium")
    for src in code:
        if not src.text.strip() and os.path.basename(src.path) != "__init__.py":
            yield repo_finding("GAP016", "gap", "low", src.path, "Empty source file",
                               "The file has no content.", "Fill it in or delete it.")
    if not code:
        return
    missing = []
    if not any(n.startswith("readme") for n in names):
        missing.append(("README", "medium", "Explain what the project does and how to run it."))
    if ".gitignore" not in names:
        missing.append((".gitignore", "low", "Add one so build output and secrets stay out."))
    if len(code) >= 3 and not repo.has_tests:
        missing.append(("tests", "high", "Add tests for the main behavior."))
    for label, severity, fix in missing:
        yield repo_finding("GAP015", "gap", severity, ".", f"Project has no {label}",
                           f"The repository has no {label}.", fix)


def _collapse(findings: List[Finding]) -> List[Finding]:
    grouped: Dict[Tuple[str, str], List[Finding]] = defaultdict(list)
    output: List[Finding] = []
    for finding in findings:
        if finding.rule in COLLAPSE:
            grouped[(finding.rule, finding.file)].append(finding)
        else:
            output.append(finding)
    for (rule, _), items in grouped.items():
        if len(items) < COLLAPSE[rule]:
            continue
        first = items[0]
        if len(items) > 1:
            lines = ", ".join(str(item.line) for item in items[:12])
            suffix = ", ..." if len(items) > 12 else ""
            first.detail = f"{len(items)} occurrences, at lines {lines}{suffix}."
        output.append(first)
    return output


def scan(root: str) -> Tuple[ScanResult, Repository]:
    repo = load_repository(root)
    findings: List[Finding] = []
    for src in repo.sources:
        findings.extend(scan_lines(src))
        findings.extend(check_brace_blocks(src))
        findings.extend(check_python_blocks(src))
        findings.extend(check_commented_code(src))
        findings.extend(check_unreachable(src))
        findings.extend(check_narration(src))
    findings.extend(check_imports(repo))
    findings.extend(check_env_docs(repo))
    findings.extend(check_duplicates(repo))
    findings.extend(check_repository(repo))

    unique: Dict[Tuple[str, str, int], Finding] = {}
    for finding in findings:
        unique.setdefault((finding.rule, finding.file, finding.line), finding)
    languages = Counter(s.language for s in repo.sources if s.kind == "code")
    result = ScanResult(repo.root, _collapse(list(unique.values())), len(repo.sources), dict(languages))
    result.sort()
    return result, repo
