"""Line-level detection rules.

Each rule names the part of a line it reads:
  code     code only, with string contents and comments removed
  strings  code and strings, with comments removed
  comment  comment text only
  raw      the whole line
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Callable, List, Optional, Pattern, Tuple

CODE = ("code",)
CODE_CONFIG = ("code", "config")
ANY = ("code", "config", "doc", "other")

_PLACEHOLDER = re.compile(
    r"(example|sample|changeme|change_me|placeholder|your[_-]|xxx|\*\*\*|dummy|fake|redacted"
    r"|^none$|^null$|^true$|^false$|^test|\$\{|\$\(|\{\{|^<|^%|^\$|process\.env|os\.environ"
    r"|getenv|^env\.|secrets\.|vault:|^/|^\./|^https?:)",
    re.I,
)
_IDENTIFIER = re.compile(r"^(?:[A-Z][A-Z0-9_]+|[a-z]+(?:[_.-][a-z]+)+)$")


def entropy(value: str) -> float:
    counts = Counter(value)
    return -sum(c / len(value) * math.log2(c / len(value)) for c in counts.values())


def looks_like_secret(value: str) -> bool:
    return (not _PLACEHOLDER.search(value) and not _IDENTIFIER.match(value)
            and entropy(value) >= 3.0)


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    confidence: str
    scope: str
    pattern: Pattern[str]
    title: str
    fix: str
    kinds: Tuple[str, ...] = CODE
    skip_tests: bool = True
    only_tests: bool = False
    secret_group: Optional[int] = None
    validate: Optional[Callable[[str], bool]] = None
    extensions: Tuple[str, ...] = ()


def _r(id_, category, severity, confidence, scope, pattern, title, fix, **options) -> Rule:
    flags = options.pop("flags", 0)
    return Rule(id_, category, severity, confidence, scope, re.compile(pattern, flags),
                title, fix, **options)


_SQL = r"(?:select\s.+\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)"
_KEY_NAME = (r"[\w.-]*(?:password|passwd|pwd|secret|api[_-]?key|auth[_-]?token|access[_-]?token"
             r"|private[_-]?key|client[_-]?secret)[\w-]*")

RULES: List[Rule] = [
    # Security
    _r("SEC001", "security", "critical", "high", "raw",
       r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY", "Private key committed",
       "Remove the key, rotate it, and purge it from git history.",
       kinds=ANY, skip_tests=False),
    _r("SEC002", "security", "critical", "high", "raw",
       r"\b(AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_\w{40,}|xox[baprs]-[\w-]{20,}"
       r"|sk_live_\w{20,}|AIza[\w-]{35}|sk-ant-[\w-]{20,}|sk-[A-Za-z0-9]{32,})\b",
       "Provider credential in source",
       "Revoke the credential now and load its replacement from a secret manager.",
       kinds=ANY, skip_tests=False, secret_group=1, validate=lambda v: "EXAMPLE" not in v),
    _r("SEC003", "security", "high", "medium", "strings",
       _KEY_NAME + r"[\"']?\s*(?::=|=>|=|:)\s*[\"'`]([^\"'`\s]{8,})[\"'`]",
       "Hardcoded secret", "Read this value from the environment or a secret manager.",
       kinds=ANY, secret_group=1, validate=looks_like_secret, flags=re.I),
    _r("SEC004", "security", "high", "medium", "strings",
       r"^\s*(?:export\s+)?" + _KEY_NAME + r"\s*[=:]\s*([^\s\"'#]{8,})\s*$",
       "Hardcoded secret in configuration",
       "Keep the real value out of the repository and commit a placeholder.",
       kinds=("config",), secret_group=1, validate=looks_like_secret, flags=re.I),
    _r("SEC010", "security", "high", "medium", "code", r"(?<![\w.])(?<!def )(?<!function )(?<!func )(?:eval|exec)\s*\(",
       "Dynamic code execution", "Replace it with a parser or an explicit dispatch table."),
    _r("SEC011", "security", "high", "medium", "code",
       r"shell\s*=\s*True|\bos\.(?:system|popen)\s*\(|child_process.*\bexec(?:Sync)?\s*\("
       r"|(?<![\w.])execSync\s*\(|Runtime\.getRuntime\(\)\.exec|(?<![\w.])(?:shell_exec|passthru|popen)\s*\(",
       "Shell command execution",
       "Pass an argument list without a shell, and validate every input."),
    _r("SEC012", "security", "high", "medium", "strings",
       r"[fF][\"'][^\"']*\b" + _SQL + r"\b[^\"']*\{"
       r"|[\"'`][^\"'`]*\b" + _SQL + r"\b[^\"'`]*(?:[\"']\s*(?:\+|%\s*[\w(]|\.\s*format\s*\()|\$\{)"
       r"|(?:Sprintf|format)\s*\(\s*[\"'][^\"']*\b" + _SQL + r"\b",
       "SQL built from string formatting", "Use parameterized queries.", flags=re.I),
    _r("SEC013", "security", "high", "high", "code",
       r"\bpickle\.loads?\s*\(|\bmarshal\.loads?\s*\(|\byaml\.load\s*\((?!.*Safe)"
       r"|\bObjectInputStream\s*\(|\bBinaryFormatter\s*\(|(?<![\w.])unserialize\s*\(",
       "Unsafe deserialization", "Use a data-only format such as JSON, or a safe loader."),
    _r("SEC014", "security", "medium", "medium", "strings",
       r"\bhashlib\.(?:md5|sha1)\b|createHash\s*\(\s*[\"'](?:md5|sha1)[\"']"
       r"|MessageDigest\.getInstance\s*\(\s*\"(?:MD5|SHA-?1)\"|(?<![\w.])(?:md5|sha1)\s*\("
       r"|\bAES/ECB\b|\bMODE_ECB\b", "Weak cryptography",
       "Use SHA-256 or better, a password KDF for passwords, and an authenticated cipher mode."),
    _r("SEC015", "security", "high", "high", "strings",
       r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true"
       r"|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0|CERT_NONE|curl\s+(?:-\w+\s+)*(?:-k|--insecure)\b",
       "TLS verification disabled", "Keep verification on and trust the right CA instead.",
       kinds=CODE_CONFIG),
    _r("SEC016", "security", "high", "medium", "code",
       r"(?i)(?:token|secret|passw|salt|otp|nonce|session).*(?:Math\.random\s*\(|\brandom\.(?:random|randint|choice)\s*\(|(?<![\w.])rand\s*\()",
       "Predictable randomness for a secret value",
       "Use a cryptographic generator such as secrets or crypto.randomBytes."),
    _r("SEC017", "security", "high", "medium", "code",
       r"\.innerHTML\s*\+?=|\.outerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(|\bv-html\b"
       r"|\bmark_safe\s*\(", "Possible cross-site scripting sink",
       "Render as text or sanitize with a maintained library."),
    _r("SEC018", "security", "medium", "medium", "strings",
       r"Access-Control-Allow-Origin[\"']?\s*[,:=]\s*[\"']\*|allow_origins\s*=\s*\[\s*[\"']\*"
       r"|\borigin\s*:\s*[\"']\*[\"']|CORS_ORIGIN_ALLOW_ALL\s*=\s*True",
       "CORS open to every origin", "Allow only the origins you serve.", kinds=CODE_CONFIG),
    _r("SEC019", "security", "medium", "medium", "strings",
       r"(?i)(?<![\w-])debug\s*[:=]\s*[\"']?(?:true|1)\b", "Debug mode enabled",
       "Drive this from the environment and default it to off.", kinds=CODE_CONFIG),
    _r("SEC020", "security", "medium", "high", "strings",
       r"\bchmod\s+(?:-R\s+)?0?777\b|os\.chmod\([^)]*0o?777", "World-writable permissions",
       "Grant the narrowest permissions that work.", kinds=CODE_CONFIG),
    _r("SEC021", "security", "medium", "high", "strings",
       r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b", "Remote script piped to a shell",
       "Download, verify a checksum, then run it.", kinds=CODE_CONFIG),
    _r("SEC022", "security", "low", "medium", "strings",
       r"[\"'`]http://(?!localhost|127\.|0\.0\.0\.0|\[::1\]|www\.w3\.org|schemas\.|example\.)",
       "Plain HTTP endpoint", "Use HTTPS."),
    _r("SEC023", "security", "low", "medium", "code",
       r"^\s*FROM\s+[\w./-]+:latest\b|^\s*USER\s+root\b", "Risky container setting",
       "Pin the image version and run as a non-root user.", extensions=("",)),

    # Slop
    _r("SLP001", "slop", "high", "high", "raw",
       r"(?i)\bas an ai\b|\bas a large language model\b|here(?:'s| is) the (?:updated|revised|corrected|complete|full) (?:code|file|version|implementation)"
       r"|\bi hope this helps\b|\blet me know if you\b|\bi apologi[sz]e for\b|\bcertainly! ",
       "AI assistant text left in the code", "Delete it and re-check the code around it."),
    _r("SLP002", "slop", "high", "high", "comment",
       r"(?i)\b(?:rest of (?:the )?(?:code|file|function|implementation)|existing code|remaining code"
       r"|previous code)\b.{0,30}(?:here|unchanged|remains?|\.\.\.|same)"
       r"|\.\.\.\s*(?:existing|rest of|remaining|previous)\b"
       r"|\byour (?:code|logic|implementation) (?:goes )?here\b"
       r"|\b(?:add|insert|put|implement) (?:\w+ ){0,3}(?:logic|code|implementation) here\b",
       "Truncated or placeholder generated code",
       "Restore or write the missing code. It was probably lost in a paste."),
    _r("SLP003", "slop", "high", "high", "code", r"^\s*```[\w+-]*\s*$",
       "Markdown fence inside a source file", "Remove the fence and check for pasted chat text.",
       skip_tests=False),
    _r("SLP005", "slop", "medium", "medium", "strings",
       r"(?i)\blorem ipsum\b|\bjohn doe\b|\bjane doe\b|\bfoo@bar\b|\btest@test\.|\buser@example\.com\b"
       r"|\byour[_-]api[_-]key\b|\byour[_-](?:token|secret|password)\b|\bacme corp\b",
       "Placeholder data in production code", "Replace it with real data or configuration."),
    _r("SLP006", "slop", "low", "medium", "code",
       r"\bconsole\.(?:log|debug)\s*\(|\bSystem\.out\.print(?:ln)?\s*\(|\bvar_dump\s*\(|\bprint_r\s*\(",
       "Debug output left in code", "Remove it or use the project's logger."),
    _r("SLP007", "slop", "medium", "medium", "strings",
       r"(?i)\bprint\s*\(\s*f?[\"'](?:debug|here|test|xxx+|wtf|got here)\b",
       "Debug print left in code", "Remove it or use the project's logger."),
    _r("SLP008", "slop", "low", "low", "strings",
       r"@ts-ignore|@ts-nocheck|eslint-disable|#\s*type:\s*ignore|#\s*noqa|//\s*nolint"
       r"|@SuppressWarnings|#\[allow\(|\bas any\b",
       "Checker silenced", "Fix the underlying issue, or record why the suppression is safe."),
    _r("SLP009", "slop", "low", "low", "comment",
       r"[✅❌\U0001F680✨\U0001F525\U0001F389\U0001F4A1]",
       "Decorative emoji in a code comment", "Use plain wording."),

    # Gaps
    _r("GAP001", "gap", "high", "high", "strings",
       r"\braise\s+NotImplementedError\b|\bunimplemented!\s*\(|\btodo!\s*\("
       r"|(?i:(?:throw\s+new\s+\w*(?:Error|Exception)|panic)\s*\(\s*[\"'`]\s*(?:not\s*implemented|todo|implement\s*me))"
       r"|\bNotImplementedException\b|\bUnsupportedOperationException\s*\(\s*\"?(?i:not implemented)?\"?\s*\)",
       "Unimplemented code path", "Implement it, or remove the path that reaches it."),
    _r("GAP002", "gap", "medium", "high", "code", r"^\s*except\s*:",
       "Bare except", "Catch specific exceptions."),
    _r("GAP003", "gap", "medium", "high", "code", r"\brescue\s+nil\b",
       "Error silently discarded", "Handle or report the error."),

    # Loose ends
    _r("END001", "loose-end", "medium", "high", "comment", r"\b(?:FIXME|BUG|HACK|XXX)\b",
       "Known problem marked in a comment", "Fix it or track it in an issue.", skip_tests=False,
       kinds=CODE_CONFIG),
    _r("END002", "loose-end", "low", "high", "comment", r"\bTODO\b",
       "TODO comment", "Finish it or track it in an issue.", skip_tests=False, kinds=CODE_CONFIG),
    _r("END003", "loose-end", "low", "medium", "comment",
       r"(?i)\b(?:temporary|temp fix|quick fix|workaround|for now|remove (?:this )?(?:later|before)|should be removed)\b",
       "Temporary code never cleaned up", "Replace it with the lasting fix.", kinds=CODE_CONFIG),
    _r("END004", "loose-end", "critical", "high", "raw", r"^(?:<{7} |>{7} )",
       "Unresolved merge conflict", "Resolve the conflict.", kinds=ANY, skip_tests=False),
    _r("END005", "loose-end", "high", "high", "code",
       r"^\s*debugger\s*;?\s*$|\bpdb\.set_trace\s*\(|(?<![\w.])breakpoint\s*\(\s*\)"
       r"|\bbinding\.(?:pry|irb)\b|^\s*byebug\s*$|(?<![\w.])dd\s*\(\s*\$",
       "Debugger statement left in code", "Remove it.", skip_tests=False),
    _r("END006", "loose-end", "high", "high", "code",
       r"\b(?:describe|it|test|context)\.only\s*\(|(?<![\w.])(?:fdescribe|fit)\s*\(",
       "Focused test hides the rest of the suite", "Remove the focus.",
       skip_tests=False, only_tests=True),
    _r("END007", "loose-end", "medium", "high", "strings",
       r"\b(?:describe|it|test)\.skip\s*\(|(?<![\w.])(?:xit|xdescribe)\s*\(|@pytest\.mark\.skip\b"
       r"|@unittest\.skip\b|^\s*@(?:Ignore|Disabled)\b|\bt\.Skip(?:f|Now)?\s*\(|#\[ignore\]",
       "Skipped test", "Fix and re-enable it, or delete it.", skip_tests=False, only_tests=True),
    _r("END008", "loose-end", "low", "low", "strings", r"\b(?:localhost|127\.0\.0\.1):\d{2,5}\b",
       "Hardcoded local address", "Move it into configuration."),
]

RULE_INDEX = {rule.id: rule for rule in RULES}
SECRET_RULES = [rule for rule in RULES if rule.secret_group]

STRUCTURAL_RULES = {
    "SLP004": ("slop", "Comments restate the code"),
    "SLP010": ("slop", "Duplicated code block"),
    "SLP011": ("slop", "Version-suffixed file name"),
    "GAP010": ("gap", "Stub function with no body"),
    "GAP011": ("gap", "Error swallowed"),
    "GAP012": ("gap", "Import points at a missing file"),
    "GAP013": ("gap", "Broken documentation link"),
    "GAP014": ("gap", "Environment variable undocumented"),
    "GAP015": ("gap", "Project basics missing"),
    "GAP016": ("gap", "Empty source file"),
    "END010": ("loose-end", "Commented-out code"),
    "END011": ("loose-end", "Unreachable code"),
    "END012": ("loose-end", "Leftover file committed"),
    "SEC030": ("security", "Sensitive file committed"),
}


def redact(line: str) -> str:
    """Mask anything a secret rule recognizes before it is shown or sent anywhere."""
    for rule in SECRET_RULES:
        def mask(match: "re.Match[str]") -> str:
            value = match.group(rule.secret_group)
            if rule.validate and not rule.validate(value):
                return match.group(0)
            return match.group(0).replace(value, value[:2] + "****")
        line = rule.pattern.sub(mask, line)
    if RULE_INDEX["SEC001"].pattern.search(line):
        return "[private key redacted]"
    return line
