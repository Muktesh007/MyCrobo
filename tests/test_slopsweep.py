import json
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from slopsweep.agent import TOOLS, Workspace, run_agent  # noqa: E402
from slopsweep.cli import main  # noqa: E402
from slopsweep.rules import redact  # noqa: E402
from slopsweep.scanner import scan  # noqa: E402
from slopsweep.source import PYTHON, C_LIKE, lex  # noqa: E402

MESSY = os.path.join(ROOT, "examples", "messy_app")
CLEAN = os.path.join(ROOT, "examples", "clean_app")


def repo(files):
    directory = tempfile.TemporaryDirectory()
    for name, content in files.items():
        path = os.path.join(directory.name, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
    return directory


def rules_for(files):
    with repo(files) as directory:
        return {f.rule for f in scan(directory)[0].findings}


class LexerTests(unittest.TestCase):
    def test_separates_code_strings_and_comments(self):
        view = lex(['x = "eval(1)"  # TODO later'], PYTHON)[0]
        self.assertNotIn("eval", view.code)
        self.assertIn("eval", view.code_str)
        self.assertIn("TODO", view.comment)

    def test_block_comment_spans_lines(self):
        views = lex(["a(); /* one", "two */ b();"], C_LIKE)
        self.assertEqual(views[0].code.strip(), "a();")
        self.assertIn("two", views[1].comment)
        self.assertIn("b()", views[1].code)

    def test_url_in_string_is_not_a_comment(self):
        self.assertEqual(lex(['u = "http://a.b";'], C_LIKE)[0].comment, "")


class ScannerTests(unittest.TestCase):
    def test_messy_sample_covers_every_category_across_languages(self):
        result, _ = scan(MESSY)
        found = {(f.rule, os.path.splitext(f.file)[1]) for f in result.findings}
        expected = {
            ("SEC003", ".py"), ("SEC012", ".py"), ("SEC011", ".py"), ("SEC013", ".py"),
            ("SEC014", ".py"), ("SEC010", ".py"), ("GAP010", ".py"), ("GAP001", ".py"),
            ("GAP011", ".py"), ("GAP012", ".py"), ("END011", ".py"), ("END001", ".py"),
            ("END002", ".py"), ("END010", ".py"), ("SLP002", ".py"),
            ("SEC016", ".js"), ("SEC017", ".js"), ("SEC012", ".js"), ("GAP010", ".js"),
            ("GAP011", ".js"), ("GAP012", ".js"), ("END005", ".js"), ("SLP001", ".js"),
            ("SEC015", ".go"), ("SEC012", ".go"), ("GAP011", ".go"), ("GAP001", ".go"),
            ("SEC013", ".java"), ("SEC014", ".java"), ("GAP010", ".java"), ("GAP011", ".java"),
            ("GAP001", ".rs"), ("GAP010", ".rs"), ("END001", ".rs"),
            ("SEC004", ".yaml"), ("SEC019", ".yaml"), ("SEC021", ".sh"), ("SEC020", ".sh"),
            ("SLP011", ".py"),
        }
        self.assertEqual(expected - found, set())

    def test_clean_sample_has_no_findings(self):
        result, _ = scan(CLEAN)
        self.assertEqual([(f.rule, f.file, f.line) for f in result.findings], [])

    def test_inline_ignore(self):
        self.assertNotIn("SEC010", rules_for({"a.py": "eval(x)  # slopsweep: ignore=SEC010\n"}))

    def test_gitignored_files_are_skipped(self):
        found = rules_for({".gitignore": "secret.py\n", "secret.py": "eval(x)\n", "a.py": "y = 1\n"})
        self.assertNotIn("SEC010", found)

    def test_unknown_extension_still_gets_secret_scan(self):
        token = "gh" + "p_" + "a1B2" * 10
        self.assertIn("SEC002", rules_for({"notes.custom": f"key {token}\n"}))

    def test_duplicates_and_merge_conflicts(self):
        block = "".join(f"value_{i} = compute({i})\n" for i in range(10))
        found = rules_for({"a.py": block, "b.py": block, "c.txt": "<<<<<<< HEAD\n"})
        self.assertLessEqual({"SLP010", "END004"}, found)

    def test_repository_basics_and_sensitive_files(self):
        found = rules_for({"a.py": "x = 1\n", "b.py": "y = 2\n", "c.py": "z = 3\n", "prod.pem": "k"})
        self.assertLessEqual({"GAP015", "SEC030"}, found)

    def test_ignored_test_folder_still_counts_as_tests(self):
        files = {"a.py": "x = 1\n", "b.py": "y = 2\n", "c.py": "z = 3\n", "README.md": "r\n",
                 ".gitignore": "x\n", ".slopsweepignore": "tests/\n", "tests/test_a.py": "t = 1\n"}
        self.assertNotIn("GAP015", rules_for(files))

    def test_secret_never_appears_in_output(self):
        secret = "q7Zp2Lx9Vt4Rk8Mn3Bw6"
        result, _ = scan(MESSY)
        self.assertNotIn(secret, json.dumps([f.to_dict() for f in result.findings]))
        self.assertNotIn(secret, redact(f'API_SECRET = "{secret}"'))


class NoiseRegressionTests(unittest.TestCase):
    """Each case is a false positive found by scanning a large real SDK."""

    def test_documentation_and_typing_idioms_stay_quiet(self):
        source = (
            'from typing import overload\n'
            'ENV_API_KEY = "ANTHROPIC_API_KEY"\n\n'
            'class Client:\n'
            '    """Use it like this:\n\n    ```py\n    Client()\n    ```\n\n'
            '    The value stays the same.\n    """\n\n'
            '    def next_page(self) -> int: ...\n\n'
            '    async def exec(self, command):\n'
            '        raise NotImplementedError(f"Unknown command: {command}")\n'
        )
        self.assertEqual(rules_for({"README.md": "x\n", ".gitignore": "x\n",
                                    "test_a.py": "x = 1\n", "client.py": source}), set())

    def test_long_docstring_does_not_hide_the_function_body(self):
        docstring = "".join(f"    line {i}\\n" for i in range(60))
        source = f'def work():\\n    """Summary.\\n{docstring}    """\\n    return 1\\n'
        self.assertNotIn("GAP010", rules_for({"a.py": source}))

    def test_specific_exception_is_low_but_broad_exception_is_high(self):
        source = ("def a():\n    try:\n        b()\n    except KeyError:\n        pass\n"
                  "def c():\n    try:\n        b()\n    except Exception:\n        pass\n")
        with repo({"a.py": source}) as directory:
            found = [f.severity for f in scan(directory)[0].findings if f.rule == "GAP011"]
        self.assertEqual(sorted(found), ["high", "low"])

    def test_signature_overloads_are_not_duplicates_and_pairs_are_merged(self):
        signature = "".join(f"    arg_number_{i}: int = {i},\n" for i in range(12))
        overloads = f"def f(\n{signature}) -> int:\n    return 1\n"
        self.assertNotIn("SLP010", rules_for({"a.py": overloads, "b.py": overloads}))
        logic = "".join(f"value_{i} = compute({i})\n" for i in range(30))
        with repo({"a.py": logic, "b.py": logic}) as directory:
            hits = [f for f in scan(directory)[0].findings if f.rule == "SLP010"]
        self.assertEqual(len(hits), 1)


def block(kind, **fields):
    return SimpleNamespace(type=kind, **fields)


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.responses.pop(0)


def reply(stop, *content):
    return SimpleNamespace(stop_reason=stop, content=list(content),
                           usage=SimpleNamespace(input_tokens=10, output_tokens=5))


class AgentTests(unittest.TestCase):
    def test_tools_are_strict_with_complete_required_lists(self):
        for tool in TOOLS:
            schema = tool["input_schema"]
            self.assertTrue(tool["strict"])
            self.assertEqual(set(schema["required"]), set(schema["properties"]))

    def test_review_loop_applies_verdicts_and_verified_findings(self):
        with repo({"a.py": "eval(data)\nvalue = 1\n"}) as directory:
            result, source_repo = scan(directory)
            target = next(f for f in result.findings if f.rule == "SEC010")
            client = FakeClient([
                reply("tool_use",
                      block("tool_use", id="1", name="read_file",
                            input={"path": "a.py", "start_line": 1, "end_line": 2}),
                      block("tool_use", id="2", name="record_verdict",
                            input={"finding_id": target.id, "verdict": "false_positive",
                                   "reason": "Constant input.", "severity": "unchanged"})),
                reply("tool_use",
                      block("tool_use", id="3", name="add_finding",
                            input={"category": "gap", "severity": "low", "file": "a.py", "line": 2,
                                   "evidence": "not in file", "title": "T", "explanation": "E",
                                   "fix": "F"})),
                reply("tool_use",
                      block("tool_use", id="4", name="add_finding",
                            input={"category": "gap", "severity": "low", "file": "a.py", "line": 2,
                                   "evidence": "value = 1", "title": "Unused", "explanation": "E",
                                   "fix": "F"}),
                      block("tool_use", id="5", name="finish", input={"summary": "Done."})),
            ])
            outcome = run_agent(result, source_repo, client=client)

        self.assertEqual(outcome["status"], "complete")
        self.assertEqual(outcome["summary"], "Done.")
        self.assertNotIn(target, result.visible())
        self.assertEqual([f.title for f in result.findings if f.source == "agent"], ["Unused"])
        results = [item for message in client.calls[0]["messages"]
                   if message["role"] == "user" and isinstance(message["content"], list)
                   for item in message["content"]]
        self.assertEqual([r["tool_use_id"] for r in results if r["is_error"]], ["3"])
        self.assertEqual(client.calls[0]["model"], "claude-opus-5-5")
        self.assertEqual(client.calls[0]["fallbacks"], "default")

    def test_missing_credentials_keep_scanner_results(self):
        class NoCredentials(FakeClient):
            def create(self, **kwargs):
                raise TypeError("Could not resolve authentication method.")

        with repo({"a.py": "eval(data)\n"}) as directory:
            result, source_repo = scan(directory)
            outcome = run_agent(result, source_repo, client=NoCredentials([]))
        self.assertEqual(outcome["status"], "failed")
        self.assertIn("ANTHROPIC_API_KEY", outcome["summary"])
        self.assertTrue(result.findings)

    def test_refusal_keeps_scanner_results(self):
        with repo({"a.py": "eval(data)\n"}) as directory:
            result, source_repo = scan(directory)
            before = len(result.findings)
            outcome = run_agent(result, source_repo, client=FakeClient([reply("refusal")]))
        self.assertEqual(outcome["status"], "refused")
        self.assertEqual(len(result.findings), before)

    def test_workspace_withholds_sensitive_files_and_masks_secrets(self):
        secret = "q7Zp2Lx9Vt4Rk8Mn3Bw6"
        with repo({"a.py": f'API_SECRET = "{secret}"\n', "x.pem": "key\n"}) as directory:
            result, source_repo = scan(directory)
            workspace = Workspace(result, source_repo)
            text, failed = workspace.execute(
                "read_file", {"path": "a.py", "start_line": 1, "end_line": 1})
            self.assertFalse(failed)
            self.assertNotIn(secret, text)
            _, denied = workspace.execute(
                "read_file", {"path": "x.pem", "start_line": 1, "end_line": 1})
            self.assertTrue(denied)
            _, escaped = workspace.execute(
                "read_file", {"path": "../a.py", "start_line": 1, "end_line": 1})
            self.assertTrue(escaped)


class CliTests(unittest.TestCase):
    def test_fail_on_and_output_formats(self):
        with tempfile.TemporaryDirectory() as out:
            for fmt in ("json", "sarif", "markdown", "text"):
                target = os.path.join(out, "report." + fmt)
                self.assertEqual(main([MESSY, "-f", fmt, "-o", target, "--fail-on", "high"]), 1)
                self.assertGreater(os.path.getsize(target), 100)
            with open(os.path.join(out, "report.sarif"), encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["version"], "2.1.0")
            clean = os.path.join(out, "clean.txt")
            self.assertEqual(main([CLEAN, "-o", clean, "--fail-on", "low"]), 0)


if __name__ == "__main__":
    unittest.main()
