# SlopSweep report

8 files scanned. **47 findings** (27 high, 15 medium, 5 low).

## Security (20)

| Severity | Rule | Location | Issue | Fix |
|---|---|---|---|---|
| high | SEC013 | `Payments.java:10` | Unsafe deserialization | Use a data-only format such as JSON, or a safe loader. |
| high | SEC003 | `app.py:10` | Hardcoded secret | Read this value from the environment or a secret manager. |
| high | SEC012 | `app.py:17` | SQL built from string formatting | Use parameterized queries. |
| high | SEC011 | `app.py:21` | Shell command execution | Pass an argument list without a shell, and validate every input. |
| high | SEC011 | `app.py:22` | Shell command execution | Pass an argument list without a shell, and validate every input. |
| high | SEC013 | `app.py:26` | Unsafe deserialization | Use a data-only format such as JSON, or a safe loader. |
| high | SEC010 | `app.py:34` | Dynamic code execution | Replace it with a parser or an explicit dispatch table. |
| high | SEC004 | `config.yaml:3` | Hardcoded secret in configuration | Keep the real value out of the repository and commit a placeholder. |
| high | SEC015 | `main.go:11` | TLS verification disabled | Keep verification on and trust the right CA instead. |
| high | SEC012 | `main.go:16` | SQL built from string formatting | Use parameterized queries. |
| high | SEC016 | `server.js:5` | Predictable randomness for a secret value | Use a cryptographic generator such as secrets or crypto.randomBytes. |
| high | SEC017 | `server.js:8` | Possible cross-site scripting sink | Render as text or sanitize with a maintained library. |
| high | SEC011 | `server.js:14` | Shell command execution | Pass an argument list without a shell, and validate every input. |
| high | SEC012 | `server.js:23` | SQL built from string formatting | Use parameterized queries. |
| medium | SEC014 | `Payments.java:8` | Weak cryptography | Use SHA-256 or better, a password KDF for passwords, and an authenticated cipher mode. |
| medium | SEC019 | `app.py:11` | Debug mode enabled | Drive this from the environment and default it to off. |
| medium | SEC014 | `app.py:30` | Weak cryptography | Use SHA-256 or better, a password KDF for passwords, and an authenticated cipher mode. |
| medium | SEC019 | `config.yaml:2` | Debug mode enabled | Drive this from the environment and default it to off. |
| medium | SEC021 | `deploy.sh:2` | Remote script piped to a shell | Download, verify a checksum, then run it. |
| medium | SEC020 | `deploy.sh:3` | World-writable permissions | Grant the narrowest permissions that work. |

## Slop (6)

| Severity | Rule | Location | Issue | Fix |
|---|---|---|---|---|
| high | SLP002 | `app.py:60` | Truncated or placeholder generated code | Restore or write the missing code. It was probably lost in a paste. |
| high | SLP001 | `server.js:28` | AI assistant text left in the code | Delete it and re-check the code around it. |
| medium | SLP007 | `app.py:54` | Debug print left in code | Remove it or use the project's logger. |
| low | SLP006 | `Payments.java:9` | Debug output left in code | Remove it or use the project's logger. |
| low | SLP011 | `helpers_final.py` | Version-suffixed file name: Version control should hold old versions, not file names. | Keep one canonical file. |
| low | SLP006 | `server.js:9` | Debug output left in code | Remove it or use the project's logger. |

## Coding gaps (15)

| Severity | Rule | Location | Issue | Fix |
|---|---|---|---|---|
| high | GAP011 | `Payments.java:16` | Error swallowed: The failure is caught and dropped without any handling. | Handle it, log it, or let it propagate. |
| high | GAP012 | `app.py:8` | Import points at a missing file: `.helpers` does not resolve inside this repository. | Add the missing module or correct the path. Generated code often invents these. |
| high | GAP001 | `app.py:42` | Unimplemented code path | Implement it, or remove the path that reaches it. |
| high | GAP011 | `app.py:48` | Error swallowed: The exception is caught and dropped without any handling. | Handle it, log it, or let it propagate. |
| high | GAP001 | `lib.rs:3` | Unimplemented code path | Implement it, or remove the path that reaches it. |
| high | GAP011 | `main.go:18` | Error swallowed: The failure is caught and dropped without any handling. | Handle it, log it, or let it propagate. |
| high | GAP001 | `main.go:23` | Unimplemented code path | Implement it, or remove the path that reaches it. |
| high | GAP012 | `server.js:2` | Import points at a missing file: `./billing/invented-module` does not resolve inside this repository. | Add the missing module or correct the path. Generated code often invents these. |
| high | GAP011 | `server.js:19` | Error swallowed: The failure is caught and dropped without any handling. | Handle it, log it, or let it propagate. |
| high | GAP011 | `server.js:24` | Error swallowed: The failure is caught and dropped without any handling. | Handle it, log it, or let it propagate. |
| medium | GAP015 | `.` | Project has no README: The repository has no README. | Explain what the project does and how to run it. |
| medium | GAP010 | `Payments.java:5` | Stub function with no body: The function is declared but does nothing. | Implement it or delete it. |
| medium | GAP010 | `app.py:37` | Stub function with no body: `send_invoice` is declared but does nothing. | Implement it or delete it. |
| medium | GAP010 | `lib.rs:6` | Stub function with no body: The function is declared but does nothing. | Implement it or delete it. |
| medium | GAP010 | `server.js:17` | Stub function with no body: The function is declared but does nothing. | Implement it or delete it. |

## Loose ends (6)

| Severity | Rule | Location | Issue | Fix |
|---|---|---|---|---|
| high | END005 | `server.js:10` | Debugger statement left in code | Remove it. |
| medium | END011 | `app.py:54` | Unreachable code: Line 53 always exits first. | Delete it or fix the control flow. |
| medium | END001 | `app.py:58` | Known problem marked in a comment | Fix it or track it in an issue. |
| medium | END001 | `lib.rs:2` | Known problem marked in a comment | Fix it or track it in an issue. |
| low | END002 | `app.py:57` | TODO comment | Finish it or track it in an issue. |
| low | END010 | `app.py:64` | Commented-out code: 4 consecutive lines of disabled code. | Delete it. Version control keeps the history. |
