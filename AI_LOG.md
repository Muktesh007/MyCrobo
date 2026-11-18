# AI Log

## Summary

Muktesh Naidu Chandaka directed the work using **Claude Code** with **Claude Opus 5.5** (`claude-opus-5-5`) and published the files to this repository through the GitHub website and made the requested repository edits.

All times are IST on 18 November 2026.

## Who did what

| Contributor | Contribution |
|---|---|
| Claude | Interpreted the brief, designed the architecture, wrote the code, tests, samples, README and CI, ran the checks, and diagnosed failures |
| Muktesh Naidu Chandaka | Requested the build, supplied the assignment, reviewed progress, and relayed platform and CI results. Created the repository, uploaded the files, and applied the fixes through GitHub |

## Timeline

| Time | Prompt or event | AI output | Human or verification result |
|---|---|---|---|
| About 15:13 | Asked Claude to read the assignment email | Summarized the requirement, deadline and submission route | Muktesh asked it to start building |
| 15:15 to 15:28 | "Yes, start building" | Wrote the lexer, rules, structural checks, agent loop, reports, CLI, samples and tests | First run: 13 of 16 tests passed |
| About 15:28 | Test failures reviewed by Claude | Fixed a false positive for `shell=True` inside strings and a faulty test | 16 of 16 tests passed |
| 15:28 to 15:33 | Claude scanned a real 1,424-file SDK | Tightened noisy rules and sped up the lexer | Findings fell from 1,873 to 172, and scan time fell from about 64 to 24 seconds |
| 15:33 to 15:37 | End-to-end checks | Fixed ignored test folders being reported as missing tests, a crash without API credentials, and closed-pipe handling | 22 of 22 tests passed, and a clean install worked |
| 15:40 | Asked for a zip | Packaged the project and tested a fresh extract | 22 of 22 tests passed |
| 16:21 | Files uploaded to GitHub | Compared the repository with the build | Two files were missing, and two tests failed without them |
| 16:26 to 16:27 | Missing files added through GitHub | Rechecked the repository | All files matched, but CI failed |
| 16:33 to 16:34 | CI could not find Python 3.9 on Ubuntu 26.04 | Moved the supported versions to Python 3.11 and 3.13 | CI passed on both versions |
| 16:36 to 16:45 | Platform required `arena.json`, and an example file was provided | Added `arena.json`, `requirements.txt`, an HTTP API and API tests, based on the format in a public Arena smoke-test repository | Tests and the declared install, test and start commands passed from a fresh extract |

## Key AI decisions

- Used one small lexer that understands comments and strings, so the rules work without a parser for each language.
- Kept scanning dependency-free and made the Claude review optional.
- Made the agent's tools read-only, masked secrets, withheld sensitive files, and required quoted evidence for agent-added findings.
- Treated repository text as untrusted to reduce prompt-injection risk.
- Added a small API because the example Arena project declares start and port commands. The track's hidden-test contract was not available, so `/scan` is this project's own design.

## Known limits

- The Claude review mode was tested with a simulated API client. It has not completed a live API run.
- The scanner matches text patterns and does not perform full data-flow analysis.
- Local testing used Python 3.11 on Windows. GitHub CI covers Python 3.11 and 3.13 on Ubuntu.
