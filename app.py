"""HTTP entry point: GET /health and POST /scan."""

from __future__ import annotations

import json
import os
import tempfile
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Tuple

from slopsweep.scanner import scan

MAX_BODY_BYTES = 2_000_000
MAX_FILES = 200
_scan_slots = threading.BoundedSemaphore(4)


class BadRequest(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _safe_path(path: Any) -> str:
    if not isinstance(path, str) or not path or len(path) > 300:
        raise BadRequest("invalid_path")
    parts = path.split("/")
    if "\\" in path or ":" in path or "\0" in path or any(p in ("", ".", "..") for p in parts):
        raise BadRequest("invalid_path")
    return path


def scan_files(files: Any) -> Dict[str, Any]:
    if not isinstance(files, dict) or not files:
        raise BadRequest("files_required")
    if len(files) > MAX_FILES:
        raise BadRequest("too_many_files")
    with tempfile.TemporaryDirectory(prefix="slopsweep-") as root:
        for raw_path, content in files.items():
            path = _safe_path(raw_path)
            if not isinstance(content, str):
                raise BadRequest("invalid_content")
            target = os.path.join(root, *path.split("/"))
            try:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "w", encoding="utf-8", newline="") as handle:
                    handle.write(content)
            except (OSError, UnicodeError) as exc:
                raise BadRequest("invalid_path") from exc
        result, _ = scan(root)
    return {
        "files_scanned": result.files_scanned,
        "summary": dict(Counter(f.severity for f in result.findings)),
        "findings": [f.to_dict() for f in result.findings],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "SlopSweep"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(10)

    def reply(self, status: int, data: Dict[str, Any]) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/health":
            self.reply(200, {"ok": True})
        else:
            self.reply(404, {"error": "not_found"})

    def _discard(self, size: int) -> None:
        """Read a bounded rejected body so the client can receive the error."""
        remaining = min(max(size, 0), MAX_BODY_BYTES * 2)
        try:
            while remaining:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    return
                remaining -= len(chunk)
        except OSError:
            return

    def _read_json(self) -> Tuple[int, Any]:
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return 400, {"error": "invalid_length"}
        if not 1 <= size <= MAX_BODY_BYTES:
            self._discard(size)
            return 413, {"error": "body_size"}
        try:
            return 200, json.loads(self.rfile.read(size))
        except (ValueError, UnicodeError):
            return 400, {"error": "invalid_json"}
        except TimeoutError:
            return 408, {"error": "timeout"}

    def do_POST(self) -> None:
        if self.path != "/scan":
            self.reply(404, {"error": "not_found"})
            return
        status, data = self._read_json()
        if status != 200:
            self.close_connection = True
            self.reply(status, data)
            return
        if not isinstance(data, dict):
            self.reply(400, {"error": "files_required"})
            return
        if not _scan_slots.acquire(blocking=False):
            self.reply(503, {"error": "busy"})
            return
        try:
            self.reply(200, scan_files(data.get("files")))
        except BadRequest as exc:
            self.reply(400, {"error": exc.code})
        finally:
            _scan_slots.release()

    def log_message(self, *_args: Any) -> None:
        """Submitted code and client addresses are not logged."""


def create_server(host: str, port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


if __name__ == "__main__":
    create_server(os.getenv("HOST", "0.0.0.0"), int(os.getenv("PORT", "8000"))).serve_forever()
