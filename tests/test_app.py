import http.client
import json
import os
import sys
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app import MAX_BODY_BYTES, MAX_FILES, create_server  # noqa: E402


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = create_server("127.0.0.1", 0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def request(self, method, path, payload=None, raw=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=10)
        body = raw if raw is not None else (json.dumps(payload) if payload is not None else None)
        connection.request(method, path, body=body)
        response = connection.getresponse()
        data = json.loads(response.read())
        connection.close()
        return response.status, data

    def test_health(self):
        self.assertEqual(self.request("GET", "/health"), (200, {"ok": True}))

    def test_scan_reports_findings_without_leaking_secrets(self):
        secret = "q7Zp2Lx9Vt4Rk8Mn3Bw6"
        status, data = self.request("POST", "/scan", {"files": {
            "src/app.py": f'API_SECRET = "{secret}"\neval(user_input)\n',
        }})
        self.assertEqual(status, 200)
        self.assertEqual(data["files_scanned"], 1)
        self.assertLessEqual({"SEC003", "SEC010"}, {f["rule"] for f in data["findings"]})
        self.assertNotIn(secret, json.dumps(data))

    def test_path_traversal_is_rejected(self):
        for path in ("../evil.py", "/evil.py", "a/../../evil.py", "C:/evil.py", "a\\evil.py"):
            self.assertEqual(self.request("POST", "/scan", {"files": {path: "x"}}),
                             (400, {"error": "invalid_path"}), path)

    def test_invalid_requests(self):
        self.assertEqual(self.request("POST", "/scan", raw="{"), (400, {"error": "invalid_json"}))
        self.assertEqual(self.request("POST", "/scan", {"files": {}}),
                         (400, {"error": "files_required"}))
        self.assertEqual(self.request("POST", "/scan", {"files": {"a.py": 1}}),
                         (400, {"error": "invalid_content"}))
        self.assertEqual(self.request("GET", "/missing"), (404, {"error": "not_found"}))

    def test_limits(self):
        files = {f"f{i}.py": "x = 1\n" for i in range(MAX_FILES + 1)}
        self.assertEqual(self.request("POST", "/scan", {"files": files}),
                         (400, {"error": "too_many_files"}))
        status, data = self.request("POST", "/scan", raw="x" * (MAX_BODY_BYTES + 1))
        self.assertEqual((status, data), (413, {"error": "body_size"}))


if __name__ == "__main__":
    unittest.main()
