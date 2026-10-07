import hashlib
import io
import json
import tempfile
import threading
import unittest
import urllib.parse
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import param_mine


class TestHandler(BaseHTTPRequestHandler):
    changed_path_hits = 0

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/changed")
            self.end_headers()
            return
        if parsed.path == "/changed":
            type(self).changed_path_hits += 1
        if parsed.path == "/large":
            body = b"x" * (param_mine.MAX_RESPONSE_BYTES + 100)
        elif "feature" in query:
            body = b"feature enabled"
        else:
            body = b"baseline"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string, *args):
        return


class ParamMineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), TestHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join()

    def test_scan_reports_response_change_and_redacts_query_values(self):
        url = self.base_url + "/scan?token=secret&blank=&dup=1&dup=2"
        findings, errors, stable = param_mine.scan(
            url, ["feature", "missing"], {}, 2, 2, 100
        )

        self.assertTrue(stable)
        self.assertEqual(errors, [])
        self.assertEqual([item["param"] for item in findings], ["feature"])
        self.assertTrue(findings[0]["body_changed"])
        self.assertIn("body changed", findings[0]["diff"])
        self.assertNotIn("secret", json.dumps(findings))
        self.assertIn("%3Credacted%3E", findings[0]["url"])

    def test_query_building_preserves_blank_and_duplicate_values(self):
        probe = param_mine.build_probe_url(
            "https://example.test/p?a=&dup=1&dup=2&x=old", "x"
        )
        query = urllib.parse.parse_qsl(
            urllib.parse.urlsplit(probe).query, keep_blank_values=True
        )
        self.assertEqual(query, [("a", ""), ("dup", "1"), ("dup", "2"), ("x", "FUZZ")])

    def test_redirects_are_not_followed(self):
        TestHandler.changed_path_hits = 0
        findings, errors, stable = param_mine.scan(
            self.base_url + "/redirect", ["feature"], {}, 1, 2, 100
        )
        self.assertTrue(stable)
        self.assertEqual(findings, [])
        self.assertEqual(errors, [])
        self.assertEqual(TestHandler.changed_path_hits, 0)

    def test_response_read_is_bounded(self):
        result = param_mine.fetch_response(
            self.base_url + "/large", {}, 2, param_mine.RateLimiter(100)
        )
        self.assertEqual(result.length, param_mine.MAX_RESPONSE_BYTES)
        self.assertTrue(result.truncated)

    def test_unstable_baseline_ignores_body_only_changes(self):
        fingerprints = [
            param_mine.ResponseFingerprint(200, 8, digest, False)
            for digest in ("first", "second")
        ]
        response = param_mine.ResponseFingerprint(200, 8, "third", False)
        finding = param_mine.compare_response(
            "probe", response, fingerprints, False, "https://example.test/?token=x"
        )
        self.assertIsNone(finding)

    def test_wordlist_deduplicates_and_enforces_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            wordlist = Path(directory) / "params.txt"
            wordlist.write_text("# comment\nalpha\nalpha\nbeta\n", encoding="utf-8")
            self.assertEqual(
                param_mine.load_parameters(str(wordlist), 2), ["alpha", "beta"]
            )
            with self.assertRaises(param_mine.ScanError):
                param_mine.load_parameters(str(wordlist), 1)

    def test_target_validation_rejects_non_http_and_url_credentials(self):
        for target in ("file:///etc/passwd", "https://user:pass@example.test/"):
            with self.subTest(target=target), self.assertRaises(param_mine.ScanError):
                param_mine.normalize_target_url(target)

    def test_header_validation_requires_a_single_line_header(self):
        with self.assertRaises(param_mine.ScanError):
            param_mine.validate_headers(["X-Test: ok\r\nInjected: yes"])

    def test_fingerprint_uses_sha256(self):
        expected = hashlib.sha256(b"baseline").hexdigest()
        response = param_mine.fetch_response(
            self.base_url + "/scan", {}, 2, param_mine.RateLimiter(100)
        )
        self.assertEqual(response.body_sha256, expected)

    def test_baseline_network_failure_is_not_reported_as_empty_scan(self):
        with patch.object(
            param_mine.HTTP_OPENER,
            "open",
            side_effect=urllib.error.URLError("offline"),
        ):
            with self.assertRaisesRegex(param_mine.ScanError, "baseline request failed"):
                param_mine.scan(
                    self.base_url + "/scan", ["feature"], {}, 1, 2, 100
                )

    def test_parameter_network_failures_are_reported_with_nonzero_exit(self):
        baseline_body = hashlib.sha256(b"baseline").hexdigest()
        baseline = param_mine.ResponseFingerprint(200, 8, baseline_body, False)
        changed_body = hashlib.sha256(b"feature enabled").hexdigest()
        changed = param_mine.ResponseFingerprint(200, 15, changed_body, False)
        with tempfile.TemporaryDirectory() as directory:
            wordlist = Path(directory) / "params.txt"
            wordlist.write_text("failed\nfeature\n", encoding="utf-8")
            with patch(
                "param_mine.fetch_response",
                side_effect=[
                    baseline,
                    baseline,
                    urllib.error.URLError("offline"),
                    changed,
                ],
            ):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    exit_code = param_mine.main(
                        [
                            self.base_url + "/scan",
                            "--wordlist",
                            str(wordlist),
                            "--threads",
                            "1",
                            "--rate-limit",
                            "100",
                        ]
                    )
        self.assertEqual(exit_code, 1)
        self.assertIn("param=failed: request failed (URLError: offline)", stderr.getvalue())
        self.assertIn("1 potentially interesting parameters found", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
