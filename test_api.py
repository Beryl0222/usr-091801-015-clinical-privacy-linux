"""HTTP API 测试：健康端点保持兼容，/v1/* 覆盖核心流程。"""

import json
import threading
import unittest
from datetime import timedelta
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from privacy import PrivacyService, utcnow
from service import make_handler


class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.service = PrivacyService()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cls.service))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def post(self, path, payload):
        request = Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=2) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            body = json.loads(error.read())
            error.close()
            return error.code, body

    def test_health_unchanged(self):
        with urlopen(f"{self.base_url}/health", timeout=2) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(json.load(response)["service"], "clinical-privacy")

    def test_unknown_route_404(self):
        with self.assertRaises(HTTPError) as error:
            urlopen(f"{self.base_url}/v1/nope", timeout=2)
        self.assertEqual(error.exception.code, 404)
        error.exception.close()

    def test_access_check_denies_intern_media(self):
        status, body = self.post(
            "/v1/access/check",
            {
                "staff_id": "I-1",
                "role": "intern",
                "patient_id": "P-1",
                "relationship": "attending",
                "purpose": "clinical",
                "fields": ["obstetric_media"],
            },
        )
        self.assertEqual(status, 200)
        self.assertFalse(body["allowed"])
        self.assertEqual(body["reason"], "field-scope-exceeds-role-ceiling")

    def test_full_export_flow_over_http(self):
        now = utcnow()
        status, consent = self.post(
            "/v1/consents/register",
            {
                "patient_id": "P-http",
                "version": "teach-v1",
                "purposes": ["teaching"],
                "fields": ["obstetric_media"],
                "valid_from": (now - timedelta(days=1)).isoformat(),
                "valid_until": (now + timedelta(days=30)).isoformat(),
            },
        )
        self.assertEqual(status, 201)

        access = {
            "staff_id": "D-http",
            "role": "physician",
            "patient_id": "P-http",
            "relationship": "attending",
            "purpose": "teaching",
            "fields": ["obstetric_media"],
            "consent_version": "teach-v1",
        }
        status, session = self.post(
            "/v1/exports/begin", {**access, "recipient": "教学平台", "source_id": "SRC-http"}
        )
        self.assertEqual(status, 201)

        status, record = self.post(
            "/v1/exports/complete",
            {"session_id": session["session_id"], "file_hash": "hash-http"},
        )
        self.assertEqual(status, 201)
        self.assertEqual(record["recipient"], "教学平台")
        self.assertEqual(len(record["auth_chain"]), 3)

        status, verification = self.post(
            "/v1/exports/verify",
            {"file_hash": "hash-http", "watermark": record["watermark"]},
        )
        self.assertEqual(status, 200)
        self.assertTrue(verification["valid"])
        self.assertEqual(verification["operator"], "D-http")

        # 撤回后，新的导出会话无法完成
        status, session2 = self.post(
            "/v1/exports/begin", {**access, "recipient": "教学平台", "source_id": "SRC-http"}
        )
        self.assertEqual(status, 201)
        status, _ = self.post("/v1/consents/withdraw", {"consent_id": consent["consent_id"]})
        self.assertEqual(status, 200)
        status, body = self.post(
            "/v1/exports/complete",
            {"session_id": session2["session_id"], "file_hash": "hash-http-2"},
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "consent-withdrawn")

    def test_begin_export_denied_returns_403(self):
        status, body = self.post(
            "/v1/exports/begin",
            {
                "staff_id": "I-2",
                "role": "intern",
                "patient_id": "P-1",
                "relationship": "attending",
                "purpose": "research",
                "fields": ["diagnosis"],
                "recipient": "外部",
                "source_id": "SRC-x",
            },
        )
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "purpose-not-in-role-matrix")

    def test_incident_flow_over_http(self):
        now = utcnow()
        _, consent = self.post(
            "/v1/consents/register",
            {
                "patient_id": "P-inc",
                "version": "teach-v1",
                "purposes": ["teaching"],
                "fields": ["obstetric_media"],
                "valid_from": (now - timedelta(days=1)).isoformat(),
                "valid_until": (now + timedelta(days=30)).isoformat(),
            },
        )
        access = {
            "staff_id": "D-inc",
            "role": "physician",
            "patient_id": "P-inc",
            "relationship": "attending",
            "purpose": "teaching",
            "fields": ["obstetric_media"],
            "consent_version": "teach-v1",
        }
        _, session = self.post(
            "/v1/exports/begin", {**access, "recipient": "账号A", "source_id": "SRC-inc"}
        )
        _, record = self.post(
            "/v1/exports/complete",
            {"session_id": session["session_id"], "file_hash": "hash-inc"},
        )

        status, incident = self.post(
            "/v1/incidents/report",
            {
                "kind": "leak",
                "patient_id": "P-inc",
                "reporter": "SEC-1",
                "export_ids": [record["export_id"]],
            },
        )
        self.assertEqual(status, 201)
        self.assertTrue(incident["frozen_audit_seqs"])

        status, traced = self.post("/v1/incidents/trace", {"export_id": record["export_id"]})
        self.assertEqual(status, 200)
        self.assertEqual(len(traced["records"]), 1)

        status, deletion = self.post(
            "/v1/deletions/initiate",
            {"export_id": record["export_id"], "reason": "leak", "initiator": "SEC-1"},
        )
        self.assertEqual(status, 201)
        status, confirmed = self.post(
            "/v1/deletions/confirm",
            {"request_id": deletion["request_id"], "confirmer": "SEC-2"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(confirmed["status"], "confirmed")


if __name__ == "__main__":
    unittest.main()
