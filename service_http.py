"""HTTP 端到端契约：安全部门通过真实接口看到阻断、水印验证与授权链。

运行：python3 -m unittest -v service_http
"""

import base64
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from privacy.encoding import Clock
import service as http_service
from service import Handler, SERVICE_ID, SERVICE_NAME, health_payload


class HttpContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        # 每个用例使用独立服务实例与可拨快时钟。
        self.clock = Clock()
        from privacy.app import PrivacyService
        self.svc = http_service.reset_service(PrivacyService(self.clock))

    def call(self, method, path, payload=None):
        data = json.dumps(payload or {}, ensure_ascii=False).encode()
        req = Request(f"{self.base}{path}", data=data, method=method,
                      headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=3) as resp:
                return resp.status, json.load(resp)
        except HTTPError as err:
            return err.code, json.load(err)

    def get(self, path):
        with urlopen(f"{self.base}{path}", timeout=3) as resp:
            return resp.status, json.load(resp)

    # ---- 基础契约保持不变 --------------------------------------------------

    def test_health_payload_has_stable_identity(self):
        self.assertEqual(
            health_payload(),
            {"status": "ok", "service": SERVICE_ID, "name": SERVICE_NAME},
        )

    def test_health_endpoint_returns_json(self):
        status, body = self.get("/health")
        self.assertEqual(status, 200)
        self.assertEqual(body, health_payload())

    def test_unknown_route_is_not_exposed(self):
        status, body = self.call("POST", "/unknown", {})
        self.assertEqual(status, 404)

    # ---- 越权阻断在接口层可见 ----------------------------------------------

    def test_unauthorized_intern_view_returns_403(self):
        self.call("POST", "/admin/users",
                  {"actor_id": "intern_zhao", "role": "intern", "name": "赵实习"})
        status, body = self.call("POST", "/access/view", {
            "actor_id": "intern_zhao", "patient_id": "P001",
            "purpose": "treatment", "fields": ["diagnosis"]})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "purpose-denied")
        # 阻断事件进了审计链。
        _, audit = self.get("/audit/entries")
        self.assertTrue(any(e["action"] == "access.denied" for e in audit["entries"]))

    def test_missing_fields_rejected(self):
        status, body = self.call("POST", "/consents", {"actor_id": "dr_li"})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "missing-fields")

    # ---- 同意 → 导出 → 轮换 → 旧哈希验证全链路 -----------------------------

    def test_consent_export_rotate_verify_chain_over_http(self):
        for uid, role, name in [
            ("dr_li", "physician", "李医生"),
            ("res_sun", "resident", "孙住院医"),
            ("sec_wu", "security", "吴安全"),
        ]:
            self.call("POST", "/admin/users",
                      {"actor_id": uid, "role": role, "name": name})

        _, consent = self.call("POST", "/consents", {
            "actor_id": "dr_li", "patient_id": "P001",
            "purposes": ["teaching"], "version": "CONSENT-v1",
            "fields": ["diagnosis", "obstetric", "procedure", "media"]})

        raw = b"\x89PNG-fake-obstetric-surgery-photo"
        status, exported = self.call("POST", "/exports", {
            "actor_id": "res_sun", "patient_id": "P001", "purpose": "teaching",
            "fields": ["obstetric", "media"], "delivered_to": "示教室工作站",
            "consent_id": consent["consent_id"],
            "content_b64": base64.b64encode(raw).decode()})
        self.assertEqual(status, 200)
        old_kid = exported["watermark"]["kid"]
        file_hash = exported["export"]["file_hash"]

        # 重复导出被阻断。
        status, body = self.call("POST", "/exports", {
            "actor_id": "res_sun", "patient_id": "P001", "purpose": "teaching",
            "fields": ["obstetric", "media"], "delivered_to": "示教室工作站",
            "consent_id": consent["consent_id"],
            "content_b64": base64.b64encode(raw).decode()})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "duplicate-export")

        # 密钥轮换后，用旧文件哈希与旧水印仍可验证并追完整授权链。
        self.call("POST", "/keys/rotate", {"actor_id": "sec_wu"})
        status, verified = self.call("POST", "/exports/verify", {
            "actor_id": "sec_wu", "file_hash": file_hash, "token": exported["watermark"]})
        self.assertEqual(status, 200)
        self.assertTrue(verified["verification"]["valid"])
        self.assertEqual(verified["verification"]["kid"], old_kid)
        self.assertEqual(verified["verification"]["key_status"], "verify-only")
        actions = [e["action"] for e in verified["authorization_chain"]]
        self.assertIn("consent.registered", actions)
        self.assertIn("export.requested", actions)

    # ---- break-glass 与主动通知 --------------------------------------------

    def test_emergency_flow_and_notification_over_http(self):
        self.call("POST", "/admin/users",
                  {"actor_id": "nr_wang", "role": "nurse", "name": "王护士"})
        self.call("POST", "/admin/users",
                  {"actor_id": "qa_zhou", "role": "qa_officer", "name": "周质控"})

        status, grant = self.call("POST", "/emergencies", {
            "actor_id": "nr_wang", "patient_id": "P001", "reason": "产后大出血需立即查看史"})
        self.assertEqual(status, 200)
        self.assertEqual(grant["ttl_seconds"], 900)

        status, view = self.call("POST", f"/emergencies/{grant['emergency_id']}/view", {
            "actor_id": "nr_wang", "patient_id": "P001",
            "fields": ["obstetric", "allergies"]})
        self.assertEqual(status, 200)
        self.assertEqual(view["purpose"], "emergency")

        _, notes = self.get("/notifications")
        self.assertTrue(any(n["template"] == "emergency-started" for n in notes["notifications"]))

        status, review = self.call("POST", f"/emergencies/{grant['emergency_id']}/review", {
            "reviewer_id": "qa_zhou", "approved": True, "note": "指征充分"})
        self.assertEqual(status, 200)
        self.assertEqual(review["review_outcome"], "justified")

    # ---- 撤回即时阻断 ------------------------------------------------------

    def test_revocation_blocks_export_over_http(self):
        self.call("POST", "/admin/users",
                  {"actor_id": "dr_li", "role": "physician"})
        self.call("POST", "/admin/users",
                  {"actor_id": "res_sun", "role": "resident"})
        _, consent = self.call("POST", "/consents", {
            "actor_id": "dr_li", "patient_id": "P001",
            "purposes": ["teaching"], "version": "v1",
            "fields": ["diagnosis", "obstetric", "procedure", "media"]})
        status, outcome = self.call("POST", f"/consents/{consent['consent_id']}/revoke",
                                    {"actor_id": "dr_li", "reason": "患者撤回"})
        self.assertEqual(status, 200)
        self.assertEqual(outcome["state"], "revoked")

        raw = b"img"
        status, body = self.call("POST", "/exports", {
            "actor_id": "res_sun", "patient_id": "P001", "purpose": "teaching",
            "fields": ["media"], "delivered_to": "终端X",
            "consent_id": consent["consent_id"],
            "content_b64": base64.b64encode(raw).decode()})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "consent-revoked")


if __name__ == "__main__":
    unittest.main()
