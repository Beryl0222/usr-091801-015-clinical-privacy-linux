"""安全部门模拟场景：越权、过期缓存、重复导出、密钥轮换、并发撤回、
break-glass、水印旧哈希验证与授权链、审计篡改、事件冻结与删除确认。

运行：python3 -m unittest -v service_scenarios
"""

import json
import threading
import unittest
from datetime import timedelta

from privacy.app import PrivacyService, RETENTION_DAYS
from privacy.audit import LedgerFrozenError, TamperError
from privacy.encoding import Clock, iso
from privacy.policy import PolicyError
from privacy.watermark import WatermarkError

OB_IMAGE = b"\x89PNG-fake-obstetric-surgery-photo"
OB_IMAGE_2 = b"\x89PNG-fake-obstetric-surgery-photo-v2"


def build_world():
    """构造一所微型医院：医生/护士/实习生/科研/质控/安全/2 名管理员。"""
    clk = Clock()
    svc = PrivacyService(clk)
    people = {
        "dr_li": ("physician", "李医生"),
        "nr_wang": ("nurse", "王护士"),
        "intern_zhao": ("intern", "赵实习"),
        "res_sun": ("resident", "孙住院医"),
        "prof_chen": ("researcher", "陈研究员"),
        "qa_zhou": ("qa_officer", "周质控"),
        "sec_wu": ("security", "吴安全"),
        "adm_a": ("admin", "管理员甲"),
        "adm_b": ("admin", "管理员乙"),
    }
    for uid, (role, name) in people.items():
        svc.register_user(uid, role, name)
    svc.register_relation("dr_li", "P001", "attending")
    svc.register_relation("nr_wang", "P001", "team")
    return svc, clk


class RoleMatrixTests(unittest.TestCase):
    def setUp(self):
        self.svc, self.clk = build_world()

    def test_physician_with_relation_can_view_treatment(self):
        decision = self.svc.view_record("dr_li", "P001", "treatment", ["diagnosis", "orders"])
        self.assertEqual(decision["decision"], "allow")

    def test_intern_is_blocked_from_treatment_and_research(self):
        for purpose in ("treatment", "research"):
            with self.subTest(purpose=purpose):
                with self.assertRaises(PolicyError) as ctx:
                    self.svc.view_record("intern_zhao", "P001", purpose, ["diagnosis"])
                self.assertEqual(ctx.exception.code, "purpose-denied")

    def test_admin_has_zero_clinical_purposes(self):
        with self.assertRaises(PolicyError) as ctx:
            self.svc.view_record("adm_a", "P001", "treatment", ["diagnosis"])
        self.assertEqual(ctx.exception.code, "purpose-denied")

    def test_no_relation_blocks_treatment_with_audit(self):
        with self.assertRaises(PolicyError) as ctx:
            self.svc.view_record("res_sun", "P001", "treatment", ["diagnosis"])
        self.assertEqual(ctx.exception.code, "no-relation")
        denied = self.svc.ledger.by_action("access.denied")
        self.assertTrue(any(e.payload["reason"] == "no-relation" for e in denied))

    def test_field_minimization_overreach_is_blocked(self):
        # 护士诊疗目的不允许越界取过敏史以外的未授权字段：medication 允许，allergies 不允许。
        with self.assertRaises(PolicyError) as ctx:
            self.svc.view_record("nr_wang", "P001", "treatment", ["allergies"])
        self.assertEqual(ctx.exception.code, "field-overreach")
        self.assertIn("allergies", ctx.exception.details["rejected"])

    def test_every_denial_is_recorded_for_forensics(self):
        with self.assertRaises(PolicyError):
            self.svc.view_record("intern_zhao", "P001", "treatment", ["diagnosis"])
        with self.assertRaises(PolicyError):
            self.svc.view_record("prof_chen", "P001", "teaching", ["media"])
        reasons = {e.payload["reason"] for e in self.svc.ledger.by_action("access.denied")}
        self.assertIn("purpose-denied", reasons)

    def test_export_denied_for_treatment_purpose(self):
        with self.assertRaises(PolicyError) as ctx:
            self.svc.request_export(
                "dr_li", "P001", "treatment", ["diagnosis"], "U盘", OB_IMAGE)
        self.assertEqual(ctx.exception.code, "export-denied")


class ConsentTests(unittest.TestCase):
    def setUp(self):
        self.svc, self.clk = build_world()

    def _consent(self, **kw):
        params = dict(
            actor_id="dr_li", patient_id="P001", purposes=["teaching"],
            version="CONSENT-2026-v1",
            fields=["diagnosis", "obstetric", "procedure", "media"],
        )
        params.update(kw)
        return self.svc.register_consent(**params)

    def test_teaching_requires_bound_consent_version(self):
        with self.assertRaises(PolicyError) as ctx:
            self.svc.view_with_consent(
                "intern_zhao", "P001", "teaching", ["diagnosis", "media"],
                consent_id="con_missing")
        self.assertEqual(ctx.exception.code, "consent-not-found")

    def test_consent_purpose_version_mismatch_blocks(self):
        consent = self._consent(purposes=["teaching"], version="v-teach")
        with self.assertRaises(PolicyError) as ctx:
            self.svc.view_with_consent(
                "prof_chen", "P001", "research", ["diagnosis"],
                consent_id=consent["consent_id"])
        self.assertEqual(ctx.exception.code, "consent-purpose-mismatch")

    def test_expired_consent_is_blocked(self):
        consent = self._consent(duration_days=30)
        self.clk.advance(31 * 86400)
        with self.assertRaises(PolicyError) as ctx:
            self.svc.view_with_consent(
                "res_sun", "P001", "teaching", ["diagnosis"],
                consent_id=consent["consent_id"])
        self.assertEqual(ctx.exception.code, "consent-expired")

    def test_scope_exceedance_is_blocked(self):
        consent = self._consent(fields=["diagnosis"])
        with self.assertRaises(PolicyError) as ctx:
            self.svc.view_with_consent(
                "res_sun", "P001", "teaching", ["diagnosis", "media"],
                consent_id=consent["consent_id"])
        self.assertEqual(ctx.exception.code, "consent-scope-exceeded")

    def test_wrong_patient_consent_is_blocked(self):
        consent = self._consent(patient_id="P999")
        with self.assertRaises(PolicyError) as ctx:
            self.svc.view_with_consent(
                "res_sun", "P001", "teaching", ["diagnosis"],
                consent_id=consent["consent_id"])
        self.assertEqual(ctx.exception.code, "consent-mismatch")


class CachedResponseTests(unittest.TestCase):
    def setUp(self):
        self.svc, self.clk = build_world()

    def test_fresh_cache_token_is_accepted(self):
        decision = self.svc.view_record(
            "dr_li", "P001", "treatment", ["diagnosis"],
            cache_token="cache-1", cache_issued_at=iso(self.clk.now()))
        self.assertEqual(decision["decision"], "allow")

    def test_stale_cache_is_rejected_and_must_reauthorize(self):
        issued = iso(self.clk.now())
        self.clk.advance(61)
        with self.assertRaises(PolicyError) as ctx:
            self.svc.view_record(
                "dr_li", "P001", "treatment", ["diagnosis"],
                cache_token="cache-1", cache_issued_at=issued)
        self.assertEqual(ctx.exception.code, "cache-expired")


class EmergencyBreakGlassTests(unittest.TestCase):
    def setUp(self):
        self.svc, self.clk = build_world()

    def test_break_glass_full_cycle_grant_access_expire_review_notify(self):
        grant = self.svc.start_emergency(
            "nr_wang", "P001", "产妇大出血，主刀未到场，需立即查看既往手术记录")
        self.assertEqual(grant["status"], "active")
        self.assertEqual(grant["ttl_seconds"], 900)

        view = self.svc.emergency_view(
            "nr_wang", "P001", ["obstetric", "allergies"], grant["emergency_id"])
        self.assertEqual(view["purpose"], "emergency")

        # 主动通知：隐私官、患者通道、质控三方。
        note = self.svc.notifications[-1]
        self.assertEqual(note["template"], "emergency-started")
        self.assertIn("privacy-officer", note["channels"])
        self.assertIn("qa-officer", note["channels"])

        # 短时授权：TTL 过后立即失效。
        self.clk.advance(901)
        with self.assertRaises(PolicyError) as ctx:
            self.svc.emergency_view(
                "nr_wang", "P001", ["obstetric"], grant["emergency_id"])
        self.assertEqual(ctx.exception.code, "emergency-expired")

        # 事后复核。
        review = self.svc.review_emergency(
            "qa_zhou", grant["emergency_id"], approved=True, note="记录完整，指征充分")
        self.assertEqual(review["review_outcome"], "justified")

    def test_intern_cannot_break_glass(self):
        with self.assertRaises(PolicyError) as ctx:
            self.svc.start_emergency("intern_zhao", "P001", "自称紧急")
        self.assertEqual(ctx.exception.code, "emergency-role-denied")

    def test_reviewer_must_be_qa_or_security(self):
        grant = self.svc.start_emergency("dr_li", "P001", "急诊")
        with self.assertRaises(PolicyError) as ctx:
            self.svc.review_emergency("intern_zhao", grant["emergency_id"], True)
        self.assertEqual(ctx.exception.code, "reviewer-denied")

    def test_flagged_emergency_is_recorded(self):
        grant = self.svc.start_emergency("dr_li", "P001", "理由含糊")
        result = self.svc.review_emergency("sec_wu", grant["emergency_id"], False, "未见危急指征")
        self.assertEqual(result["review_outcome"], "flagged")


class ExportAndWatermarkTests(unittest.TestCase):
    def setUp(self):
        self.svc, self.clk = build_world()
        self.consent = self.svc.register_consent(
            "dr_li", "P001", ["teaching"], "CONSENT-2026-v1",
            fields=["diagnosis", "obstetric", "procedure", "media"])

    def _export(self, delivered_to="教学终端01", content=OB_IMAGE, actor="res_sun"):
        return self.svc.request_export(
            actor, "P001", "teaching", ["obstetric", "media"],
            delivered_to, content, consent_id=self.consent["consent_id"])

    def test_watermark_carries_operator_time_and_hash_but_no_raw_image(self):
        result = self._export()
        claims = result["watermark"]["payload"]
        self.assertEqual(claims["operator"], "res_sun")
        self.assertEqual(claims["file_hash"], result["export"]["file_hash"])
        self.assertTrue(claims["issued_at"])
        # 服务任何登记结构中都找不到原始影像字节。
        blob = json.dumps(list(self.svc.exports.values()), ensure_ascii=False)
        self.assertNotIn("fake-obstetric", blob)

    def test_duplicate_export_same_authorization_and_recipient_blocked(self):
        first = self._export(delivered_to="教学终端01")
        with self.assertRaises(PolicyError) as ctx:
            self._export(delivered_to="教学终端01")
        self.assertEqual(ctx.exception.code, "duplicate-export")
        self.assertEqual(ctx.exception.details["existing_export"], first["export"]["id"])
        # 审计留痕：重复导出被阻断。
        self.assertTrue(self.svc.ledger.by_action("export.duplicate_blocked"))

    def test_same_content_to_different_recipient_is_distinct_registration(self):
        self._export(delivered_to="教学终端01")
        second = self._export(delivered_to="教学终端02")
        self.assertEqual(second["export"]["status"], "active")

    def test_verify_with_old_file_hash_after_key_rotation_and_full_chain(self):
        result = self._export()
        old_hash = result["export"]["file_hash"]
        old_token = result["watermark"]
        old_kid = old_token["kid"]

        rotated = self.svc.rotate_keys("sec_wu")
        self.assertNotEqual(rotated["active_kid"], old_kid)
        self.assertEqual(self.svc.keyring.status(old_kid), "verify-only")

        # 用旧文件哈希 + 旧水印仍可验证，并能追到完整授权链。
        verified = self.svc.verify_watermark("sec_wu", old_hash, old_token)
        self.assertTrue(verified["verification"]["valid"])
        self.assertEqual(verified["verification"]["kid"], old_kid)
        chain_actions = [e["action"] for e in verified["authorization_chain"]]
        self.assertIn("consent.registered", chain_actions)
        self.assertIn("export.requested", chain_actions)
        self.assertIn("service.booted", chain_actions)
        self.assertEqual(verified["export"]["operator"], "res_sun")
        self.assertEqual(verified["export"]["delivered_to"], "教学终端01")

        # 轮换后新导出使用新密钥。
        new_result = self._export(delivered_to="教学终端03", content=OB_IMAGE_2)
        self.assertEqual(new_result["watermark"]["kid"], rotated["active_kid"])

    def test_revoked_key_fails_verification(self):
        result = self._export()
        self.svc.rotate_keys("sec_wu")
        self.svc.keyring.revoke(result["watermark"]["kid"])
        with self.assertRaises(WatermarkError):
            self.svc.verify_watermark("sec_wu", result["export"]["file_hash"],
                                      result["watermark"])

    def test_tampered_watermark_payload_is_rejected(self):
        result = self._export()
        forged = json.loads(json.dumps(result["watermark"]))
        forged["payload"]["delivered_to"] = "外网社交平台"
        with self.assertRaises(WatermarkError) as ctx:
            self.svc.verify_watermark("sec_wu", result["export"]["file_hash"], forged)
        self.assertIn("签名不匹配", str(ctx.exception))

    def test_watermark_bound_to_different_file_is_rejected(self):
        result = self._export()
        from privacy.encoding import content_hash
        other_hash = content_hash(b"completely-different-file")
        with self.assertRaises(WatermarkError):
            self.svc.verify_watermark("sec_wu", other_hash, result["watermark"])


class RevocationTests(unittest.TestCase):
    def setUp(self):
        self.svc, self.clk = build_world()
        self.consent = self.svc.register_consent(
            "dr_li", "P001", ["teaching"], "v1",
            fields=["diagnosis", "obstetric", "procedure", "media"])
        self.exports = [
            self.svc.request_export(
                "res_sun", "P001", "teaching", ["obstetric", "media"],
                f"教学终端0{i}", OB_IMAGE, consent_id=self.consent["consent_id"])
            for i in range(1, 4)
        ]

    def test_revocation_blocks_pending_and_issued_exports_immediately(self):
        outcome = self.svc.revoke_consent("dr_li", self.consent["consent_id"], "患者电话撤回授权")
        self.assertEqual(len(outcome["blocked"]), 3)
        for result in self.exports:
            self.assertEqual(
                self.svc.export_info(result["export"]["id"])["status"], "blocked")

        # 撤回后的新访问/导出立即被阻断。
        with self.assertRaises(PolicyError) as ctx:
            self.svc.view_with_consent(
                "res_sun", "P001", "teaching", ["diagnosis"],
                consent_id=self.consent["consent_id"])
        self.assertEqual(ctx.exception.code, "consent-revoked")
        with self.assertRaises(PolicyError) as ctx:
            self.svc.request_export(
                "res_sun", "P001", "teaching", ["obstetric", "media"],
                "教学终端09", OB_IMAGE_2, consent_id=self.consent["consent_id"])
        self.assertEqual(ctx.exception.code, "consent-revoked")

    def test_concurrent_revocation_vs_access_never_serves_after_revoke(self):
        errors = []
        outcomes = {"allowed": 0, "denied": 0}
        barrier = threading.Barrier(5)

        def viewer(seq):
            barrier.wait()
            try:
                self.svc.view_with_consent(
                    "res_sun", "P001", "teaching", ["diagnosis"],
                    consent_id=self.consent["consent_id"])
                outcomes["allowed"] += 1
            except PolicyError as exc:
                outcomes["denied"] += 1
                errors.append(exc.code)

        def revoker():
            barrier.wait()
            self.svc.revoke_consent("dr_li", self.consent["consent_id"], "并发撤回")

        threads = [threading.Thread(target=viewer, args=(i,)) for i in range(4)]
        threads.append(threading.Thread(target=revoker))
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        self.assertEqual(outcomes["allowed"] + outcomes["denied"], 4)
        # 撤回后发出的每一个请求都必须被拒；允许的只能是撤回前抢先完成的。
        self.assertTrue(all(code == "consent-revoked" for code in errors))
        self.assertEqual(len(self.svc.ledger.by_action("consent.revoked")), 1)


class AuditIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.svc, self.clk = build_world()

    def test_hash_chain_verifies_clean(self):
        info = self.svc.ledger.verify()
        self.assertGreater(info["entries"], 0)

    def test_tampering_with_an_entry_is_detected(self):
        self.svc.register_relation("dr_li", "P002", "attending")
        entry = self.svc.ledger.all()[-1]
        # 模拟有人试图抹掉/改写自己的操作。
        object.__setattr__(entry, "payload", {**entry.payload, "patient_id": "REDACTED"})
        with self.assertRaises(TamperError):
            self.svc.ledger.verify()

    def test_deleting_an_entry_is_detected(self):
        self.svc.register_relation("dr_li", "P002", "attending")
        del self.svc.ledger._entries[3]
        with self.assertRaises(TamperError):
            self.svc.ledger.verify()

    def test_admin_cannot_erase_own_actions_and_freezing_blocks_appends(self):
        # 没有删除 API：尝试冻结后再写入普通业务审计应被拒绝。
        first = self.svc.freeze_audit("adm_a", "社交平台外泄事件调查", "token-a")
        self.assertEqual(first["state"], "pending")
        second = self.svc.freeze_audit("adm_b", "社交平台外泄事件调查", "token-b")
        self.assertEqual(second["state"], "frozen")

        with self.assertRaises(LedgerFrozenError):
            self.svc.register_user("ghost", "physician", "想趁冻结浑水摸鱼")

        # 同一管理员自己两次确认不能凑数（双人完整性）。
        svc2, _ = build_world()
        svc2.freeze_audit("adm_a", "理由", "t1")
        again = svc2.freeze_audit("adm_a", "理由", "t2")
        self.assertEqual(again["state"], "pending")

        # 安全事件仍可穿透冻结记录。
        incident = self.svc.report_incident("sec_wu", "photo-leak", "发现未遮挡产科手术照片")
        self.assertEqual(incident["status"], "open")


class IncidentAndPurgeTests(unittest.TestCase):
    def setUp(self):
        self.svc, self.clk = build_world()
        self.consent = self.svc.register_consent(
            "dr_li", "P001", ["teaching"], "v1",
            fields=["diagnosis", "obstetric", "procedure", "media"])
        self.e1 = self.svc.request_export(
            "res_sun", "P001", "teaching", ["obstetric", "media"],
            "教学终端01", OB_IMAGE, consent_id=self.consent["consent_id"])
        self.e2 = self.svc.request_export(
            "res_sun", "P001", "teaching", ["obstetric", "media"],
            "教学终端02", OB_IMAGE, consent_id=self.consent["consent_id"])

    def test_incident_links_and_holds_same_source_exports(self):
        trace = self.svc.trace_source("sec_wu", self.e1["export"]["file_hash"])
        self.assertEqual(trace["count"], 2)
        recipients = {e["delivered_to"] for e in trace["lineage"]}
        self.assertEqual(recipients, {"教学终端01", "教学终端02"})

        incident = self.svc.report_incident(
            "sec_wu", "photo-leak", "社交平台发现未遮挡照片",
            file_hash=self.e1["export"]["file_hash"])
        self.assertEqual(set(incident["linked_exports"]),
                         {self.e1["export"]["id"], self.e2["export"]["id"]})

        # 未结事件期间命中法律保全，不能删除。
        with self.assertRaises(PolicyError) as ctx:
            self.svc.initiate_purge("adm_a", self.e1["export"]["file_hash"], "事件期清理")
        self.assertEqual(ctx.exception.code, "legal-hold")

    def test_retention_policy_and_two_person_purge_confirmation(self):
        file_hash = self.e1["export"]["file_hash"]
        # 保留期内拒绝删除并给出最早可删时间。
        with self.assertRaises(PolicyError) as ctx:
            self.svc.initiate_purge("adm_a", file_hash, "到期清理")
        self.assertEqual(ctx.exception.code, "retention-active")
        self.assertEqual(len(ctx.exception.details["retained"]), 2)

        # 越过教学用途保留期。
        self.clk.advance(RETENTION_DAYS["teaching"] * 86400 + 1)
        purge = self.svc.initiate_purge("adm_a", file_hash, "保留到期，删除确认")
        self.assertEqual(purge["status"], "pending")

        # 同一管理员不能两次确认。
        with self.assertRaises(PolicyError) as ctx:
            self.svc.confirm_purge("adm_a", purge["purge_id"])
        # 第一次确认成功（initiate 时已计 1 次由 adm_a），这里应拒绝重复确认。
        self.assertEqual(ctx.exception.code, "purge-double-confirm")

        confirmed = self.svc.confirm_purge("adm_b", purge["purge_id"])
        self.assertEqual(confirmed["status"], "confirmed")
        self.assertEqual(
            self.svc.export_info(self.e1["export"]["id"])["status"], "delete-confirmed")

        # 哈希与授权链仍在，删除本身也有不可抹除的证明。
        self.assertEqual(self.svc.export_info(self.e1["export"]["id"])["file_hash"], file_hash)
        self.assertTrue(self.svc.ledger.by_action("incident.purge_confirmed"))
        self.svc.ledger.verify()

    def test_freeze_during_incident_blocks_purge_until_unfrozen(self):
        file_hash = self.e1["export"]["file_hash"]
        incident = self.svc.report_incident(
            "sec_wu", "photo-leak", "外泄", file_hash=file_hash)
        # 事件关闭后法律保全解除；保留期也已越过，可以发起删除。
        self.svc.close_incident("sec_wu", incident["incident_id"])
        self.clk.advance(RETENTION_DAYS["teaching"] * 86400 + 1)
        purge = self.svc.initiate_purge("adm_a", file_hash, "到期删除")

        # 取证冻结期间，第二名管理员的删除确认被挡下。
        self.svc.freeze_audit("adm_a", "取证", "ta")
        self.svc.freeze_audit("adm_b", "取证", "tb")
        with self.assertRaises(LedgerFrozenError):
            self.svc.confirm_purge("adm_b", purge["purge_id"])
        # 冻结未改变删除流程状态。
        self.assertEqual(self.svc.purges[purge["purge_id"]]["status"], "pending")

        self.svc.unfreeze_audit("adm_a", "取证完成")
        result = self.svc.confirm_purge("adm_b", purge["purge_id"])
        self.assertEqual(result["status"], "confirmed")


class EndToEndScenarioTests(unittest.TestCase):
    """完整叙事：从越权拍摄报告到旧水印取证。"""

    def test_leak_investigation_story(self):
        svc, clk = build_world()
        consent = svc.register_consent(
            "dr_li", "P001", ["teaching", "research"], "CONSENT-v1",
            fields=["diagnosis", "obstetric", "procedure", "media", "lab"])

        exported = svc.request_export(
            "res_sun", "P001", "teaching", ["obstetric", "media"],
            "示教室工作站", OB_IMAGE, consent_id=consent["consent_id"])
        old_kid = exported["watermark"]["kid"]

        # 安全部门轮换密钥两次。
        svc.rotate_keys("sec_wu")
        svc.rotate_keys("sec_wu")

        # 事后在社交平台发现图片，拿到文件哈希：仍可验证旧水印并追授权链。
        from privacy.encoding import content_hash
        seized_hash = content_hash(OB_IMAGE)
        verified = svc.verify_watermark("sec_wu", seized_hash, exported["watermark"])
        self.assertEqual(verified["verification"]["kid"], old_kid)
        self.assertEqual(verified["verification"]["key_status"], "verify-only")
        chain = verified["authorization_chain"]
        self.assertEqual(chain[0]["action"], "service.booted")
        self.assertTrue(any(e["action"] == "consent.registered" for e in chain))

        # 报告事件 → 追踪同源 → 冻结取证。
        incident = svc.report_incident(
            "sec_wu", "photo-leak", "社交平台出现未遮挡产科手术照片",
            file_hash=seized_hash)
        self.assertEqual(len(incident["linked_exports"]), 1)
        svc.freeze_audit("adm_a", "外泄取证", "k1")
        svc.freeze_audit("adm_b", "外泄取证", "k2")
        self.assertTrue(svc.ledger.frozen)

        # 审计链自洽，且任何管理员都无法抹除。
        report = svc.ledger.verify()
        self.assertEqual(report["frozen"], True)
        self.assertGreaterEqual(report["entries"], 8)


if __name__ == "__main__":
    unittest.main()
