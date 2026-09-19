"""领域规则测试：用途管控、知情同意、break-glass、水印、事件响应。"""

import threading
import unittest
from datetime import timedelta

from privacy import (
    FIELD_DIAGNOSIS,
    FIELD_LABS,
    FIELD_OBSTETRIC_MEDIA,
    PURPOSE_CLINICAL,
    PURPOSE_DISSEMINATION,
    PURPOSE_EMERGENCY,
    PURPOSE_RESEARCH,
    PURPOSE_TEACHING,
    REL_ASSIGNED,
    REL_ATTENDING,
    REL_NONE,
    ROLE_ADMIN,
    ROLE_EDUCATOR,
    ROLE_INTERN,
    ROLE_NURSE,
    ROLE_PHYSICIAN,
    ROLE_RESEARCHER,
    AccessRequest,
    BreakGlassError,
    ConsentWithdrawn,
    DeletionStateError,
    DuplicateExport,
    ExportSessionError,
    PrivacyService,
    utcnow,
)
from privacy.simulation import run_simulation


def req(**kw):
    defaults = dict(
        staff_id="D-1",
        role=ROLE_PHYSICIAN,
        patient_id="P-1",
        relationship=REL_ATTENDING,
        purpose=PURPOSE_CLINICAL,
        fields=frozenset({FIELD_DIAGNOSIS}),
    )
    defaults.update(kw)
    if not isinstance(defaults["fields"], frozenset):
        defaults["fields"] = frozenset(defaults["fields"])
    return AccessRequest(**defaults)


def make_teaching_service(fields=(FIELD_OBSTETRIC_MEDIA,), version="teach-v1"):
    svc = PrivacyService()
    now = utcnow()
    consent = svc.grant_consent(
        patient_id="P-1",
        version=version,
        purposes={PURPOSE_TEACHING},
        fields=set(fields),
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=30),
    )
    teaching_req = req(
        purpose=PURPOSE_TEACHING,
        fields=set(fields),
        consent_version=version,
    )
    return svc, consent, teaching_req, now


class AccessPolicyTest(unittest.TestCase):
    def test_request_carries_relationship_purpose_and_minimal_fields(self):
        request = req()
        self.assertEqual(request.relationship, REL_ATTENDING)
        self.assertEqual(request.purpose, PURPOSE_CLINICAL)
        self.assertEqual(request.fields, frozenset({FIELD_DIAGNOSIS}))

    def test_role_matrix_blocks_escalation(self):
        svc = PrivacyService()
        cases = [
            (req(role=ROLE_INTERN, purpose=PURPOSE_RESEARCH), "purpose-not-in-role-matrix"),
            (req(role=ROLE_NURSE, relationship=REL_ASSIGNED, purpose=PURPOSE_DISSEMINATION,
                 fields={FIELD_OBSTETRIC_MEDIA}), "purpose-not-in-role-matrix"),
            (req(role=ROLE_ADMIN), "purpose-not-in-role-matrix"),
            (req(role=ROLE_EDUCATOR, purpose=PURPOSE_CLINICAL), "purpose-not-in-role-matrix"),
        ]
        for request, reason in cases:
            with self.subTest(reason=reason):
                decision = svc.check_access(request)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, reason)

    def test_field_scope_ceiling(self):
        svc = PrivacyService()
        decision = svc.check_access(req(role=ROLE_INTERN, fields={FIELD_OBSTETRIC_MEDIA}))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "field-scope-exceeds-role-ceiling")
        self.assertTrue(svc.check_access(req(role=ROLE_INTERN)).allowed)

    def test_clinical_requires_treatment_relationship(self):
        svc = PrivacyService()
        decision = svc.check_access(req(relationship=REL_NONE))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "clinical-relationship-required")

    def test_every_evaluation_is_audited(self):
        svc = PrivacyService()
        svc.check_access(req())
        svc.check_access(req(role=ROLE_ADMIN))
        entries = svc.audit.find(action="access.evaluated")
        self.assertEqual(len(entries), 2)
        self.assertEqual({e.details["allowed"] for e in entries}, {True, False})


class ConsentBindingTest(unittest.TestCase):
    def test_teaching_requires_consent_version(self):
        svc = PrivacyService()
        decision = svc.check_access(req(purpose=PURPOSE_TEACHING, fields={FIELD_OBSTETRIC_MEDIA}))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "consent-required")

    def test_consent_version_must_match(self):
        svc, _consent, teaching_req, _now = make_teaching_service()
        wrong = svc.check_access(
            req(purpose=PURPOSE_TEACHING, fields={FIELD_OBSTETRIC_MEDIA}, consent_version="teach-v999")
        )
        self.assertFalse(wrong.allowed)
        self.assertEqual(wrong.reason, "consent-version-mismatch")
        self.assertTrue(svc.check_access(teaching_req).allowed)

    def test_consent_validity_window_enforced(self):
        svc, consent, teaching_req, _now = make_teaching_service()
        after = consent.valid_until + timedelta(seconds=1)
        decision = svc.check_access(teaching_req, now=after)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "consent-expired-or-withdrawn")

    def test_consent_field_scope_enforced(self):
        svc = PrivacyService()
        now = utcnow()
        svc.grant_consent(
            patient_id="P-1", version="res-v1", purposes={PURPOSE_RESEARCH},
            fields={FIELD_DIAGNOSIS},
            valid_from=now - timedelta(days=1), valid_until=now + timedelta(days=30),
        )
        decision = svc.check_access(
            req(role=ROLE_RESEARCHER, relationship=REL_NONE, purpose=PURPOSE_RESEARCH,
                fields={FIELD_LABS}, consent_version="res-v1")
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "consent-scope-missing-fields")

    def test_withdrawal_blocks_pending_export(self):
        svc, consent, teaching_req, now = make_teaching_service()
        session = svc.begin_export(teaching_req, recipient="教学平台", source_id="SRC-1", now=now)
        svc.withdraw_consent(consent.consent_id)
        with self.assertRaises(ConsentWithdrawn):
            svc.complete_export(session.session_id, "hash-1")
        self.assertEqual(session.state, "blocked")

    def test_export_completed_before_withdrawal_is_kept(self):
        svc, consent, teaching_req, now = make_teaching_service()
        session = svc.begin_export(teaching_req, recipient="教学平台", source_id="SRC-1", now=now)
        record = svc.complete_export(session.session_id, "hash-1", now=now)
        svc.withdraw_consent(consent.consent_id)
        self.assertIsNotNone(svc.exports.get(record.export_id))

    def test_withdrawal_invalidates_cached_decision(self):
        svc, consent, teaching_req, _now = make_teaching_service()
        self.assertTrue(svc.check_access(teaching_req).allowed)  # 进入缓存
        svc.withdraw_consent(consent.consent_id)
        decision = svc.check_access(teaching_req)
        self.assertFalse(decision.allowed)


class BreakGlassTest(unittest.TestCase):
    def test_reason_and_ttl_enforced(self):
        svc = PrivacyService()
        with self.assertRaises(BreakGlassError):
            svc.request_break_glass("I-1", "P-1", "  ")
        with self.assertRaises(BreakGlassError):
            svc.request_break_glass("I-1", "P-1", "抢救", ttl_seconds=3600)

    def test_full_break_glass_flow(self):
        svc = PrivacyService()
        now = utcnow()
        emergency = req(
            staff_id="I-1", role=ROLE_INTERN, relationship=REL_NONE,
            purpose=PURPOSE_EMERGENCY, fields={FIELD_DIAGNOSIS, FIELD_OBSTETRIC_MEDIA},
        )
        self.assertEqual(svc.check_access(emergency, now).reason, "break-glass-required")

        grant = svc.request_break_glass("I-1", "P-1", "术中大出血", ttl_seconds=300, now=now)
        allowed = svc.check_access(
            req(staff_id="I-1", role=ROLE_INTERN, relationship=REL_NONE,
                purpose=PURPOSE_EMERGENCY, fields={FIELD_DIAGNOSIS},
                break_glass_id=grant.grant_id),
            now,
        )
        self.assertTrue(allowed.allowed)

        # 主动通知安全部门与患者
        audiences = {n.audience for n in svc.notifications.list()}
        self.assertIn("security_officer", audiences)
        self.assertIn("patient:P-1", audiences)

        # 授权短时有效
        expired = svc.check_access(
            req(staff_id="I-1", role=ROLE_INTERN, relationship=REL_NONE,
                purpose=PURPOSE_EMERGENCY, fields={FIELD_DIAGNOSIS},
                break_glass_id=grant.grant_id),
            now + timedelta(seconds=301),
        )
        self.assertEqual(expired.reason, "break-glass-expired")

        # 事后复核
        self.assertTrue(svc.breakglass.pending_reviews(now + timedelta(seconds=301)))
        svc.review_break_glass(grant.grant_id, "SEC-1", "upheld", "属实", now=now + timedelta(seconds=400))
        self.assertEqual(svc.breakglass.get(grant.grant_id).review_outcome, "upheld")
        self.assertFalse(svc.breakglass.pending_reviews(now + timedelta(seconds=401)))

    def test_grant_bound_to_staff_and_patient(self):
        svc = PrivacyService()
        now = utcnow()
        grant = svc.request_break_glass("I-1", "P-1", "抢救", now=now)
        decision = svc.check_access(
            req(staff_id="I-2", role=ROLE_INTERN, relationship=REL_NONE,
                purpose=PURPOSE_EMERGENCY, fields={FIELD_DIAGNOSIS},
                break_glass_id=grant.grant_id),
            now,
        )
        self.assertEqual(decision.reason, "break-glass-scope-mismatch")


class ExportAndWatermarkTest(unittest.TestCase):
    def test_export_records_only_hash_chain_and_recipient(self):
        svc, _c, teaching_req, now = make_teaching_service()
        session = svc.begin_export(teaching_req, recipient="教学平台", source_id="SRC-9", now=now)
        record = svc.complete_export(session.session_id, "sha256:abc", now=now)
        self.assertEqual(record.file_hash, "sha256:abc")
        self.assertEqual(record.recipient, "教学平台")
        self.assertEqual(len(record.auth_chain), 3)
        self.assertFalse(hasattr(record, "content"))  # 不保存原始影像副本

    def test_watermark_contains_operator_and_time(self):
        svc, _c, teaching_req, now = make_teaching_service()
        session = svc.begin_export(teaching_req, recipient="教学平台", source_id="SRC-9", now=now)
        record = svc.complete_export(session.session_id, "hash-1", now=now)
        result = svc.verify_download("hash-1", record.watermark)
        self.assertTrue(result["valid"])
        self.assertEqual(result["operator"], "D-1")
        self.assertEqual(result["occurred_at"], record.completed_at.isoformat())
        self.assertEqual(result["chain"], list(record.auth_chain))

    def test_old_watermark_verifies_after_key_rotation(self):
        svc, _c, teaching_req, now = make_teaching_service()
        s1 = svc.begin_export(teaching_req, recipient="教学平台", source_id="SRC-9", now=now)
        old_record = svc.complete_export(s1.session_id, "hash-old", now=now)
        svc.rotate_keys()
        result = svc.verify_download("hash-old", old_record.watermark)
        self.assertTrue(result["valid"])
        s2 = svc.begin_export(teaching_req, recipient="教学平台", source_id="SRC-9", now=now)
        new_record = svc.complete_export(s2.session_id, "hash-new", now=now)
        self.assertNotEqual(
            old_record.watermark.split(".")[1], new_record.watermark.split(".")[1]
        )

    def test_tampered_or_mismatched_watermark_rejected(self):
        svc, _c, teaching_req, now = make_teaching_service()
        session = svc.begin_export(teaching_req, recipient="教学平台", source_id="SRC-9", now=now)
        record = svc.complete_export(session.session_id, "hash-1", now=now)
        tampered = record.watermark[:-1] + ("0" if not record.watermark.endswith("0") else "1")
        self.assertFalse(svc.verify_download("hash-1", tampered)["valid"])
        self.assertFalse(svc.verify_download("hash-2", record.watermark)["valid"])

    def test_duplicate_export_blocked(self):
        svc, _c, teaching_req, now = make_teaching_service()
        s1 = svc.begin_export(teaching_req, recipient="教学平台", source_id="SRC-9", now=now)
        svc.complete_export(s1.session_id, "hash-1", now=now)
        s2 = svc.begin_export(teaching_req, recipient="教学平台", source_id="SRC-9", now=now)
        with self.assertRaises(DuplicateExport):
            svc.complete_export(s2.session_id, "hash-1", now=now)

    def test_expired_session_cannot_complete(self):
        svc, _c, teaching_req, now = make_teaching_service()
        session = svc.begin_export(teaching_req, recipient="教学平台", source_id="SRC-9", now=now)
        with self.assertRaises(ExportSessionError):
            svc.complete_export(session.session_id, "hash-1", now=now + timedelta(seconds=601))

    def test_concurrent_withdrawal_is_linearizable(self):
        svc = PrivacyService()
        now = utcnow()
        for i in range(20):
            consent = svc.grant_consent(
                patient_id=f"P-c{i}", version="v1", purposes={PURPOSE_TEACHING},
                fields={FIELD_DIAGNOSIS},
                valid_from=now - timedelta(days=1), valid_until=now + timedelta(days=30),
            )
            session = svc.begin_export(
                req(patient_id=f"P-c{i}", purpose=PURPOSE_TEACHING,
                    fields={FIELD_DIAGNOSIS}, consent_version="v1"),
                recipient="教学平台", source_id=f"SRC-c{i}", now=now,
            )
            barrier = threading.Barrier(2)
            outcome = {}

            def do_complete(s=session, h=f"hash-{i}"):
                barrier.wait()
                try:
                    outcome["record"] = svc.complete_export(s.session_id, h)
                except ConsentWithdrawn:
                    outcome["blocked"] = True

            def do_withdraw(c=consent):
                barrier.wait()
                outcome["consent"] = svc.withdraw_consent(c.consent_id)

            threads = [threading.Thread(target=do_complete), threading.Thread(target=do_withdraw)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            record = outcome.get("record")
            if record is not None:
                self.assertLessEqual(record.completed_at, outcome["consent"].withdrawn_at)
            else:
                self.assertTrue(outcome.get("blocked"))
                self.assertEqual(session.state, "blocked")


class IncidentResponseTest(unittest.TestCase):
    def setUp(self):
        self.svc, _c, self.teaching_req, self.now = make_teaching_service()
        s1 = self.svc.begin_export(self.teaching_req, recipient="账号A", source_id="SRC-7", now=self.now)
        self.rec1 = self.svc.complete_export(s1.session_id, "hash-a", now=self.now)
        s2 = self.svc.begin_export(self.teaching_req, recipient="账号B", source_id="SRC-7", now=self.now)
        self.rec2 = self.svc.complete_export(s2.session_id, "hash-b", now=self.now)

    def test_incident_freezes_related_audit(self):
        incident = self.svc.report_incident(
            "unauthorized_photo", "P-1", reporter="SEC-1", export_ids=[self.rec1.export_id]
        )
        self.assertTrue(incident.frozen_audit_seqs)
        frozen = self.svc.audit.frozen_entries()
        self.assertTrue(frozen)
        self.assertTrue(all(e.details.get("patient_id") == "P-1" for e in frozen))
        self.assertTrue(self.svc.audit.verify_chain())

    def test_trace_same_source(self):
        traced = self.svc.trace_same_source(self.rec1.export_id)
        self.assertEqual({r.export_id for r in traced}, {self.rec1.export_id, self.rec2.export_id})

    def test_deletion_requires_second_confirmer(self):
        request = self.svc.initiate_deletion(self.rec1.export_id, "leak", initiator="SEC-1")
        with self.assertRaises(DeletionStateError):
            self.svc.confirm_deletion(request.request_id, confirmer="SEC-1")
        self.svc.confirm_deletion(request.request_id, confirmer="SEC-2")
        self.assertEqual(self.svc.exports.get(self.rec1.export_id).delivery_status, "deletion_confirmed")

    def test_retention_policy_due_dates(self):
        leak = self.svc.initiate_deletion(self.rec1.export_id, "leak", initiator="SEC-1", now=self.now)
        self.assertEqual(leak.due_at, self.now)  # 违规类立即到期
        routine = self.svc.initiate_deletion(self.rec2.export_id, "routine", initiator="SEC-1", now=self.now)
        self.assertEqual(routine.due_at, self.now + timedelta(days=30))

    def test_admin_cannot_erase_own_operations(self):
        entry = self.svc.audit.append("admin-1", "config.change", {"key": "retention"})
        self.assertFalse(self.svc.audit.erase("admin-1", entry.seq))
        actions = [e.action for e in self.svc.audit.entries()]
        self.assertIn("config.change", actions)
        self.assertIn("audit.erase.denied", actions)
        self.assertTrue(self.svc.audit.verify_chain())


class SimulationTest(unittest.TestCase):
    def test_all_security_scenarios_pass(self):
        report = run_simulation()
        for scenario in report["scenarios"]:
            self.assertTrue(scenario["passed"], f"{scenario['name']}: {scenario['failures']}")


if __name__ == "__main__":
    unittest.main()
