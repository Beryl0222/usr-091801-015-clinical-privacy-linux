"""安全部门模拟场景：按角色矩阵演练越权、过期缓存、重复导出、
密钥轮换与并发撤回，并验证违规事件的处置闭环。

运行：python3 -m privacy.simulation
退出码：全部场景通过为 0，否则为 1。
"""

from __future__ import annotations

import threading
from datetime import timedelta

from .facade import PrivacyService
from .models import (
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
    ROLE_INTERN,
    ROLE_NURSE,
    ROLE_PHYSICIAN,
    ROLE_RESEARCHER,
    AccessRequest,
    BreakGlassError,
    ConsentWithdrawn,
    DeletionStateError,
    DuplicateExport,
    utcnow,
)


def _req(**kw) -> AccessRequest:
    defaults = dict(
        staff_id="S-1",
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


def _check(fn, description: str, failures: list[str]) -> None:
    try:
        ok = bool(fn())
    except Exception as exc:  # 场景内任何异常都记为失败
        failures.append(f"{description}（异常 {type(exc).__name__}: {exc}）")
        return
    if not ok:
        failures.append(description)


def scenario_role_matrix() -> tuple[str, list[str]]:
    """越权：角色矩阵之外的用途与字段一律阻断。"""
    svc = PrivacyService()
    failures: list[str] = []
    cases = [
        # (请求, 期望放行, 期望原因)
        (_req(role=ROLE_INTERN, fields={FIELD_OBSTETRIC_MEDIA}), False, "field-scope-exceeds-role-ceiling"),
        (_req(role=ROLE_INTERN, purpose=PURPOSE_RESEARCH), False, "purpose-not-in-role-matrix"),
        (_req(role=ROLE_NURSE, relationship=REL_ASSIGNED, purpose=PURPOSE_DISSEMINATION,
              fields={FIELD_OBSTETRIC_MEDIA}), False, "purpose-not-in-role-matrix"),
        (_req(role=ROLE_ADMIN), False, "purpose-not-in-role-matrix"),
        (_req(relationship=REL_NONE), False, "clinical-relationship-required"),
        (_req(fields={FIELD_OBSTETRIC_MEDIA}), True, "allowed"),
    ]
    for i, (req, expected_allowed, expected_reason) in enumerate(cases, 1):
        decision = svc.check_access(req)
        _check(
            lambda d=decision, a=expected_allowed, r=expected_reason: d.allowed == a and d.reason == r,
            f"用例{i}: 期望 allowed={expected_allowed} reason={expected_reason}，实际 {decision.allowed}/{decision.reason}",
            failures,
        )
    return "角色矩阵越权", failures


def scenario_expired_cache() -> tuple[str, list[str]]:
    """过期缓存：撤回后缓存失效，手工注入的过期条目不被采信。"""
    svc = PrivacyService(cache_ttl_seconds=30)
    now = utcnow()
    consent = svc.grant_consent(
        patient_id="P-2",
        version="teach-v2",
        purposes={PURPOSE_TEACHING},
        fields={FIELD_DIAGNOSIS},
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=30),
    )
    req = _req(
        staff_id="D-2",
        patient_id="P-2",
        purpose=PURPOSE_TEACHING,
        fields={FIELD_DIAGNOSIS},
        consent_version="teach-v2",
    )
    failures: list[str] = []
    first = svc.check_access(req, now)
    _check(lambda: first.allowed, "首次评估应放行", failures)

    svc.withdraw_consent(consent.consent_id, now=now)
    second = svc.check_access(req, now + timedelta(seconds=1))
    _check(
        lambda: not second.allowed and second.reason == "consent-expired-or-withdrawn",
        f"撤回后应阻断，实际 {second.allowed}/{second.reason}",
        failures,
    )

    # 模拟脏缓存：把旧的放行决策以“已过期”的时间写回，绝不能被采信
    svc.policy.cache.put(req, first, now - timedelta(seconds=120), ttl_seconds=30)
    third = svc.check_access(req, now + timedelta(seconds=2))
    _check(
        lambda: not third.allowed,
        f"过期缓存不得放行，实际 {third.allowed}/{third.reason}",
        failures,
    )
    return "过期缓存", failures


def scenario_duplicate_export() -> tuple[str, list[str]]:
    """重复导出：同人同患者同哈希同交付对象的第二次导出被阻断。"""
    svc = PrivacyService()
    now = utcnow()
    svc.grant_consent(
        patient_id="P-3",
        version="res-v1",
        purposes={PURPOSE_RESEARCH},
        fields={FIELD_DIAGNOSIS, FIELD_LABS},
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=30),
    )
    req = _req(
        staff_id="R-1",
        role=ROLE_RESEARCHER,
        patient_id="P-3",
        relationship=REL_NONE,
        purpose=PURPOSE_RESEARCH,
        fields={FIELD_DIAGNOSIS},
        consent_version="res-v1",
    )
    failures: list[str] = []
    s1 = svc.begin_export(req, recipient="CRO-1", source_id="SRC-3", now=now)
    svc.complete_export(s1.session_id, "hash-aaa", now=now)
    s2 = svc.begin_export(req, recipient="CRO-1", source_id="SRC-3", now=now)
    try:
        svc.complete_export(s2.session_id, "hash-aaa", now=now)
        failures.append("重复导出应被阻断")
    except DuplicateExport:
        pass
    # 不同交付对象属于新的交付，应允许并单独登记
    s3 = svc.begin_export(req, recipient="CRO-2", source_id="SRC-3", now=now)
    try:
        svc.complete_export(s3.session_id, "hash-aaa", now=now)
    except DuplicateExport:
        failures.append("不同交付对象不应误判为重复")
    return "重复导出", failures


def scenario_key_rotation() -> tuple[str, list[str]]:
    """密钥轮换：旧文件哈希仍能验证旧水印并追到授权链，新导出用新密钥。"""
    svc = PrivacyService()
    now = utcnow()
    svc.grant_consent(
        patient_id="P-4",
        version="teach-v1",
        purposes={PURPOSE_TEACHING},
        fields={FIELD_DIAGNOSIS, FIELD_OBSTETRIC_MEDIA},
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=30),
    )
    req = _req(
        staff_id="D-4",
        patient_id="P-4",
        purpose=PURPOSE_TEACHING,
        fields={FIELD_OBSTETRIC_MEDIA},
        consent_version="teach-v1",
    )
    failures: list[str] = []
    kid_before = svc.keyring.active_kid
    s1 = svc.begin_export(req, recipient="教学平台", source_id="SRC-4", now=now)
    rec1 = svc.complete_export(s1.session_id, "hash-old", now=now)

    svc.rotate_keys()
    kid_after = svc.keyring.active_kid
    _check(lambda: kid_before != kid_after, "轮换后 active 密钥应变化", failures)

    # 旧文件哈希 + 旧水印：仍可验证并追到完整授权链
    result = svc.verify_download("hash-old", rec1.watermark)
    _check(lambda: result["valid"], "旧水印应仍有效", failures)
    _check(
        lambda: result.get("operator") == "D-4" and len(result.get("chain", [])) == 3,
        "授权链应含操作者与三段引用",
        failures,
    )

    # 新导出使用新密钥
    s2 = svc.begin_export(req, recipient="教学平台", source_id="SRC-4", now=now)
    rec2 = svc.complete_export(s2.session_id, "hash-new", now=now)
    _check(
        lambda: rec2.watermark.split(".")[1] == kid_after,
        "新水印应使用新密钥",
        failures,
    )

    # 篡改与哈希不符都必须失败
    tampered = rec1.watermark[:-1] + ("0" if not rec1.watermark.endswith("0") else "1")
    _check(lambda: not svc.verify_download("hash-old", tampered)["valid"], "篡改水印应失败", failures)
    _check(
        lambda: not svc.verify_download("hash-other", rec1.watermark)["valid"],
        "哈希不符应失败",
        failures,
    )
    return "密钥轮换", failures


def scenario_concurrent_withdrawal() -> tuple[str, list[str]]:
    """并发撤回：完成导出与撤回竞争，结果必须线性一致。"""
    svc = PrivacyService()
    now = utcnow()
    failures: list[str] = []
    rounds = 25
    for i in range(rounds):
        patient_id = f"P-5-{i}"
        consent = svc.grant_consent(
            patient_id=patient_id,
            version="teach-v9",
            purposes={PURPOSE_TEACHING},
            fields={FIELD_DIAGNOSIS},
            valid_from=now - timedelta(days=1),
            valid_until=now + timedelta(days=30),
        )
        req = _req(
            staff_id="D-5",
            patient_id=patient_id,
            purpose=PURPOSE_TEACHING,
            fields={FIELD_DIAGNOSIS},
            consent_version="teach-v9",
        )
        session = svc.begin_export(req, recipient="教学平台", source_id=f"SRC-5-{i}", now=now)
        barrier = threading.Barrier(2)
        outcome: dict[str, object] = {}

        def do_complete():
            barrier.wait()
            try:
                outcome["record"] = svc.complete_export(session.session_id, f"hash-{i}")
            except ConsentWithdrawn:
                outcome["blocked"] = True

        def do_withdraw():
            barrier.wait()
            outcome["consent"] = svc.withdraw_consent(consent.consent_id)

        t1 = threading.Thread(target=do_complete)
        t2 = threading.Thread(target=do_withdraw)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        record = outcome.get("record")
        withdrawn_consent = outcome["consent"]
        if record is not None:
            # 完成胜出：完成时间必不晚于撤回生效时间（线性化）
            _check(
                lambda r=record, c=withdrawn_consent: r.completed_at <= c.withdrawn_at,
                f"第{i}轮：导出完成时间晚于撤回时间",
                failures,
            )
        else:
            _check(
                lambda: outcome.get("blocked") is True and session.state == "blocked",
                f"第{i}轮：撤回后导出应被阻断",
                failures,
            )
    return "并发撤回", failures


def scenario_break_glass() -> tuple[str, list[str]]:
    """break-glass：理由必填、短时授权、事后复核、主动通知。"""
    svc = PrivacyService()
    now = utcnow()
    failures: list[str] = []
    req = _req(
        staff_id="I-9",
        role=ROLE_INTERN,
        patient_id="P-9",
        relationship=REL_NONE,
        purpose=PURPOSE_EMERGENCY,
        fields={FIELD_DIAGNOSIS, FIELD_OBSTETRIC_MEDIA},
    )
    denied = svc.check_access(req, now)
    _check(lambda: not denied.allowed and denied.reason == "break-glass-required",
           "无授权应阻断", failures)

    try:
        svc.request_break_glass("I-9", "P-9", "", now=now)
        failures.append("空理由应被拒绝")
    except BreakGlassError:
        pass

    grant = svc.request_break_glass("I-9", "P-9", "术中大出血需调阅影像", ttl_seconds=300, now=now)
    allowed = svc.check_access(
        _req(
            staff_id="I-9",
            role=ROLE_INTERN,
            patient_id="P-9",
            relationship=REL_NONE,
            purpose=PURPOSE_EMERGENCY,
            fields={FIELD_DIAGNOSIS, FIELD_OBSTETRIC_MEDIA},
            break_glass_id=grant.grant_id,
        ),
        now,
    )
    _check(lambda: allowed.allowed, "有效授权应放行", failures)

    notes = svc.notifications.list()
    _check(
        lambda: any(n.audience == "security_officer" for n in notes)
        and any(n.audience == "patient:P-9" for n in notes),
        "应主动通知安全部门与患者",
        failures,
    )

    expired = svc.check_access(
        _req(
            staff_id="I-9",
            role=ROLE_INTERN,
            patient_id="P-9",
            relationship=REL_NONE,
            purpose=PURPOSE_EMERGENCY,
            fields={FIELD_DIAGNOSIS},
            break_glass_id=grant.grant_id,
        ),
        now + timedelta(seconds=301),
    )
    _check(
        lambda: not expired.allowed and expired.reason == "break-glass-expired",
        f"授权过期应阻断，实际 {expired.allowed}/{expired.reason}",
        failures,
    )

    _check(
        lambda: any(g.grant_id == grant.grant_id for g in svc.breakglass.pending_reviews(now + timedelta(seconds=301))),
        "过期授权应进入待复核队列",
        failures,
    )
    svc.review_break_glass(grant.grant_id, reviewer="SEC-1", outcome="upheld", notes="情况属实", now=now + timedelta(seconds=400))
    _check(
        lambda: svc.breakglass.get(grant.grant_id).review_outcome == "upheld",
        "复核结论应落账",
        failures,
    )
    return "break-glass 紧急授权", failures


def scenario_incident_response() -> tuple[str, list[str]]:
    """违规外泄：冻结审计、同源追踪、删除确认、管理员无法抹除操作。"""
    svc = PrivacyService()
    now = utcnow()
    svc.grant_consent(
        patient_id="P-7",
        version="teach-v7",
        purposes={PURPOSE_TEACHING},
        fields={FIELD_OBSTETRIC_MEDIA},
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=30),
    )
    req = _req(
        staff_id="D-7",
        patient_id="P-7",
        purpose=PURPOSE_TEACHING,
        fields={FIELD_OBSTETRIC_MEDIA},
        consent_version="teach-v7",
    )
    failures: list[str] = []
    s1 = svc.begin_export(req, recipient="账号A", source_id="SRC-77", now=now)
    rec1 = svc.complete_export(s1.session_id, "hash-leak", now=now)
    s2 = svc.begin_export(req, recipient="账号B", source_id="SRC-77", now=now)
    rec2 = svc.complete_export(s2.session_id, "hash-leak-2", now=now)

    incident = svc.report_incident(
        "leak", "P-7", reporter="SEC-1", description="社交平台发现未遮挡影像",
        export_ids=[rec1.export_id], now=now,
    )
    _check(lambda: len(incident.frozen_audit_seqs) > 0, "相关审计应被冻结", failures)
    _check(lambda: svc.audit.verify_chain(), "冻结后哈希链应完好", failures)

    traced = svc.trace_same_source(rec1.export_id)
    _check(
        lambda: {r.export_id for r in traced} == {rec1.export_id, rec2.export_id},
        "同源导出应全部追踪到",
        failures,
    )

    deletion = svc.initiate_deletion(rec1.export_id, reason="leak", initiator="SEC-1", now=now)
    _check(lambda: deletion.due_at == now, "外泄应立即到期删除", failures)
    try:
        svc.confirm_deletion(deletion.request_id, confirmer="SEC-1", now=now)
        failures.append("发起人与确认人相同应被拒绝")
    except DeletionStateError:
        pass
    svc.confirm_deletion(deletion.request_id, confirmer="SEC-2", now=now)
    _check(
        lambda: svc.exports.get(rec1.export_id).delivery_status == "deletion_confirmed",
        "确认后交付状态应更新",
        failures,
    )

    # 管理员试图抹除自己的操作：拒绝且留痕
    admin_entry = svc.audit.append("admin-1", "config.change", {"key": "retention_days"})
    erased = svc.audit.erase("admin-1", admin_entry.seq)
    _check(lambda: erased is False, "抹除应被拒绝", failures)
    actions = [e.action for e in svc.audit.entries()]
    _check(
        lambda: "config.change" in actions and "audit.erase.denied" in actions,
        "原操作与抹除尝试都应留痕",
        failures,
    )
    _check(lambda: svc.audit.verify_chain(), "抹除尝试后哈希链应完好", failures)
    return "违规外泄处置", failures


SCENARIOS = [
    scenario_role_matrix,
    scenario_expired_cache,
    scenario_duplicate_export,
    scenario_key_rotation,
    scenario_concurrent_withdrawal,
    scenario_break_glass,
    scenario_incident_response,
]


def run_simulation() -> dict:
    """运行全部场景，返回结构化报告。"""
    results = []
    for scenario in SCENARIOS:
        name, failures = scenario()
        results.append({"name": name, "passed": not failures, "failures": failures})
    return {"scenarios": results, "all_passed": all(r["passed"] for r in results)}


def format_report(report: dict) -> str:
    lines = ["安全模拟报告", "=" * 40]
    for result in report["scenarios"]:
        mark = "通过" if result["passed"] else "失败"
        lines.append(f"[{mark}] {result['name']}")
        for failure in result["failures"]:
            lines.append(f"    - {failure}")
    lines.append("=" * 40)
    lines.append("全部场景通过" if report["all_passed"] else "存在失败场景")
    return "\n".join(lines)


def main() -> int:
    report = run_simulation()
    print(format_report(report))
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
