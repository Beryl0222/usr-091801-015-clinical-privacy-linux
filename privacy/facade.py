"""门面服务：装配各组件，并保证关键并发不变量。

最重要的是“撤回 vs 完成导出”的线性化：两者都在同一把锁内完成，
因此不存在“撤回已生效但导出仍完成”的中间态。
"""

from __future__ import annotations

import threading
from datetime import datetime
from typing import Optional

from .audit import AuditLog
from .breakglass import BreakGlassGrant, BreakGlassService
from .consent import Consent, ConsentRegistry
from .exports import ExportRecord, ExportService, ExportSession
from .incidents import DeletionRequest, Incident, IncidentService, RetentionPolicy
from .models import (
    AccessRequest,
    Decision,
    NotificationCenter,
    WatermarkInvalid,
    utcnow,
)
from .policy import DEFAULT_CACHE_TTL_SECONDS, DecisionCache, PolicyEngine
from .watermark import KeyRing


class PrivacyService:
    """诊疗隐私用途管控的统一入口。"""

    def __init__(
        self,
        cache_ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
        session_ttl_seconds: int = 600,
        retention_days: int = 30,
    ) -> None:
        # 串行化“撤回同意”与“完成导出”的主锁
        self._lock = threading.RLock()
        self.audit = AuditLog()
        self.notifications = NotificationCenter()
        self.consents = ConsentRegistry()
        self.breakglass = BreakGlassService(self.audit, self.notifications)
        self.keyring = KeyRing()
        self.policy = PolicyEngine(
            self.consents,
            self.breakglass,
            self.audit,
            DecisionCache(cache_ttl_seconds),
        )
        self.exports = ExportService(
            self.policy, self.consents, self.keyring, self.audit, session_ttl_seconds
        )
        self.incidents = IncidentService(
            self.audit, self.exports, RetentionPolicy(retention_days), self.notifications
        )
        # 撤回即失效：缓存中的放行决策按患者清除
        self.consents.add_listener(lambda c: self.policy.cache.invalidate_patient(c.patient_id))

    # --- 访问评估 ---
    def check_access(self, request: AccessRequest, now: Optional[datetime] = None) -> Decision:
        return self.policy.evaluate(request, now or utcnow())

    # --- 知情同意 ---
    def grant_consent(
        self,
        patient_id: str,
        version: str,
        purposes,
        fields,
        valid_from: datetime,
        valid_until: datetime,
        actor: str = "patient",
    ) -> Consent:
        with self._lock:
            consent = self.consents.register(
                patient_id, version, purposes, fields, valid_from, valid_until
            )
            self.audit.append(
                actor,
                "consent.registered",
                {
                    "patient_id": patient_id,
                    "consent_id": consent.consent_id,
                    "version": consent.version,
                    "purposes": sorted(consent.purposes),
                    "valid_until": consent.valid_until.isoformat(),
                },
            )
            return consent

    def withdraw_consent(
        self, consent_id: str, actor: str = "patient", now: Optional[datetime] = None
    ) -> Consent:
        """撤回同意；与 complete_export 互斥，撤回后未完成导出必被阻断。"""
        with self._lock:
            consent = self.consents.withdraw(consent_id, now=now)
            self.audit.append(
                actor,
                "consent.withdrawn",
                {
                    "patient_id": consent.patient_id,
                    "consent_id": consent.consent_id,
                    "version": consent.version,
                },
                now=now,
            )
            return consent

    # --- break-glass ---
    def request_break_glass(
        self,
        staff_id: str,
        patient_id: str,
        reason: str,
        ttl_seconds: int = 600,
        now: Optional[datetime] = None,
    ) -> BreakGlassGrant:
        return self.breakglass.request(staff_id, patient_id, reason, ttl_seconds, now=now)

    def review_break_glass(
        self,
        grant_id: str,
        reviewer: str,
        outcome: str,
        notes: str = "",
        now: Optional[datetime] = None,
    ) -> BreakGlassGrant:
        return self.breakglass.review(grant_id, reviewer, outcome, notes, now=now)

    # --- 导出与水印 ---
    def begin_export(
        self,
        request: AccessRequest,
        recipient: str,
        source_id: str,
        now: Optional[datetime] = None,
    ) -> ExportSession:
        return self.exports.begin(request, recipient, source_id, now=now)

    def complete_export(
        self, session_id: str, file_hash: str, now: Optional[datetime] = None
    ) -> ExportRecord:
        """完成导出；与 withdraw_consent 互斥，保证撤回即时生效。"""
        with self._lock:
            return self.exports.complete(session_id, file_hash, now=now)

    def verify_download(self, file_hash: str, watermark: str) -> dict:
        """用文件哈希验证水印并解析授权链；验证失败返回 valid=False。"""
        try:
            return self.exports.verify_download(file_hash, watermark)
        except WatermarkInvalid as exc:
            return {"valid": False, "reason": str(exc)}

    def rotate_keys(self, actor: str = "key-admin") -> str:
        """轮换水印签名密钥；旧密钥保留，旧水印仍可验证。"""
        with self._lock:
            kid = self.keyring.rotate()
            self.audit.append(actor, "keyring.rotated", {"active_kid": kid})
            return kid

    # --- 事件响应 ---
    def report_incident(
        self,
        kind: str,
        patient_id: str,
        reporter: str,
        description: str = "",
        export_ids=(),
        now: Optional[datetime] = None,
    ) -> Incident:
        return self.incidents.report(kind, patient_id, reporter, description, export_ids, now=now)

    def trace_same_source(self, export_id: str) -> list[ExportRecord]:
        return self.incidents.trace_same_source(export_id)

    def initiate_deletion(
        self, export_id: str, reason: str, initiator: str, now: Optional[datetime] = None
    ) -> DeletionRequest:
        return self.incidents.initiate_deletion(export_id, reason, initiator, now=now)

    def confirm_deletion(
        self, request_id: str, confirmer: str, now: Optional[datetime] = None
    ) -> DeletionRequest:
        return self.incidents.confirm_deletion(request_id, confirmer, now=now)
