"""导出会话与登记：只记录文件哈希、授权链与交付对象，不保存原始影像。

流程：begin（策略评估，生成会话）-> complete（复核同意状态、查重、
签发含水印的回执并登记）。同意撤回后，所有未完成会话在 complete 时
被阻断；同一（操作者, 患者, 文件哈希, 交付对象）不允许重复导出。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from .audit import AuditLog
from .consent import ConsentRegistry
from .models import (
    AccessRequest,
    ConsentWithdrawn,
    DuplicateExport,
    ExportSessionError,
    PolicyDenied,
    new_id,
    utcnow,
)
from .policy import PolicyEngine
from .watermark import KeyRing, issue, verify

DEFAULT_SESSION_TTL_SECONDS = 600


@dataclass
class ExportSession:
    session_id: str
    request: AccessRequest
    decision_id: str
    consent_id: Optional[str]
    break_glass_id: Optional[str]
    recipient: str  # 交付对象
    source_id: str  # 来源标识（同源追踪用）
    created_at: datetime
    expires_at: datetime
    state: str = "pending"  # pending | completed | blocked | expired


@dataclass
class ExportRecord:
    """导出登记：只含哈希与授权链，绝不含原始内容。"""

    export_id: str
    operator_id: str
    patient_id: str
    purpose: str
    recipient: str
    source_id: str
    file_hash: str
    watermark: str
    auth_chain: tuple  # (决策号, 同意/紧急授权引用, 会话号)
    completed_at: datetime
    delivery_status: str = "delivered"  # delivered | deletion_pending | deletion_confirmed


class ExportService:
    def __init__(
        self,
        policy: PolicyEngine,
        consents: ConsentRegistry,
        keyring: KeyRing,
        audit: AuditLog,
        session_ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    ) -> None:
        self._policy = policy
        self._consents = consents
        self._keyring = keyring
        self._audit = audit
        self._session_ttl = session_ttl_seconds
        self._sessions: dict[str, ExportSession] = {}
        self._records: dict[str, ExportRecord] = {}
        self._lock = threading.RLock()

    def begin(
        self,
        request: AccessRequest,
        recipient: str,
        source_id: str,
        now: Optional[datetime] = None,
    ) -> ExportSession:
        """策略评估通过后开启导出会话；拒绝则抛 PolicyDenied。"""
        now = now or utcnow()
        if not recipient or not recipient.strip():
            raise ExportSessionError("export-recipient-required")
        decision = self._policy.evaluate(request, now)
        if not decision.allowed:
            raise PolicyDenied(decision.reason)
        session = ExportSession(
            session_id=new_id("exp"),
            request=request,
            decision_id=decision.decision_id,
            consent_id=decision.consent_id,
            break_glass_id=decision.break_glass_id,
            recipient=recipient.strip(),
            source_id=source_id,
            created_at=now,
            expires_at=now + timedelta(seconds=self._session_ttl),
        )
        with self._lock:
            self._sessions[session.session_id] = session
        self._audit.append(
            request.staff_id,
            "export.session.opened",
            {
                "patient_id": request.patient_id,
                "session_id": session.session_id,
                "decision_id": decision.decision_id,
                "purpose": request.purpose,
                "recipient": session.recipient,
                "source_id": source_id,
            },
        )
        return session

    def complete(self, session_id: str, file_hash: str, now: Optional[datetime] = None) -> ExportRecord:
        """完成导出：复核同意、查重、签水印、登记哈希与授权链。

        注意：调用方（门面）负责把本方法与同意撤回串行化。
        """
        now = now or utcnow()
        if not file_hash or not file_hash.strip():
            raise ExportSessionError("export-file-hash-required")
        file_hash = file_hash.strip()
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise ExportSessionError("export-session-unknown")
            if session.state != "pending":
                raise ExportSessionError("export-session-not-pending")
            if now >= session.expires_at:
                session.state = "expired"
                self._audit.append(
                    session.request.staff_id,
                    "export.session.expired",
                    {"patient_id": session.request.patient_id, "session_id": session_id},
                )
                raise ExportSessionError("export-session-expired")

            # 撤回即阻断：完成前复核同意仍然有效
            if session.consent_id and not self._consents.is_active(session.consent_id, now):
                session.state = "blocked"
                self._audit.append(
                    session.request.staff_id,
                    "export.blocked",
                    {
                        "patient_id": session.request.patient_id,
                        "session_id": session_id,
                        "consent_id": session.consent_id,
                        "reason": "consent-withdrawn",
                    },
                )
                raise ConsentWithdrawn("consent-withdrawn")

            # 重复导出检测：同人、同患者、同哈希、同交付对象
            for record in self._records.values():
                if (
                    record.operator_id == session.request.staff_id
                    and record.patient_id == session.request.patient_id
                    and record.file_hash == file_hash
                    and record.recipient == session.recipient
                ):
                    self._audit.append(
                        session.request.staff_id,
                        "export.duplicate.denied",
                        {
                            "patient_id": session.request.patient_id,
                            "session_id": session_id,
                            "file_hash": file_hash,
                            "recipient": session.recipient,
                            "original_export_id": record.export_id,
                        },
                    )
                    raise DuplicateExport("duplicate-export")

            export_id = new_id("exr")
            auth_chain = (
                session.decision_id,
                session.consent_id or session.break_glass_id or "clinical-relationship",
                session.session_id,
            )
            payload = {
                "export_id": export_id,
                "operator": session.request.staff_id,
                "occurred_at": now.isoformat(),
                "file_hash": file_hash,
                "patient_id": session.request.patient_id,
                "purpose": session.request.purpose,
                "recipient": session.recipient,
                "chain": list(auth_chain),
            }
            record = ExportRecord(
                export_id=export_id,
                operator_id=session.request.staff_id,
                patient_id=session.request.patient_id,
                purpose=session.request.purpose,
                recipient=session.recipient,
                source_id=session.source_id,
                file_hash=file_hash,
                watermark=issue(self._keyring, payload),
                auth_chain=auth_chain,
                completed_at=now,
            )
            self._records[export_id] = record
            session.state = "completed"
        self._audit.append(
            session.request.staff_id,
            "export.completed",
            {
                "patient_id": record.patient_id,
                "export_id": export_id,
                "session_id": session_id,
                "file_hash": file_hash,
                "recipient": record.recipient,
                "source_id": record.source_id,
                "auth_chain": list(auth_chain),
            },
        )
        return record

    def get(self, export_id: str) -> Optional[ExportRecord]:
        with self._lock:
            return self._records.get(export_id)

    def records(self) -> list[ExportRecord]:
        with self._lock:
            return list(self._records.values())

    def trace_source(self, source_id: str) -> list[ExportRecord]:
        """同源导出追踪：同一来源标识的全部交付记录。"""
        with self._lock:
            return [r for r in self._records.values() if r.source_id == source_id]

    def verify_download(self, file_hash: str, watermark: str) -> dict:
        """用文件哈希验证水印，并解析出完整授权链与交付对象。"""
        payload = verify(self._keyring, watermark, file_hash)
        record = self._records.get(payload.get("export_id", ""))
        return {
            "valid": True,
            "export_id": payload["export_id"],
            "operator": payload["operator"],
            "occurred_at": payload["occurred_at"],
            "chain": list(payload["chain"]),
            "recipient": payload["recipient"],
            "registered": record is not None,
            "delivery_status": record.delivery_status if record else None,
        }
