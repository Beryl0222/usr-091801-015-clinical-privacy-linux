"""违规拍摄/外泄事件响应：冻结审计、同源追踪、按保留政策的删除确认。"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from .audit import AuditLog
from .exports import ExportRecord, ExportService
from .models import (
    DeletionStateError,
    NotificationCenter,
    PrivacyError,
    ROLE_SECURITY,
    new_id,
    utcnow,
)

# 需要立即删除交付副本的原因；其余按保留期限到期删除
IMMEDIATE_DELETION_REASONS = frozenset(
    {"leak", "unauthorized_photo", "consent_withdrawn", "incident"}
)


class RetentionPolicy:
    """交付副本的保留政策：默认保留天数，违规类原因立即到期。"""

    def __init__(self, export_copy_days: int = 30) -> None:
        self.export_copy_days = export_copy_days

    def due_at(self, reason: str, now: datetime) -> datetime:
        if reason in IMMEDIATE_DELETION_REASONS:
            return now
        return now + timedelta(days=self.export_copy_days)


@dataclass
class Incident:
    incident_id: str
    kind: str  # leak | unauthorized_photo | ...
    patient_id: str
    reporter: str
    description: str
    related_export_ids: list
    created_at: datetime
    status: str = "open"  # open | resolved
    frozen_audit_seqs: list = field(default_factory=list)


@dataclass
class DeletionRequest:
    request_id: str
    export_id: str
    reason: str
    initiator: str
    created_at: datetime
    due_at: datetime
    status: str = "pending"  # pending | confirmed
    confirmer: Optional[str] = None
    confirmed_at: Optional[datetime] = None


class IncidentService:
    def __init__(
        self,
        audit: AuditLog,
        exports: ExportService,
        retention: RetentionPolicy,
        notifications: NotificationCenter,
    ) -> None:
        self._audit = audit
        self._exports = exports
        self._retention = retention
        self._notifications = notifications
        self._incidents: dict[str, Incident] = {}
        self._deletions: dict[str, DeletionRequest] = {}
        self._lock = threading.RLock()

    def report(
        self,
        kind: str,
        patient_id: str,
        reporter: str,
        description: str = "",
        export_ids=(),
        now: Optional[datetime] = None,
    ) -> Incident:
        """登记事件并冻结相关审计条目（证据保全）。"""
        now = now or utcnow()
        export_ids = list(export_ids)

        def related(entry) -> bool:
            if entry.details.get("patient_id") == patient_id:
                return True
            if export_ids:
                blob = json.dumps(entry.details, ensure_ascii=False, default=str)
                return any(eid in blob for eid in export_ids)
            return False

        frozen = self._audit.freeze_where(related)
        incident = Incident(
            incident_id=new_id("inc"),
            kind=kind,
            patient_id=patient_id,
            reporter=reporter,
            description=description,
            related_export_ids=export_ids,
            created_at=now,
            frozen_audit_seqs=frozen,
        )
        with self._lock:
            self._incidents[incident.incident_id] = incident
        self._audit.append(
            reporter,
            "incident.reported",
            {
                "patient_id": patient_id,
                "incident_id": incident.incident_id,
                "kind": kind,
                "export_ids": export_ids,
                "frozen_audit_seqs": frozen,
            },
        )
        self._notifications.send(
            kind="incident",
            audience=ROLE_SECURITY,
            message=f"事件 {incident.incident_id}（{kind}）已登记，相关审计已冻结",
            payload={"incident_id": incident.incident_id, "patient_id": patient_id},
            now=now,
        )
        return incident

    def get(self, incident_id: str) -> Incident:
        with self._lock:
            try:
                return self._incidents[incident_id]
            except KeyError:
                raise PrivacyError("incident-not-found") from None

    def trace_same_source(self, export_id: str) -> list[ExportRecord]:
        """从一条导出记录出发，追踪同一来源的全部交付记录。"""
        record = self._exports.get(export_id)
        if record is None:
            raise PrivacyError("export-not-found")
        return self._exports.trace_source(record.source_id)

    def initiate_deletion(
        self,
        export_id: str,
        reason: str,
        initiator: str,
        now: Optional[datetime] = None,
    ) -> DeletionRequest:
        """按保留政策对交付副本发起删除确认（双人流程的第一步）。"""
        now = now or utcnow()
        record = self._exports.get(export_id)
        if record is None:
            raise PrivacyError("export-not-found")
        with self._lock:
            if record.delivery_status != "delivered":
                raise DeletionStateError("deletion-already-initiated")
            request = DeletionRequest(
                request_id=new_id("del"),
                export_id=export_id,
                reason=reason,
                initiator=initiator,
                created_at=now,
                due_at=self._retention.due_at(reason, now),
            )
            self._deletions[request.request_id] = request
            record.delivery_status = "deletion_pending"
        self._audit.append(
            initiator,
            "deletion.initiated",
            {
                "patient_id": record.patient_id,
                "export_id": export_id,
                "request_id": request.request_id,
                "reason": reason,
                "due_at": request.due_at.isoformat(),
            },
        )
        return request

    def confirm_deletion(
        self,
        request_id: str,
        confirmer: str,
        now: Optional[datetime] = None,
    ) -> DeletionRequest:
        """第二人确认删除：确认人必须不同于发起人。"""
        now = now or utcnow()
        with self._lock:
            request = self._deletions.get(request_id)
            if request is None:
                raise DeletionStateError("deletion-request-not-found")
            if request.status != "pending":
                raise DeletionStateError("deletion-already-confirmed")
            if confirmer == request.initiator:
                raise DeletionStateError("deletion-requires-second-confirmer")
            request.status = "confirmed"
            request.confirmer = confirmer
            request.confirmed_at = now
            record = self._exports.get(request.export_id)
            if record is not None:
                record.delivery_status = "deletion_confirmed"
        self._audit.append(
            confirmer,
            "deletion.confirmed",
            {
                "export_id": request.export_id,
                "request_id": request_id,
                "initiator": request.initiator,
            },
        )
        return request
