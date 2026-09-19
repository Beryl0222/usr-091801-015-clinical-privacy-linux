"""紧急救治 break-glass：理由必填、短时授权、事后复核、主动通知。"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from .audit import AuditLog
from .models import (
    ROLE_SECURITY,
    BreakGlassError,
    NotificationCenter,
    new_id,
    utcnow,
)

MAX_GRANT_TTL_SECONDS = 30 * 60  # 短时授权上限：30 分钟
REVIEW_OUTCOMES = frozenset({"upheld", "violation"})


@dataclass
class BreakGlassGrant:
    grant_id: str
    staff_id: str
    patient_id: str
    reason: str
    issued_at: datetime
    expires_at: datetime
    status: str = "active"  # active | revoked
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_outcome: Optional[str] = None
    review_notes: str = ""

    def is_active(self, now: datetime) -> bool:
        return self.status == "active" and now < self.expires_at


class BreakGlassService:
    def __init__(self, audit: AuditLog, notifications: NotificationCenter) -> None:
        self._audit = audit
        self._notifications = notifications
        self._grants: dict[str, BreakGlassGrant] = {}
        self._lock = threading.RLock()

    def request(
        self,
        staff_id: str,
        patient_id: str,
        reason: str,
        ttl_seconds: int = 600,
        now: Optional[datetime] = None,
    ) -> BreakGlassGrant:
        """签发短时紧急授权；理由必填，时长受上限约束。"""
        now = now or utcnow()
        if not reason or not reason.strip():
            raise BreakGlassError("break-glass-reason-required")
        if ttl_seconds <= 0 or ttl_seconds > MAX_GRANT_TTL_SECONDS:
            raise BreakGlassError("break-glass-ttl-out-of-range")
        grant = BreakGlassGrant(
            grant_id=new_id("bg"),
            staff_id=staff_id,
            patient_id=patient_id,
            reason=reason.strip(),
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
        with self._lock:
            self._grants[grant.grant_id] = grant
        self._audit.append(
            staff_id,
            "breakglass.granted",
            {
                "patient_id": patient_id,
                "grant_id": grant.grant_id,
                "reason": grant.reason,
                "expires_at": grant.expires_at.isoformat(),
            },
        )
        # 主动通知：安全部门与患者门户
        self._notifications.send(
            kind="break_glass",
            audience=ROLE_SECURITY,
            message=f"紧急授权 {grant.grant_id} 已签发，待事后复核",
            payload={"grant_id": grant.grant_id, "staff_id": staff_id, "patient_id": patient_id},
            now=now,
        )
        self._notifications.send(
            kind="break_glass",
            audience=f"patient:{patient_id}",
            message=f"您的病历因紧急救治被临时调阅（授权 {grant.grant_id}）",
            payload={"grant_id": grant.grant_id, "staff_id": staff_id},
            now=now,
        )
        return grant

    def get(self, grant_id: str) -> Optional[BreakGlassGrant]:
        with self._lock:
            return self._grants.get(grant_id)

    def active_grant(self, grant_id: str, now: Optional[datetime] = None) -> Optional[BreakGlassGrant]:
        now = now or utcnow()
        grant = self.get(grant_id)
        if grant is None or not grant.is_active(now):
            return None
        return grant

    def review(
        self,
        grant_id: str,
        reviewer: str,
        outcome: str,
        notes: str = "",
        now: Optional[datetime] = None,
    ) -> BreakGlassGrant:
        """事后复核：记录复核人、结论与说明。"""
        now = now or utcnow()
        if outcome not in REVIEW_OUTCOMES:
            raise BreakGlassError("break-glass-review-outcome-invalid")
        with self._lock:
            grant = self._grants.get(grant_id)
            if grant is None:
                raise BreakGlassError("break-glass-not-found")
            if grant.reviewed_by is not None:
                raise BreakGlassError("break-glass-already-reviewed")
            grant.reviewed_by = reviewer
            grant.reviewed_at = now
            grant.review_outcome = outcome
            grant.review_notes = notes
        self._audit.append(
            reviewer,
            "breakglass.reviewed",
            {
                "patient_id": grant.patient_id,
                "grant_id": grant.grant_id,
                "outcome": outcome,
                "notes": notes,
            },
        )
        return grant

    def pending_reviews(self, now: Optional[datetime] = None) -> list[BreakGlassGrant]:
        """已过期但尚未复核的授权，即待办复核队列。"""
        now = now or utcnow()
        with self._lock:
            return [
                g
                for g in self._grants.values()
                if g.reviewed_by is None and now >= g.expires_at
            ]
