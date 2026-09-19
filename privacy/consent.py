"""患者知情同意登记：具体版本、有效期限、用途与字段范围、撤回。

撤回通过监听器广播（策略缓存失效、未完成导出在提交时被阻断），
并暴露锁给门面做“撤回 vs 完成导出”的串行化。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional

from .models import CONSENT_PURPOSES, PrivacyError, new_id, utcnow


@dataclass
class Consent:
    consent_id: str
    patient_id: str
    version: str  # 知情同意书的具体版本
    purposes: frozenset[str]
    fields: frozenset[str]
    valid_from: datetime
    valid_until: datetime
    status: str = "active"  # active | withdrawn
    withdrawn_at: Optional[datetime] = None

    def in_validity(self, now: datetime) -> bool:
        return self.valid_from <= now < self.valid_until

    def is_active(self, now: datetime) -> bool:
        return self.status == "active" and self.in_validity(now)


class ConsentRegistry:
    """线程安全的同意登记处。"""

    def __init__(self) -> None:
        self._consents: dict[str, Consent] = {}
        self._listeners: list[Callable[[Consent], None]] = []
        # 门面用同一把锁把“撤回”与“完成导出前的复核”串行化
        self.lock = threading.RLock()

    def add_listener(self, listener: Callable[[Consent], None]) -> None:
        self._listeners.append(listener)

    def register(
        self,
        patient_id: str,
        version: str,
        purposes,
        fields,
        valid_from: datetime,
        valid_until: datetime,
    ) -> Consent:
        purposes = frozenset(purposes)
        fields = frozenset(fields)
        if not version or not version.strip():
            raise PrivacyError("consent-version-required")
        if not purposes or not purposes <= CONSENT_PURPOSES:
            raise PrivacyError("consent-purpose-invalid")
        if valid_until <= valid_from:
            raise PrivacyError("consent-validity-invalid")
        consent = Consent(
            consent_id=new_id("cst"),
            patient_id=patient_id,
            version=version.strip(),
            purposes=purposes,
            fields=fields,
            valid_from=valid_from,
            valid_until=valid_until,
        )
        with self.lock:
            self._consents[consent.consent_id] = consent
        return consent

    def get(self, consent_id: str) -> Consent:
        with self.lock:
            try:
                return self._consents[consent_id]
            except KeyError:
                raise PrivacyError("consent-not-found") from None

    def withdraw(
        self,
        consent_id: str,
        now: Optional[datetime] = None,
    ) -> Consent:
        """撤回指定版本的同意；幂等，重复撤回返回原状态。"""
        now = now or utcnow()
        with self.lock:
            consent = self.get(consent_id)
            if consent.status == "withdrawn":
                return consent
            consent.status = "withdrawn"
            consent.withdrawn_at = now
        for listener in self._listeners:
            listener(consent)
        return consent

    def withdraw_for_patient(
        self,
        patient_id: str,
        purposes=None,
        now: Optional[datetime] = None,
    ) -> list[Consent]:
        """按患者（可选按用途）撤回全部有效同意。"""
        now = now or utcnow()
        with self.lock:
            targets = [
                c
                for c in self._consents.values()
                if c.patient_id == patient_id
                and c.status == "active"
                and (purposes is None or c.purposes & frozenset(purposes))
            ]
        return [self.withdraw(c.consent_id, now=now) for c in targets]

    def is_active(self, consent_id: str, now: Optional[datetime] = None) -> bool:
        now = now or utcnow()
        with self.lock:
            try:
                return self._consents[consent_id].is_active(now)
            except KeyError:
                return False

    def match(
        self,
        patient_id: str,
        purpose: str,
        version: Optional[str],
        fields,
        now: Optional[datetime] = None,
    ) -> tuple[Optional[Consent], str]:
        """按患者/用途/版本/字段/期限匹配同意，返回 (同意或 None, 原因码)。"""
        now = now or utcnow()
        with self.lock:
            candidates = [c for c in self._consents.values() if c.patient_id == patient_id]
        if version is not None:
            candidates = [c for c in candidates if c.version == version]
            if not candidates:
                return None, "consent-version-mismatch"
        relevant = [c for c in candidates if purpose in c.purposes]
        if not relevant:
            return None, "consent-purpose-not-covered"
        active = [c for c in relevant if c.is_active(now)]
        if not active:
            return None, "consent-expired-or-withdrawn"
        needed = frozenset(fields)
        covering = [c for c in active if needed <= c.fields]
        if not covering:
            return None, "consent-scope-missing-fields"
        return covering[0], "allowed"
