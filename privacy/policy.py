"""用途管控策略引擎与带 TTL 的决策缓存。

评估顺序固定：角色矩阵 -> 字段上限 -> 治疗关系 -> break-glass -> 知情同意。
只有放行决策会被缓存；缓存有过期时间，过期条目一律不采信，
同意撤回时还会按患者主动失效，双保险。
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta
from typing import Optional

from .audit import AuditLog
from .breakglass import BreakGlassService
from .consent import ConsentRegistry
from .models import (
    CONSENT_PURPOSES,
    PURPOSE_CLINICAL,
    PURPOSE_EMERGENCY,
    ROLE_PURPOSES,
    TREATMENT_RELATIONSHIPS,
    AccessRequest,
    Decision,
    field_ceiling,
    new_id,
    utcnow,
)

DEFAULT_CACHE_TTL_SECONDS = 60.0


def _cache_key(req: AccessRequest) -> tuple:
    return (
        req.staff_id,
        req.role,
        req.patient_id,
        req.relationship,
        req.purpose,
        tuple(sorted(req.fields)),
        req.consent_version,
        req.break_glass_id,
    )


class DecisionCache:
    """放行决策的短 TTL 缓存；过期即弃，绝不延长。"""

    def __init__(self, ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._items: dict[tuple, tuple[Decision, datetime, str]] = {}
        self._lock = threading.RLock()

    def get(self, req: AccessRequest, now: Optional[datetime] = None) -> Optional[Decision]:
        now = now or utcnow()
        key = _cache_key(req)
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            decision, expires_at, _patient_id = item
            if now >= expires_at:
                # 过期缓存立即丢弃，调用方必须重新评估
                del self._items[key]
                return None
            return decision

    def put(
        self,
        req: AccessRequest,
        decision: Decision,
        now: Optional[datetime] = None,
        ttl_seconds: Optional[float] = None,
    ) -> None:
        now = now or utcnow()
        ttl = self._ttl if ttl_seconds is None else ttl_seconds
        with self._lock:
            self._items[_cache_key(req)] = (
                decision,
                now + timedelta(seconds=ttl),
                req.patient_id,
            )

    def invalidate_patient(self, patient_id: str) -> int:
        """同意撤回等事件触发：按患者失效全部缓存决策。"""
        with self._lock:
            keys = [k for k, v in self._items.items() if v[2] == patient_id]
            for key in keys:
                del self._items[key]
            return len(keys)


class PolicyEngine:
    def __init__(
        self,
        consents: ConsentRegistry,
        breakglass: BreakGlassService,
        audit: AuditLog,
        cache: Optional[DecisionCache] = None,
    ) -> None:
        self._consents = consents
        self._breakglass = breakglass
        self._audit = audit
        self.cache = cache or DecisionCache()

    def evaluate(self, req: AccessRequest, now: Optional[datetime] = None) -> Decision:
        now = now or utcnow()
        cached = self.cache.get(req, now)
        if cached is not None:
            self._record(req, cached, now, cached_hit=True)
            return cached
        decision = self._evaluate_uncached(req, now)
        self._record(req, decision, now, cached_hit=False)
        if decision.allowed:
            self.cache.put(req, decision, now)
        return decision

    def _record(self, req: AccessRequest, decision: Decision, now: datetime, cached_hit: bool) -> None:
        self._audit.append(
            req.staff_id,
            "access.evaluated",
            {
                "patient_id": req.patient_id,
                "role": req.role,
                "relationship": req.relationship,
                "purpose": req.purpose,
                "fields": sorted(req.fields),
                "consent_version": req.consent_version,
                "break_glass_id": req.break_glass_id,
                "allowed": decision.allowed,
                "reason": decision.reason,
                "decision_id": decision.decision_id,
                "cached": cached_hit,
            },
            now=now,
        )

    def _evaluate_uncached(self, req: AccessRequest, now: datetime) -> Decision:
        def deny(reason: str) -> Decision:
            return Decision(allowed=False, reason=reason, decision_id=new_id("dec"))

        # 1. 角色矩阵：该角色是否允许此用途
        if req.purpose not in ROLE_PURPOSES.get(req.role, frozenset()):
            return deny("purpose-not-in-role-matrix")

        # 2. 最小字段范围必须落在 (角色, 用途) 上限之内
        if not req.fields or not frozenset(req.fields) <= field_ceiling(req.role, req.purpose):
            return deny("field-scope-exceeds-role-ceiling")

        # 3. 诊疗用途要求存在治疗关系
        if req.purpose == PURPOSE_CLINICAL and req.relationship not in TREATMENT_RELATIONSHIPS:
            return deny("clinical-relationship-required")

        # 4. 紧急用途要求有效 break-glass 授权，且人、患匹配
        if req.purpose == PURPOSE_EMERGENCY:
            if not req.break_glass_id:
                return deny("break-glass-required")
            grant = self._breakglass.get(req.break_glass_id)
            if grant is None:
                return deny("break-glass-required")
            if not grant.is_active(now):
                return deny("break-glass-expired")
            if grant.staff_id != req.staff_id or grant.patient_id != req.patient_id:
                return deny("break-glass-scope-mismatch")
            return Decision(
                allowed=True,
                reason="allowed",
                decision_id=new_id("dec"),
                granted_fields=frozenset(req.fields),
                break_glass_id=grant.grant_id,
            )

        # 5. 教学/科研/传播用途必须绑定具体版本且在有效期内的知情同意
        if req.purpose in CONSENT_PURPOSES:
            if not req.consent_version:
                return deny("consent-required")
            consent, reason = self._consents.match(
                req.patient_id, req.purpose, req.consent_version, req.fields, now
            )
            if consent is None:
                return deny(reason)
            return Decision(
                allowed=True,
                reason="allowed",
                decision_id=new_id("dec"),
                granted_fields=frozenset(req.fields),
                consent_id=consent.consent_id,
            )

        return Decision(
            allowed=True,
            reason="allowed",
            decision_id=new_id("dec"),
            granted_fields=frozenset(req.fields),
        )
