"""隐私用途管控编排服务：把策略、同意、导出、紧急授权、水印、审计、
事件与保留删除串成一条贯穿诊疗流程的授权链。

所有改变状态的动作都会写入追加式哈希链审计；服务内存只保留哈希、
授权链与交付对象登记，从不保存原始影像内容。
"""

import base64
import threading
from datetime import timedelta

from .audit import AuditLedger, LedgerFrozenError
from .encoding import content_hash, iso, new_id, utc_from
from .policy import AccessRequest, ConsentView, PolicyEngine, PolicyError, ROLE_MATRIX
from .watermark import KeyRing, WatermarkError

# 各用途交付物的保留期限（天）；到期后才能发起删除确认。
RETENTION_DAYS = {
    "teaching": 180,
    "research": 365,
    "quality": 90,
    "security_investigation": 2555,
}

EMERGENCY_TTL_SECONDS = 900
CACHE_TTL_SECONDS = 60


class PrivacyService:
    def __init__(self, clock):
        self.clock = clock
        self.ledger = AuditLedger(clock)
        self.keyring = KeyRing()
        self.keyring.rotate()  # 初始签名密钥
        self.policy = PolicyEngine(clock)
        self._lock = threading.RLock()

        self.users: dict[str, dict] = {}
        self.relations: dict[tuple, str] = {}
        self.consents: dict[str, dict] = {}
        self.exports: dict[str, dict] = {}
        self.emergencies: dict[str, dict] = {}
        self.incidents: dict[str, dict] = {}
        self.purges: dict[str, dict] = {}
        self.notifications: list[dict] = []

        self.ledger.append("system", "service.booted", {"key_id": self.keyring.active_kid})

    # ---- 人员与关系登记 ----------------------------------------------------

    def register_user(self, actor_id: str, role: str, name: str = ""):
        with self._lock:
            self.ledger.append(actor_id, "user.registered", {"role": role, "name": name})
            self.users[actor_id] = {"id": actor_id, "role": role, "name": name}
            return self.users[actor_id]

    def register_relation(self, actor_id: str, patient_id: str, relation: str):
        with self._lock:
            self.ledger.append(
                actor_id, "relation.registered",
                {"patient_id": patient_id, "relation": relation},
            )
            self.relations[(actor_id, patient_id)] = relation
            return {"actor_id": actor_id, "patient_id": patient_id, "relation": relation}

    def _user(self, actor_id: str) -> dict:
        user = self.users.get(actor_id)
        if user is None:
            raise PolicyError("unknown-user", f"未知操作者 {actor_id}")
        return user

    # ---- 知情同意 ----------------------------------------------------------

    def register_consent(self, actor_id: str, patient_id: str, purposes, version: str,
                         valid_from=None, valid_until=None, duration_days: float = 365,
                         fields=None, redaction: str = "deidentified"):
        with self._lock:
            now = self.clock.now()
            vf = now if valid_from is None else utc_from(valid_from)
            vu = vf + timedelta(days=duration_days) if valid_until is None else utc_from(valid_until)
            consent_id = new_id("con")
            view = ConsentView(
                consent_id=consent_id, patient_id=patient_id,
                purposes=frozenset(purposes), version=version,
                valid_from=vf, valid_until=vu,
                scope_fields=frozenset(fields) if fields is not None else None,
                redaction=redaction,
            )
            self.ledger.append(
                actor_id, "consent.registered",
                {
                    "consent_id": consent_id, "patient_id": patient_id,
                    "version": version, "purposes": sorted(purposes),
                    "valid_from": iso(vf), "valid_until": iso(vu),
                    "fields": sorted(fields) if fields else None,
                    "redaction": redaction,
                },
            )
            self.consents[consent_id] = {
                "view": view,
                "registered_by": actor_id,
                "registered_at": iso(now),
            }
            return self.consent_info(consent_id)

    def consent_info(self, consent_id: str) -> dict:
        record = self.consents.get(consent_id)
        if record is None:
            raise PolicyError("consent-not-found", f"未知同意书 {consent_id}")
        v = record["view"]
        return {
            "consent_id": v.consent_id, "patient_id": v.patient_id,
            "version": v.version, "purposes": sorted(v.purposes),
            "valid_from": iso(v.valid_from), "valid_until": iso(v.valid_until),
            "revoked": v.revoked, "revoked_at": iso(v.revoked_at) if v.revoked_at else None,
            "scope_fields": sorted(v.scope_fields) if v.scope_fields else None,
            "redaction": v.redaction,
            "registered_by": record["registered_by"],
        }

    def revoke_consent(self, actor_id: str, consent_id: str, reason: str):
        """撤回立即生效：同意失效，所有尚未完成/已签发的同源导出立即阻断。"""
        with self._lock:
            record = self.consents.get(consent_id)
            if record is None:
                raise PolicyError("consent-not-found", f"未知同意书 {consent_id}")
            view = record["view"]
            if view.revoked:
                return {"consent_id": consent_id, "state": "already-revoked", "blocked": []}
            now = self.clock.now()
            view.revoked = True
            view.revoked_at = now
            self.ledger.append(
                actor_id, "consent.revoked",
                {"consent_id": consent_id, "patient_id": view.patient_id,
                 "reason": reason, "revoked_at": iso(now)},
            )
            blocked = self._block_exports(
                lambda e: e["consent_id"] == consent_id and e["status"] == "active",
                reason="consent-revoked", actor=actor_id,
            )
            return {"consent_id": consent_id, "state": "revoked",
                    "revoked_at": iso(now), "blocked": blocked}

    def _block_exports(self, match, reason: str, actor: str):
        blocked = []
        for export in self.exports.values():
            if match(export):
                export["status"] = "blocked"
                export["blocked_reason"] = reason
                export["blocked_at"] = iso(self.clock.now())
                self.ledger.append(
                    actor, "export.blocked",
                    {"export_id": export["id"], "file_hash": export["file_hash"],
                     "consent_id": export["consent_id"], "reason": reason},
                )
                blocked.append(export["id"])
        return blocked

    # ---- 敏感记录访问 ------------------------------------------------------

    def view_record(self, actor_id: str, patient_id: str, purpose: str, fields,
                    cache_token: str = None, cache_issued_at=None):
        with self._lock:
            user = self._user(actor_id)
            fields = frozenset(fields)
            req = AccessRequest(
                actor_id=actor_id, role=user["role"], patient_id=patient_id,
                purpose=purpose, fields=fields,
                relation=self.relations.get((actor_id, patient_id), "none"),
                cache_token=cache_token, cache_issued_at=cache_issued_at,
            )
            grant = None
            try:
                decision = self.policy.check_access(req, consent=None, emergency_grant=None)
            except PolicyError as denied:
                self.ledger.append(
                    actor_id, "access.denied",
                    {"patient_id": patient_id, "purpose": purpose,
                     "fields": sorted(fields), "reason": denied.code},
                )
                raise
            self.ledger.append(
                actor_id, "access.allowed",
                {"patient_id": patient_id, "purpose": purpose,
                 "fields": decision["fields"], "relation": decision["relation"],
                 "via": "direct"},
            )
            decision["access_id"] = new_id("acc")
            decision["cache_ttl_seconds"] = CACHE_TTL_SECONDS
            return decision

    def view_with_consent(self, actor_id: str, patient_id: str, purpose: str, fields,
                          consent_id: str, cache_token: str = None, cache_issued_at=None):
        with self._lock:
            user = self._user(actor_id)
            record = self.consents.get(consent_id)
            if record is None:
                raise PolicyError("consent-not-found", f"未知同意书 {consent_id}")
            fields = frozenset(fields)
            req = AccessRequest(
                actor_id=actor_id, role=user["role"], patient_id=patient_id,
                purpose=purpose, fields=fields,
                relation=self.relations.get((actor_id, patient_id), "none"),
                cache_token=cache_token, cache_issued_at=cache_issued_at,
            )
            try:
                decision = self.policy.check_access(req, consent=record["view"])
            except PolicyError as denied:
                self.ledger.append(
                    actor_id, "access.denied",
                    {"patient_id": patient_id, "purpose": purpose,
                     "fields": sorted(fields), "consent_id": consent_id,
                     "reason": denied.code},
                )
                raise
            self.ledger.append(
                actor_id, "access.allowed",
                {"patient_id": patient_id, "purpose": purpose,
                 "fields": decision["fields"], "consent_id": consent_id,
                 "consent_version": record["view"].version, "via": "consent"},
            )
            decision["cache_ttl_seconds"] = CACHE_TTL_SECONDS
            return decision

    # ---- Break-glass 紧急救治 ---------------------------------------------

    def start_emergency(self, actor_id: str, patient_id: str, reason: str,
                        ttl_seconds: int = EMERGENCY_TTL_SECONDS):
        with self._lock:
            user = self._user(actor_id)
            if "emergency" not in ROLE_MATRIX[user["role"]]:
                denied = PolicyError("emergency-role-denied",
                                     f"角色 {user['role']} 无权发起 break-glass")
                self.ledger.append(actor_id, "emergency.denied",
                                   {"patient_id": patient_id, "reason": denied.code})
                raise denied
            now = self.clock.now()
            emergency_id = new_id("emg")
            grant = {
                "emergency_id": emergency_id, "patient_id": patient_id,
                "operator": actor_id, "reason": reason,
                "started_at": iso(now), "expires_at": iso(now + timedelta(seconds=ttl_seconds)),
                "ttl_seconds": ttl_seconds, "status": "active",
                "reviewed": False, "review_outcome": None,
            }
            self.ledger.append(actor_id, "emergency.started", dict(grant))
            self.emergencies[emergency_id] = grant
            self._notify(
                channels=["privacy-officer", f"patient:{patient_id}", "qa-officer"],
                template="emergency-started",
                payload={"emergency_id": emergency_id, "patient_id": patient_id,
                         "operator": actor_id, "reason": reason,
                         "expires_at": grant["expires_at"]},
                actor=actor_id,
            )
            return dict(grant)

    def emergency_view(self, actor_id: str, patient_id: str, fields, emergency_id: str,
                       cache_token: str = None, cache_issued_at=None):
        with self._lock:
            user = self._user(actor_id)
            grant = self.emergencies.get(emergency_id)
            if grant is None or grant["patient_id"] != patient_id:
                raise PolicyError("emergency-not-found", "紧急授权不存在或患者不匹配")
            now = self.clock.now()
            if now > utc_from(grant["expires_at"]):
                self.ledger.append(
                    actor_id, "emergency.expired",
                    {"emergency_id": emergency_id, "patient_id": patient_id},
                )
                grant["status"] = "expired"
                raise PolicyError("emergency-expired",
                                  f"紧急授权已于 {grant['expires_at']} 到期")
            if grant["status"] != "active":
                raise PolicyError("emergency-inactive",
                                  f"紧急授权状态为 {grant['status']}")
            fields = frozenset(fields)
            req = AccessRequest(
                actor_id=actor_id, role=user["role"], patient_id=patient_id,
                purpose="emergency", fields=fields, relation="none",
                cache_token=cache_token, cache_issued_at=cache_issued_at,
            )
            try:
                decision = self.policy.check_access(
                    req, consent=None, emergency_grant={"emergency_id": emergency_id})
            except PolicyError as denied:
                self.ledger.append(actor_id, "access.denied",
                                   {"patient_id": patient_id, "purpose": "emergency",
                                    "fields": sorted(fields), "emergency_id": emergency_id,
                                    "reason": denied.code})
                raise
            self.ledger.append(
                actor_id, "access.allowed",
                {"patient_id": patient_id, "purpose": "emergency",
                 "fields": decision["fields"], "emergency_id": emergency_id,
                 "reason": grant["reason"], "via": "break-glass"},
            )
            decision["emergency_id"] = emergency_id
            decision["expires_at"] = grant["expires_at"]
            return decision

    def review_emergency(self, reviewer_id: str, emergency_id: str, approved: bool, note: str = ""):
        with self._lock:
            reviewer = self._user(reviewer_id)
            if reviewer["role"] not in {"qa_officer", "security", "admin"}:
                raise PolicyError("reviewer-denied", "只有质控/安全部门可事后复核紧急授权")
            grant = self.emergencies.get(emergency_id)
            if grant is None:
                raise PolicyError("emergency-not-found", f"未知紧急授权 {emergency_id}")
            grant["reviewed"] = True
            grant["review_outcome"] = "justified" if approved else "flagged"
            grant["review_note"] = note
            grant["reviewed_by"] = reviewer_id
            self.ledger.append(
                reviewer_id, "emergency.reviewed",
                {"emergency_id": emergency_id, "outcome": grant["review_outcome"],
                 "note": note, "operator": grant["operator"]},
            )
            return {"emergency_id": emergency_id, "review_outcome": grant["review_outcome"]}

    def _notify(self, channels, template, payload, actor):
        note = {"id": new_id("ntf"), "channels": channels, "template": template,
                "payload": payload, "created_at": iso(self.clock.now())}
        self.notifications.append(note)
        self.ledger.append(actor, "notification.sent",
                           {"channels": channels, "template": template, **payload})
        return note

    # ---- 教学/科研导出与水印 ----------------------------------------------

    def request_export(self, actor_id: str, patient_id: str, purpose: str, fields,
                       delivered_to: str, content: bytes, consent_id: str = None,
                       emergency_id: str = None):
        """登记一次受控导出。content 只用于计算哈希，函数返回后不保留。"""
        with self._lock:
            user = self._user(actor_id)
            fields = frozenset(fields)
            file_hash = content_hash(content)
            del content  # 明确不保留原始影像内容

            # 重复导出：同源文件 + 同授权 + 同交付对象的活跃登记视为重复。
            dup_key = (file_hash, actor_id, purpose, delivered_to, consent_id or emergency_id)
            duplicate = next((e for e in self.exports.values()
                              if (e["file_hash"], e["operator"], e["purpose"],
                                  e["delivered_to"], e["consent_id"] or e["emergency_id"]) == dup_key
                              and e["status"] == "active"), None)
            if duplicate is not None:
                self.ledger.append(
                    actor_id, "export.duplicate_blocked",
                    {"file_hash": file_hash, "existing_export": duplicate["id"],
                     "purpose": purpose, "delivered_to": delivered_to},
                )
                raise PolicyError(
                    "duplicate-export",
                    "相同内容在同一授权与交付对象下已有活跃导出，禁止重复导出",
                    {"existing_export": duplicate["id"], "file_hash": file_hash},
                )

            self.policy.check_export(user["role"], purpose, fields)

            consent_view = None
            if consent_id is not None:
                record = self.consents.get(consent_id)
                if record is None:
                    raise PolicyError("consent-not-found", f"未知同意书 {consent_id}")
                consent_view = record["view"]
            grant = None
            if emergency_id is not None:
                grant = self.emergencies.get(emergency_id)
                if grant is None or grant["status"] != "active":
                    raise PolicyError("emergency-inactive", "紧急授权不可用于导出登记")

            req = AccessRequest(
                actor_id=actor_id, role=user["role"], patient_id=patient_id,
                purpose=purpose, fields=fields,
                relation=self.relations.get((actor_id, patient_id), "none"),
            )
            try:
                self.policy.check_access(req, consent=consent_view, emergency_grant=grant)
            except PolicyError as denied:
                self.ledger.append(
                    actor_id, "export.denied",
                    {"patient_id": patient_id, "purpose": purpose,
                     "fields": sorted(fields), "file_hash": file_hash,
                     "consent_id": consent_id, "reason": denied.code},
                )
                raise

            export_id = new_id("exp")
            issued_at = iso(self.clock.now())
            claims = {
                "file_hash": file_hash, "export_id": export_id,
                "operator": actor_id, "role": user["role"],
                "patient_id": patient_id, "purpose": purpose,
                "fields": sorted(fields), "delivered_to": delivered_to,
                "issued_at": issued_at,
                "consent_id": consent_id, "consent_version": consent_view.version if consent_view else None,
                "emergency_id": emergency_id,
            }
            token = self.keyring.issue(claims)
            entry = self.ledger.append(
                actor_id, "export.requested",
                {"export_id": export_id, "file_hash": file_hash,
                 "patient_id": patient_id, "purpose": purpose,
                 "fields": sorted(fields), "delivered_to": delivered_to,
                 "consent_id": consent_id, "kid": token["kid"]},
            )
            record_ = {
                "id": export_id, "audit_entry_id": entry.entry_id,
                "file_hash": file_hash, "operator": actor_id, "role": user["role"],
                "patient_id": patient_id, "purpose": purpose,
                "fields": sorted(fields), "delivered_to": delivered_to,
                "consent_id": consent_id, "emergency_id": emergency_id,
                "kid": token["kid"], "status": "active",
                "issued_at": issued_at, "blocked_reason": None, "blocked_at": None,
                "deleted_at": None,
            }
            self.exports[export_id] = record_
            return {"export": self.export_info(export_id), "watermark": token}

    def export_info(self, export_id: str) -> dict:
        export = self.exports.get(export_id)
        if export is None:
            raise PolicyError("export-not-found", f"未知导出 {export_id}")
        return {k: v for k, v in export.items() if k != "audit_entry_id"}

    def verify_watermark(self, actor_id: str, file_hash: str, token: dict):
        """用（可能已轮换的）文件哈希验证水印，并重建完整授权链。"""
        with self._lock:
            result = self.keyring.verify(token, expected_file_hash=file_hash)
            export_id = result["claims"].get("export_id")
            export = self.exports.get(export_id) if export_id else None
            if export is None:
                raise WatermarkError("水印中的导出登记不存在，授权链断裂")
            if export["file_hash"] != file_hash:
                raise WatermarkError("哈希与导出登记不一致")
            chain = self.ledger.chain_for(export["audit_entry_id"])
            later = [
                e.to_dict() for e in self.ledger.all()[len(chain):]
                if e.payload.get("export_id") == export_id
                or e.payload.get("consent_id") == export["consent_id"]
                or e.payload.get("file_hash") == file_hash
            ]
            self.ledger.append(
                actor_id, "watermark.verified",
                {"file_hash": file_hash, "export_id": export_id,
                 "kid": result["kid"], "key_status": result["key_status"]},
            )
            return {
                "verification": result,
                "export": self.export_info(export_id),
                "chain_head": self.ledger.head,
                "authorization_chain": chain + later,
            }

    def trace_source(self, actor_id: str, file_hash: str):
        """追踪同一内容哈希的全部导出与交付对象（含已阻断/已删除）。"""
        with self._lock:
            lineage = [self.export_info(e["id"]) for e in self.exports.values()
                       if e["file_hash"] == file_hash]
            self.ledger.append(
                actor_id, "export.traced",
                {"file_hash": file_hash, "matches": len(lineage)},
            )
            return {"file_hash": file_hash, "lineage": lineage,
                    "count": len(lineage)}

    # ---- 安全事件、审计冻结、保留删除 -------------------------------------

    def report_incident(self, reporter_id: str, kind: str, description: str,
                        file_hash: str = None):
        with self._lock:
            self._user(reporter_id)
            incident_id = new_id("inc")
            linked = []
            if file_hash:
                linked = [e["id"] for e in self.exports.values() if e["file_hash"] == file_hash]
                for export in self.exports.values():
                    if export["file_hash"] == file_hash and export["status"] == "active":
                        export["status"] = "under-investigation"
            incident = {
                "incident_id": incident_id, "kind": kind,
                "description": description, "file_hash": file_hash,
                "reporter": reporter_id, "reported_at": iso(self.clock.now()),
                "linked_exports": linked, "status": "open",
            }
            self.incidents[incident_id] = incident
            self.ledger.append(reporter_id, "incident.reported", dict(incident),
                               allow_frozen=True)
            return dict(incident)

    def freeze_audit(self, actor_id: str, reason: str, token: str):
        with self._lock:
            return self.ledger.request_freeze(actor_id, reason, token)

    def unfreeze_audit(self, actor_id: str, reason: str):
        with self._lock:
            return self.ledger.unfreeze(actor_id, reason)

    def _open_incident_hashes(self) -> set:
        return {i["file_hash"] for i in self.incidents.values()
                if i["status"] == "open" and i["file_hash"]}

    def initiate_purge(self, actor_id: str, file_hash: str, reason: str):
        """按保留政策发起删除确认：须过保留期、无未结事件，且双人确认。"""
        with self._lock:
            self._user(actor_id)
            targets = [e for e in self.exports.values() if e["file_hash"] == file_hash]
            if not targets:
                raise PolicyError("purge-target-missing", "该哈希没有可删除的交付登记")
            if file_hash in self._open_incident_hashes():
                raise PolicyError("legal-hold", "存在未结安全事件，命中法律保全，禁止删除")
            now = self.clock.now()
            retained = []
            for e in targets:
                days = RETENTION_DAYS.get(e["purpose"], 365)
                eligible_after = utc_from(e["issued_at"]) + timedelta(days=days)
                if now < eligible_after:
                    retained.append({"export_id": e["id"], "purpose": e["purpose"],
                                     "eligible_after": iso(eligible_after)})
            if retained:
                raise PolicyError("retention-active", "交付物仍在保留期内",
                                  {"retained": retained})
            purge_id = new_id("prg")
            self.purges[purge_id] = {
                "purge_id": purge_id, "file_hash": file_hash, "reason": reason,
                "confirmations": {actor_id}, "status": "pending",
                "targets": [e["id"] for e in targets],
            }
            self.ledger.append(
                actor_id, "purge.requested",
                {"purge_id": purge_id, "file_hash": file_hash,
                 "targets": [e["id"] for e in targets], "reason": reason},
            )
            return {"purge_id": purge_id, "status": "pending",
                    "required_confirmations": 2,
                    "confirmations": 1, "targets": self.purges[purge_id]["targets"]}

    def confirm_purge(self, actor_id: str, purge_id: str):
        with self._lock:
            self._user(actor_id)
            purge = self.purges.get(purge_id)
            if purge is None:
                raise PolicyError("purge-not-found", f"未知删除请求 {purge_id}")
            if purge["status"] != "pending":
                return {"purge_id": purge_id, "status": purge["status"]}
            if actor_id in purge["confirmations"]:
                raise PolicyError("purge-double-confirm", "同一管理员不能重复确认")
            total = len(purge["confirmations"]) + 1
            if total < 2:
                # 先写审计（冻结时在此被拒），再更新确认集合。
                self.ledger.append(
                    actor_id, "purge.confirmation",
                    {"purge_id": purge_id, "confirmations": total},
                )
                purge["confirmations"].add(actor_id)
                return {"purge_id": purge_id, "status": "pending",
                        "confirmations": total}
            # 双人确认完成：登记交付对象删除证明。系统本就不持有原始内容，
            # 这里确认下游交付副本已销毁；哈希与授权链永久保留作证。
            now = iso(self.clock.now())
            attested = [
                {"export_id": export_id,
                 "delivered_to": self.exports[export_id]["delivered_to"]}
                for export_id in purge["targets"]
            ]
            self.ledger.append(
                actor_id, "incident.purge_confirmed",
                {"purge_id": purge_id, "file_hash": purge["file_hash"],
                 "attestors": sorted(purge["confirmations"] | {actor_id}),
                 "deliveries": attested},
            )
            for export_id in purge["targets"]:
                export = self.exports[export_id]
                export["status"] = "delete-confirmed"
                export["deleted_at"] = now
            purge["confirmations"].add(actor_id)
            purge["status"] = "confirmed"
            purge["confirmed_at"] = now
            return {"purge_id": purge_id, "status": "confirmed",
                    "confirmed_at": now, "deliveries": attested}

    def close_incident(self, actor_id: str, incident_id: str, note: str = ""):
        with self._lock:
            incident = self.incidents.get(incident_id)
            if incident is None:
                raise PolicyError("incident-not-found", f"未知事件 {incident_id}")
            incident["status"] = "closed"
            self.ledger.append(actor_id, "incident.closed",
                               {"incident_id": incident_id, "note": note})
            return {"incident_id": incident_id, "status": "closed"}

    # ---- 密钥轮换 ----------------------------------------------------------

    def rotate_keys(self, actor_id: str):
        with self._lock:
            kid = self.keyring.rotate()
            self.ledger.append(actor_id, "key.rotated", {"kid": kid})
            return {"active_kid": kid, "keys": self.keyring.list_keys()}
    # ---- 只读视图 ----------------------------------------------------------

    def state(self):
        with self._lock:
            return {
                "ledger": self.ledger.verify(),
                "keys": self.keyring.list_keys(),
                "active_emergencies": [g["emergency_id"] for g in self.emergencies.values()
                                       if g["status"] == "active"],
                "open_incidents": [i["incident_id"] for i in self.incidents.values()
                                   if i["status"] == "open"],
            }
