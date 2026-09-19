"""用途与权限策略引擎：角色矩阵 × 业务目的 × 患者关系 × 最小字段。

策略全部以数据声明，安全部门可按矩阵逐格模拟；判定函数是纯函数，
便于在单元测试中穷举越权、过期缓存、重复导出等场景。
"""

from dataclasses import dataclass, field

# ---- 角色 → 允许的业务目的 ----------------------------------------------

ROLE_MATRIX = {
    "physician":      {"treatment", "emergency"},
    "nurse":          {"treatment", "emergency"},
    "anesthetist":    {"treatment", "emergency"},
    "resident":       {"treatment", "teaching"},
    "intern":         {"teaching"},                 # 实习人员：仅教学且须同意+脱敏
    "researcher":     {"research"},
    "medical_student":{"teaching"},
    "qa_officer":     {"quality"},
    "admin":          set(),                        # 管理员不授予业务访问权
    "security":       {"security_investigation"},
}

# ---- 业务目的 → 允许字段、是否要求同意、是否要求脱敏 -----------------------

PURPOSE_RULES = {
    "treatment": {
        "fields": {"demographics", "diagnosis", "medication", "orders", "notes", "obstetric"},
        "consent_required": False,
        "redaction_required": False,
        "export_allowed": False,
        "relation_required": True,
    },
    "emergency": {
        "fields": {"demographics", "diagnosis", "medication", "orders", "notes", "obstetric", "allergies"},
        "consent_required": False,
        "redaction_required": False,
        "export_allowed": False,
        "relation_required": False,   # break-glass 时可无既有关系
    },
    "teaching": {
        "fields": {"diagnosis", "obstetric", "procedure", "media"},
        "consent_required": True,
        "redaction_required": True,
        "export_allowed": True,
        "relation_required": False,
    },
    "research": {
        "fields": {"demographics", "diagnosis", "obstetric", "procedure", "lab"},
        "consent_required": True,
        "redaction_required": True,
        "export_allowed": True,
        "relation_required": False,
    },
    "quality": {
        "fields": {"demographics", "diagnosis", "orders", "notes"},
        "consent_required": False,
        "redaction_required": True,
        "export_allowed": False,
        "relation_required": False,
    },
    "security_investigation": {
        "fields": {"access_log", "export_log", "consent_log"},
        "consent_required": False,
        "redaction_required": False,
        "export_allowed": True,
        "relation_required": False,
    },
}

# 即便目的允许，以下字段也绝不允许未经患者关系出现在普通访问里。
IDENTITY_FIELDS = frozenset({"demographics"})


class PolicyError(PermissionError):
    """策略拒绝，code 给出机器可读的拒绝原因。"""

    def __init__(self, code: str, message: str, details: dict = None):
        super().__init__(message)
        self.code = code
        self.details = details or {}


@dataclass
class AccessRequest:
    actor_id: str
    role: str
    patient_id: str
    purpose: str
    fields: frozenset
    relation: str = "none"          # attending|team|none
    cache_token: str = None         # 携带缓存令牌表示走缓存应答
    cache_issued_at: object = None


@dataclass
class ConsentView:
    consent_id: str
    patient_id: str
    purposes: frozenset
    version: str
    valid_from: object
    valid_until: object
    revoked: bool = False
    revoked_at: object = None
    scope_fields: frozenset = None
    redaction: str = "full"         # full | deidentified


class PolicyEngine:
    def __init__(self, clock):
        self.clock = clock

    # ---- 访问判定 ---------------------------------------------------------

    def check_access(self, req: AccessRequest, consent: ConsentView = None,
                     emergency_grant: dict = None):
        now = self.clock.now()
        rule = PURPOSE_RULES.get(req.purpose)
        allowed_purposes = ROLE_MATRIX.get(req.role)
        if allowed_purposes is None:
            raise PolicyError("unknown-role", f"未知角色 {req.role}")
        if req.purpose not in allowed_purposes:
            raise PolicyError(
                "purpose-denied",
                f"角色 {req.role} 不允许以 {req.purpose} 为目的访问",
                {"role": req.role, "purpose": req.purpose},
            )
        if rule is None:
            raise PolicyError("unknown-purpose", f"未知业务目的 {req.purpose}")

        # 缓存应答必须在服务端重新校验有效期与撤回状态，过期缓存一律拒绝。
        if req.cache_token:
            issued = req.cache_issued_at
            if issued is None:
                raise PolicyError("cache-undated", "缓存令牌缺少签发时间")
            from .encoding import utc_from

            age = (now - utc_from(issued)).total_seconds()
            if age > 60:  # 敏感访问缓存最长 60 秒
                raise PolicyError(
                    "cache-expired",
                    f"缓存已过期 {age - 60:.0f} 秒，必须重新发起授权访问",
                    {"age_seconds": age},
                )

        # 字段最小化：请求字段必须被目的规则覆盖。
        overreach = req.fields - rule["fields"]
        if overreach:
            raise PolicyError(
                "field-overreach",
                f"字段超出最小必要范围：{sorted(overreach)}",
                {"allowed": sorted(rule["fields"]), "rejected": sorted(overreach)},
            )

        # 患者关系。
        if rule["relation_required"] and req.relation == "none":
            if emergency_grant is None:
                raise PolicyError(
                    "no-relation",
                    "缺少与患者的诊疗关系，拒绝访问；紧急情况请走 break-glass",
                )

        # 同意（教学/科研/传播）。
        if rule["consent_required"]:
            self._check_consent(req, consent, now)

        if rule["redaction_required"]:
            if consent is not None and consent.redaction != "deidentified" and "media" in req.fields:
                raise PolicyError(
                    "redaction-required",
                    "教学/科研影像必须脱敏（去标识化）后使用",
                )

        return {
            "decision": "allow",
            "purpose": req.purpose,
            "fields": sorted(req.fields),
            "relation": req.relation,
            "consent_id": consent.consent_id if consent else None,
        }

    def _check_consent(self, req: AccessRequest, consent: ConsentView, now):
        if consent is None:
            raise PolicyError(
                "consent-missing",
                f"{req.purpose} 用途必须绑定患者知情同意的具体版本",
            )
        if consent.patient_id != req.patient_id:
            raise PolicyError("consent-mismatch", "同意书不属于该患者")
        if req.purpose not in consent.purposes:
            raise PolicyError(
                "consent-purpose-mismatch",
                f"同意版本 {consent.version} 未授权 {req.purpose} 用途",
                {"version": consent.version, "purposes": sorted(consent.purposes)},
            )
        if consent.revoked:
            raise PolicyError(
                "consent-revoked",
                f"同意已于 {consent.revoked_at} 被撤回",
                {"consent_id": consent.consent_id},
            )
        if not (consent.valid_from <= now <= consent.valid_until):
            raise PolicyError(
                "consent-expired",
                f"同意版本 {consent.version} 不在有效期内",
                {"valid_from": str(consent.valid_from), "valid_until": str(consent.valid_until)},
            )
        if consent.scope_fields is not None:
            outside = req.fields - consent.scope_fields
            if outside:
                raise PolicyError(
                    "consent-scope-exceeded",
                    f"请求字段超出同意范围：{sorted(outside)}",
                )

    # ---- 导出判定 ---------------------------------------------------------

    def check_export(self, role: str, purpose: str, fields: frozenset):
        rule = PURPOSE_RULES[purpose]
        if not rule["export_allowed"]:
            raise PolicyError(
                "export-denied",
                f"{purpose} 用途不允许导出，仅可在受控界面查看",
                {"purpose": purpose},
            )
        overreach = fields - rule["fields"]
        if overreach:
            raise PolicyError("field-overreach", f"导出字段越界：{sorted(overreach)}")
        return True
