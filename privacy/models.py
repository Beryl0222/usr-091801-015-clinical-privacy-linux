"""领域常量、角色矩阵、访问请求/决策模型与错误类型。

矩阵说明：
- 每个角色只允许特定用途（ROLE_PURPOSES），越出即拒绝；
- 每个 (角色, 用途) 组合有字段上限（_FIELD_CEILINGS），请求的最小字段范围
  必须落在上限之内，超出即拒绝；
- 诊疗用途要求存在治疗关系；教学/科研/传播用途必须绑定知情同意；
- 紧急用途只接受有效的 break-glass 授权，字段上限放宽但全程留痕复核。
"""

from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def utcnow() -> datetime:
    """返回带时区的当前时间。"""
    return datetime.now(timezone.utc)


_id_counter = itertools.count(1)


def new_id(prefix: str) -> str:
    """生成进程内唯一、可读的标识。"""
    return f"{prefix}-{next(_id_counter):06d}"


# --- 角色 ---
ROLE_PHYSICIAN = "physician"
ROLE_NURSE = "nurse"
ROLE_INTERN = "intern"
ROLE_RESEARCHER = "researcher"
ROLE_EDUCATOR = "educator"
ROLE_ADMIN = "admin"
ROLE_SECURITY = "security_officer"

ROLES = frozenset(
    {
        ROLE_PHYSICIAN,
        ROLE_NURSE,
        ROLE_INTERN,
        ROLE_RESEARCHER,
        ROLE_EDUCATOR,
        ROLE_ADMIN,
        ROLE_SECURITY,
    }
)

# --- 业务目的 ---
PURPOSE_CLINICAL = "clinical"
PURPOSE_EMERGENCY = "emergency"
PURPOSE_TEACHING = "teaching"
PURPOSE_RESEARCH = "research"
PURPOSE_DISSEMINATION = "dissemination"

PURPOSES = frozenset(
    {
        PURPOSE_CLINICAL,
        PURPOSE_EMERGENCY,
        PURPOSE_TEACHING,
        PURPOSE_RESEARCH,
        PURPOSE_DISSEMINATION,
    }
)

# 必须绑定患者知情同意（具体版本与期限）的用途
CONSENT_PURPOSES = frozenset(
    {PURPOSE_TEACHING, PURPOSE_RESEARCH, PURPOSE_DISSEMINATION}
)

# --- 敏感记录字段 ---
FIELD_DEMOGRAPHICS = "demographics"
FIELD_CONTACTS = "contacts"
FIELD_DIAGNOSIS = "diagnosis"
FIELD_LABS = "labs"
FIELD_MEDICATIONS = "medications"
FIELD_OBSTETRIC_MEDIA = "obstetric_media"  # 产科影像，最高敏感级

ALL_FIELDS = frozenset(
    {
        FIELD_DEMOGRAPHICS,
        FIELD_CONTACTS,
        FIELD_DIAGNOSIS,
        FIELD_LABS,
        FIELD_MEDICATIONS,
        FIELD_OBSTETRIC_MEDIA,
    }
)

# --- 患者关系 ---
REL_ATTENDING = "attending"  # 主治
REL_ASSIGNED = "assigned"  # 分管
REL_CONSULTING = "consulting"  # 会诊
REL_NONE = "none"

TREATMENT_RELATIONSHIPS = frozenset({REL_ATTENDING, REL_ASSIGNED, REL_CONSULTING})

# --- 角色矩阵：角色 -> 可用用途 ---
ROLE_PURPOSES: dict[str, frozenset[str]] = {
    ROLE_PHYSICIAN: frozenset(
        {
            PURPOSE_CLINICAL,
            PURPOSE_EMERGENCY,
            PURPOSE_TEACHING,
            PURPOSE_RESEARCH,
            PURPOSE_DISSEMINATION,
        }
    ),
    ROLE_NURSE: frozenset({PURPOSE_CLINICAL, PURPOSE_EMERGENCY, PURPOSE_TEACHING}),
    # 实习人员只允许诊疗与紧急用途，且诊疗字段受限（不含任何影像）
    ROLE_INTERN: frozenset({PURPOSE_CLINICAL, PURPOSE_EMERGENCY}),
    ROLE_RESEARCHER: frozenset({PURPOSE_RESEARCH}),
    ROLE_EDUCATOR: frozenset({PURPOSE_TEACHING}),
    # 管理员与安全官不接触病历内容
    ROLE_ADMIN: frozenset(),
    ROLE_SECURITY: frozenset(),
}

# --- 字段上限：(角色, 用途) -> 允许的最大字段集合 ---
_FIELD_CEILINGS: dict[tuple[str, str], frozenset[str]] = {
    (ROLE_PHYSICIAN, PURPOSE_CLINICAL): ALL_FIELDS,
    (ROLE_NURSE, PURPOSE_CLINICAL): frozenset(
        {FIELD_DEMOGRAPHICS, FIELD_DIAGNOSIS, FIELD_MEDICATIONS}
    ),
    (ROLE_INTERN, PURPOSE_CLINICAL): frozenset(
        {FIELD_DEMOGRAPHICS, FIELD_DIAGNOSIS}
    ),
    (ROLE_PHYSICIAN, PURPOSE_TEACHING): frozenset(
        {FIELD_DIAGNOSIS, FIELD_LABS, FIELD_OBSTETRIC_MEDIA}
    ),
    (ROLE_EDUCATOR, PURPOSE_TEACHING): frozenset(
        {FIELD_DIAGNOSIS, FIELD_LABS, FIELD_OBSTETRIC_MEDIA}
    ),
    (ROLE_NURSE, PURPOSE_TEACHING): frozenset({FIELD_DIAGNOSIS}),
    (ROLE_PHYSICIAN, PURPOSE_RESEARCH): frozenset({FIELD_DIAGNOSIS, FIELD_LABS}),
    (ROLE_RESEARCHER, PURPOSE_RESEARCH): frozenset({FIELD_DIAGNOSIS, FIELD_LABS}),
    (ROLE_PHYSICIAN, PURPOSE_DISSEMINATION): frozenset({FIELD_OBSTETRIC_MEDIA}),
    # 紧急救治放宽到全字段，但要求有效 break-glass 授权并进入事后复核
    ("*", PURPOSE_EMERGENCY): ALL_FIELDS,
}


def field_ceiling(role: str, purpose: str) -> frozenset[str]:
    """返回角色在某用途下允许的最大字段集合。"""
    ceiling = _FIELD_CEILINGS.get((role, purpose))
    if ceiling is None:
        ceiling = _FIELD_CEILINGS.get(("*", purpose), frozenset())
    return ceiling


# --- 错误类型（reason 为稳定字符串，供客户端与测试断言） ---
class PrivacyError(Exception):
    """领域错误基类。"""


class PolicyDenied(PrivacyError):
    """策略拒绝；reason 为机器可读的原因码。"""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class ConsentWithdrawn(PrivacyError):
    """知情同意已撤回，未完成的导出被阻断。"""


class DuplicateExport(PrivacyError):
    """同一操作者对同一患者、同一文件哈希、同一交付对象的重复导出。"""


class ExportSessionError(PrivacyError):
    """导出会话状态非法（不存在、已完成、已过期）。"""


class WatermarkInvalid(PrivacyError):
    """水印无法通过验证（签名不符、哈希不符或密钥未知）。"""


class BreakGlassError(PrivacyError):
    """break-glass 授权请求非法（缺理由、超时时长越界等）。"""


class DeletionStateError(PrivacyError):
    """删除确认流程状态非法（重复确认、发起人与确认人相同等）。"""


# --- 访问请求与决策 ---
@dataclass(frozen=True)
class AccessRequest:
    """每次查看敏感记录都必须携带的三要素及可选授权引用。"""

    staff_id: str
    role: str
    patient_id: str
    relationship: str  # 患者关系
    purpose: str  # 业务目的
    fields: frozenset[str]  # 最小字段范围
    consent_version: Optional[str] = None  # 知情同意具体版本
    break_glass_id: Optional[str] = None  # 紧急授权编号


@dataclass(frozen=True)
class Decision:
    """策略评估结果；decision_id 会进入导出授权链。"""

    allowed: bool
    reason: str
    decision_id: str
    granted_fields: frozenset[str] = frozenset()
    consent_id: Optional[str] = None
    break_glass_id: Optional[str] = None


# --- 主动通知 ---
@dataclass(frozen=True)
class Notification:
    notification_id: str
    kind: str
    audience: str
    message: str
    created_at: datetime
    payload: dict = field(default_factory=dict)


class NotificationCenter:
    """主动通知发件箱，由安全部门与患者门户消费。"""

    def __init__(self) -> None:
        self._items: list[Notification] = []
        self._lock = threading.Lock()

    def send(
        self,
        kind: str,
        audience: str,
        message: str,
        payload: Optional[dict] = None,
        now: Optional[datetime] = None,
    ) -> Notification:
        note = Notification(
            notification_id=new_id("ntf"),
            kind=kind,
            audience=audience,
            message=message,
            created_at=now or utcnow(),
            payload=payload or {},
        )
        with self._lock:
            self._items.append(note)
        return note

    def list(self, audience: Optional[str] = None) -> list[Notification]:
        with self._lock:
            items = list(self._items)
        if audience is None:
            return items
        return [n for n in items if n.audience == audience]
