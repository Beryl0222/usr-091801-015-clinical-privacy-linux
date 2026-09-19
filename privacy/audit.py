"""仅追加、哈希链式、可冻结的审计日志。

- 每条记录携带前一条的哈希，任何篡改都会破坏 verify_chain；
- 不提供任何删除入口：erase 永远拒绝并把尝试本身记入日志，
  因此包括管理员在内的任何角色都无法抹除自己的操作；
- freeze_where 把命中条目标记为冻结（证据保全），供事件调查使用。
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional

from .models import utcnow

GENESIS_HASH = "0" * 64


def _canonical(value):
    """把细节字段规范化为可 JSON 序列化且顺序稳定的结构。"""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, dict):
        return {k: _canonical(value[k]) for k in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_canonical(v) for v in value]
    return value


def _entry_hash(seq: int, ts: datetime, actor: str, action: str, details: dict, prev_hash: str) -> str:
    payload = {
        "seq": seq,
        "ts": ts.isoformat(),
        "actor": actor,
        "action": action,
        "details": _canonical(details),
        "prev_hash": prev_hash,
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class AuditEntry:
    seq: int
    ts: datetime
    actor: str
    action: str
    details: dict
    prev_hash: str
    hash: str
    frozen: bool = False  # 事件冻结的证据标记


class AuditLog:
    """线程安全的仅追加审计日志。"""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []
        self._lock = threading.RLock()

    def append(
        self,
        actor: str,
        action: str,
        details: Optional[dict] = None,
        now: Optional[datetime] = None,
    ) -> AuditEntry:
        ts = now or utcnow()
        details = details or {}
        with self._lock:
            seq = len(self._entries) + 1
            prev_hash = self._entries[-1].hash if self._entries else GENESIS_HASH
            entry = AuditEntry(
                seq=seq,
                ts=ts,
                actor=actor,
                action=action,
                details=_canonical(details),
                prev_hash=prev_hash,
                hash=_entry_hash(seq, ts, actor, action, details, prev_hash),
            )
            self._entries.append(entry)
            return entry

    def entries(self) -> list[AuditEntry]:
        with self._lock:
            return list(self._entries)

    def find(self, action: Optional[str] = None, actor: Optional[str] = None) -> list[AuditEntry]:
        return [
            e
            for e in self.entries()
            if (action is None or e.action == action) and (actor is None or e.actor == actor)
        ]

    def freeze_where(self, predicate: Callable[[AuditEntry], bool]) -> list[int]:
        """把命中条目标记为冻结，返回被冻结的序号。"""
        with self._lock:
            frozen = []
            for entry in self._entries:
                if not entry.frozen and predicate(entry):
                    entry.frozen = True
                    frozen.append(entry.seq)
            return frozen

    def frozen_entries(self) -> list[AuditEntry]:
        return [e for e in self.entries() if e.frozen]

    def verify_chain(self) -> bool:
        """重放整条哈希链，确认没有条目被篡改或抽走。"""
        with self._lock:
            prev_hash = GENESIS_HASH
            for expected_seq, entry in enumerate(self._entries, start=1):
                if entry.seq != expected_seq or entry.prev_hash != prev_hash:
                    return False
                if entry.hash != _entry_hash(
                    entry.seq, entry.ts, entry.actor, entry.action, entry.details, entry.prev_hash
                ):
                    return False
                prev_hash = entry.hash
            return True

    def erase(self, actor: str, seq: int) -> bool:
        """删除请求永远被拒绝，并把尝试本身记入日志。

        这是“任何管理员都不能抹除自己的操作”的唯一入口：没有后门。
        """
        self.append(
            actor,
            "audit.erase.denied",
            {"target_seq": seq, "reason": "audit-log-is-append-only"},
        )
        return False
