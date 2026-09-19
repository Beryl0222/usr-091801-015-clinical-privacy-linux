"""追加式哈希链审计台账。

每条记录包含前一条记录的哈希；任何删除、修改或乱序插入都会被 verify() 检出。
冻结需要两名管理员分别授权；冻结期间除安全事件外的追加一律拒绝。
"""

import threading
from dataclasses import dataclass, field

from .encoding import content_hash, iso, new_id, utc_from

GENESIS_HASH = "0" * 64

# 冻结状态下仍然允许记录的安全事件类型（这些事件本身不可被拦截）。
FREEZE_EXEMPT_EVENTS = frozenset(
    {
        "audit.frozen",
        "audit.unfrozen",
        "audit.freeze_failed",
        "incident.reported",
    }
)


class TamperError(RuntimeError):
    """审计链校验失败（缺口、改写、乱序）。"""


class LedgerFrozenError(RuntimeError):
    """台账处于冻结状态且事件类型不允许穿透。"""


@dataclass
class AuditEntry:
    seq: int
    entry_id: str
    timestamp: str
    actor: str
    action: str
    payload: dict
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "id": self.entry_id,
            "ts": self.timestamp,
            "actor": self.actor,
            "action": self.action,
            "payload": self.payload,
            "prev": self.prev_hash,
            "hash": self.entry_hash,
        }


def _hash_entry(seq, entry_id, timestamp, actor, action, payload, prev_hash) -> str:
    return content_hash(
        [seq, entry_id, timestamp, actor, action, payload, prev_hash]
    )


@dataclass
class AuditLedger:
    clock: object
    _entries: list = field(default_factory=list, init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)
    _frozen: bool = field(default=False, init=False, repr=False)
    _freeze_tokens: set = field(default_factory=set, init=False, repr=False)
    _freeze_reason: str = field(default="", init=False, repr=False)

    def append(self, actor: str, action: str, payload: dict = None, allow_frozen: bool = False) -> AuditEntry:
        """追加一条审计。任何人（含管理员）都不能删除或改写已追加的记录。"""
        payload = dict(payload or {})
        with self._lock:
            if self._frozen and not allow_frozen and action not in FREEZE_EXEMPT_EVENTS:
                raise LedgerFrozenError(f"审计台账已冻结，拒绝记录 {action}")
            seq = len(self._entries) + 1
            entry_id = new_id("aud")
            ts = iso(self.clock.now())
            prev_hash = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
            entry_hash = _hash_entry(seq, entry_id, ts, actor, action, payload, prev_hash)
            entry = AuditEntry(seq, entry_id, ts, actor, action, payload, prev_hash, entry_hash)
            self._entries.append(entry)
            return entry

    def all(self) -> list:
        with self._lock:
            return list(self._entries)

    def by_action(self, prefix: str) -> list:
        with self._lock:
            return [e for e in self._entries if e.action.startswith(prefix)]

    def find(self, entry_id: str):
        with self._lock:
            for entry in self._entries:
                if entry.entry_id == entry_id:
                    return entry
        return None

    @property
    def frozen(self) -> bool:
        return self._frozen

    @property
    def head(self) -> str:
        with self._lock:
            return self._entries[-1].entry_hash if self._entries else GENESIS_HASH

    # ---- 冻结：双人控制（two-person integrity） -----------------------------

    def request_freeze(self, actor: str, reason: str, token: str) -> dict:
        """管理员各自提交冻结令牌；集齐两名不同管理员后台账冻结。"""
        with self._lock:
            if self._frozen:
                self.append(
                    actor,
                    "audit.freeze_failed",
                    {"reason": reason, "cause": "already-frozen"},
                    allow_frozen=True,
                )
                return {"state": "frozen", "tokens": len(self._freeze_tokens)}
            if not token:
                raise ValueError("冻结令牌不能为空")
            self._freeze_tokens.add((actor, token))
            self.append(
                actor,
                "audit.freeze_requested",
                {"reason": reason, "confirmations": len(self._freeze_tokens)},
            )
            actors = {a for a, _ in self._freeze_tokens}
            if len(self._freeze_tokens) >= 2 and len(actors) >= 2:
                self._frozen = True
                self._freeze_reason = reason
                self.append(
                    "|".join(sorted(actors)),
                    "audit.frozen",
                    {"reason": reason, "confirmations": len(self._freeze_tokens)},
                    allow_frozen=True,
                )
                return {"state": "frozen", "tokens": len(self._freeze_tokens)}
            return {"state": "pending", "tokens": len(self._freeze_tokens)}

    def unfreeze(self, actor: str, reason: str):
        with self._lock:
            if not self._frozen:
                return {"state": "active"}
            self._frozen = False
            self._freeze_tokens.clear()
            self._freeze_reason = ""
            self.append(actor, "audit.unfrozen", {"reason": reason}, allow_frozen=True)
            return {"state": "active"}

    # ---- 完整性校验 --------------------------------------------------------

    def verify(self) -> dict:
        """重算整条哈希链，返回链头信息；发现任何篡改即抛 TamperError。"""
        with self._lock:
            prev = GENESIS_HASH
            for expected_seq, entry in enumerate(list(self._entries), start=1):
                if entry.seq != expected_seq:
                    raise TamperError(f"序号断裂：期望 {expected_seq}，实际 {entry.seq}")
                if entry.prev_hash != prev:
                    raise TamperError(f"记录 {entry.entry_id} 前向哈希不匹配")
                recomputed = _hash_entry(
                    entry.seq,
                    entry.entry_id,
                    entry.timestamp,
                    entry.actor,
                    entry.action,
                    entry.payload,
                    entry.prev_hash,
                )
                if recomputed != entry.entry_hash:
                    raise TamperError(f"记录 {entry.entry_id} 内容哈希不匹配（记录可能被改写）")
                prev = entry.entry_hash
            return {"entries": len(self._entries), "head": prev, "frozen": self._frozen}

    def chain_for(self, entry_id: str) -> list:
        """返回从创世记录到指定记录的完整授权链（用于导出溯源）。"""
        with self._lock:
            target = None
            for entry in self._entries:
                if entry.entry_id == entry_id:
                    target = entry
                    break
            if target is None:
                return []
            return [e.to_dict() for e in self._entries[: target.seq]]
