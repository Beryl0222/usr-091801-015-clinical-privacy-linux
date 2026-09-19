"""含操作者与时间的可验证水印，支持密钥轮换。

水印载荷 W=(file_hash, export_id, operator, patient_id, purpose, delivered_to,
issued_at, consent_id, emergency_id, nonce)，用当前签名密钥计算
sig = HMAC-SHA256(key, 规范JSON(W))，令牌为 W+kid+sig。

轮换密钥时旧密钥以“仅验证”状态保留（kid 仍在 keyring 中），因此历史文件
可凭旧哈希继续验证；被显式吊销的 kid 立即失效。系统不保存原始影像，
水印载荷中也只出现文件哈希。
"""

import hmac
import hashlib
import threading
from dataclasses import dataclass, field

from .encoding import content_hash, json_dumps, new_id

ALGORITHM = "HMAC-SHA256"


class WatermarkError(RuntimeError):
    pass


@dataclass
class _Key:
    kid: str
    secret: bytes
    status: str = "active"  # active | verify-only | revoked


class KeyRing:
    """版本化签名密钥环：active 用于签发，verify-only/active 均可验证。"""

    def __init__(self):
        self._lock = threading.RLock()
        self._keys: dict[str, _Key] = {}
        self._order: list[str] = []
        self._active_kid = None

    def rotate(self, secret: bytes = None) -> str:
        """生成新密钥并把旧密钥降级为 verify-only（旧文件仍可验证）。"""
        import secrets

        with self._lock:
            if self._active_kid is not None:
                self._keys[self._active_kid].status = "verify-only"
            kid = f"key-{len(self._order) + 1}-{secrets.token_hex(3)}"
            self._keys[kid] = _Key(kid, secret or secrets.token_bytes(32), "active")
            self._order.append(kid)
            self._active_kid = kid
            return kid

    def revoke(self, kid: str):
        with self._lock:
            if kid not in self._keys:
                raise WatermarkError(f"未知密钥 {kid}")
            self._keys[kid].status = "revoked"
            if self._active_kid == kid:
                self._active_kid = None

    @property
    def active_kid(self):
        return self._active_kid

    def status(self, kid: str) -> str:
        key = self._keys.get(kid)
        return key.status if key else "unknown"

    def list_keys(self):
        with self._lock:
            return [{"kid": k, "status": self._keys[k].status} for k in self._order]

    def _signing_key(self) -> _Key:
        with self._lock:
            if self._active_kid is None:
                raise WatermarkError("没有可用的签名密钥，请先轮换密钥")
            return self._keys[self._active_kid]

    def _mac(self, key: _Key, payload: dict) -> str:
        return hmac.new(key.secret, json_dumps(payload).encode(), hashlib.sha256).hexdigest()

    def issue(self, claims: dict) -> dict:
        """签发水印令牌。claims 至少包含 file_hash 与操作者信息。"""
        key = self._signing_key()
        payload = dict(claims)
        payload.setdefault("nonce", new_id("nonce").split("_", 1)[-1])
        payload["kid"] = key.kid
        sig = self._mac(key, payload)
        return {
            "alg": ALGORITHM,
            "kid": key.kid,
            "payload": payload,
            "sig": sig,
        }

    def verify(self, token: dict, expected_file_hash: str = None) -> dict:
        """验证水印令牌；密钥轮换后旧 kid 仍可通过，吊销或篡改则失败。

        返回 {"valid": True, ...验证要素}；失败时抛 WatermarkError。
        """
        if not isinstance(token, dict) or "payload" not in token or "sig" not in token:
            raise WatermarkError("水印令牌格式不完整")
        payload = token["payload"]
        kid = token.get("kid") or payload.get("kid")
        with self._lock:
            key = self._keys.get(kid)
            if key is None:
                raise WatermarkError(f"未知密钥 {kid}，授权链密钥缺失")
            if key.status == "revoked":
                raise WatermarkError(f"密钥 {kid} 已被吊销")
        expected = self._mac(key, payload)
        if not hmac.compare_digest(expected, token["sig"]):
            raise WatermarkError("水印签名不匹配，文件或水印可能被篡改")
        if expected_file_hash is not None and payload.get("file_hash") != expected_file_hash:
            raise WatermarkError("水印绑定的文件哈希与被验证文件不一致")
        claims = {k: v for k, v in payload.items() if k != "kid"}
        return {
            "valid": True,
            "kid": kid,
            "key_status": key.status,
            "alg": token.get("alg", ALGORITHM),
            "claims": claims,
        }

    @staticmethod
    def hash_bytes(data: bytes) -> str:
        return content_hash(data)
