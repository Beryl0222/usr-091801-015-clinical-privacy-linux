"""可验证水印与密钥轮换。

水印格式：WM1.<kid>.<base64url(payload)>.<hmac_hex>
payload 含操作者、时间、文件哈希与授权链；kid 指明签名密钥。
轮换只新增密钥、保留旧密钥，因此旧文件哈希对应的水印仍可验证。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading

from .models import WatermarkInvalid

WATERMARK_PREFIX = "WM1"


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


class KeyRing:
    """签名密钥环：active 用于签发，全部历史密钥用于验证。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._secrets: dict[str, bytes] = {}
        self._counter = 0
        self._active_kid = ""
        self.rotate()

    @property
    def active_kid(self) -> str:
        with self._lock:
            return self._active_kid

    def known_kids(self) -> list[str]:
        with self._lock:
            return sorted(self._secrets)

    def rotate(self, secret: bytes | None = None) -> str:
        """轮换出新密钥并设为 active；旧密钥保留用于验证。"""
        with self._lock:
            self._counter += 1
            kid = f"k{self._counter}"
            self._secrets[kid] = secret or secrets.token_bytes(32)
            self._active_kid = kid
            return kid

    def sign(self, payload: dict) -> tuple[str, str]:
        with self._lock:
            kid = self._active_kid
            secret = self._secrets[kid]
        signature = hmac.new(secret, _canonical(payload), hashlib.sha256).hexdigest()
        return kid, signature

    def verify(self, kid: str, payload: dict, signature: str) -> bool:
        with self._lock:
            secret = self._secrets.get(kid)
        if secret is None:
            return False
        expected = hmac.new(secret, _canonical(payload), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)


def issue(keyring: KeyRing, payload: dict) -> str:
    """用当前 active 密钥签发水印。"""
    kid, signature = keyring.sign(payload)
    return f"{WATERMARK_PREFIX}.{kid}.{_b64encode(_canonical(payload))}.{signature}"


def parse(token: str) -> tuple[str, dict, str]:
    """解析水印，不验证签名。"""
    try:
        prefix, kid, body, signature = token.split(".")
    except ValueError:
        raise WatermarkInvalid("watermark-malformed") from None
    if prefix != WATERMARK_PREFIX:
        raise WatermarkInvalid("watermark-malformed")
    try:
        payload = json.loads(_b64decode(body))
    except (ValueError, UnicodeDecodeError):
        raise WatermarkInvalid("watermark-malformed") from None
    if not isinstance(payload, dict):
        raise WatermarkInvalid("watermark-malformed")
    return kid, payload, signature


def verify(keyring: KeyRing, token: str, file_hash: str) -> dict:
    """验证水印签名与文件哈希，返回 payload；失败抛 WatermarkInvalid。"""
    kid, payload, signature = parse(token)
    if not keyring.verify(kid, payload, signature):
        raise WatermarkInvalid("watermark-signature-mismatch")
    if payload.get("file_hash") != file_hash:
        raise WatermarkInvalid("watermark-file-hash-mismatch")
    return payload
