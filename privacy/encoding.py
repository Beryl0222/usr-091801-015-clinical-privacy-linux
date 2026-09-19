"""确定性编码工具：时钟、标识符、字节摘要。

生产环境应替换为注入真实时钟与 CSPRNG 标识；默认实现保持测试可复现。
"""

import hashlib
import secrets
import threading
import time
from datetime import datetime, timezone


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_from(value) -> datetime:
    """把 ISO8601 字符串或时间戳归一化为带时区的 UTC datetime。"""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(value, tz=timezone.utc)
    else:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def content_hash(data) -> str:
    """对字节或可 JSON 化对象计算 SHA-256（对象使用规范排序编码）。"""
    if isinstance(data, str):
        data = data.encode()
    elif not isinstance(data, (bytes, bytearray)):
        data = canonical_json(data).encode()
    return hashlib.sha256(bytes(data)).hexdigest()


def canonical_json(data) -> str:
    return json_dumps(data)


def json_dumps(data) -> str:
    import json

    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class Clock:
    """可在测试中拨快的线程安全虚拟时钟，默认跟随墙钟。"""

    def __init__(self, start: datetime = None):
        self._lock = threading.Lock()
        self._fixed = None
        self._offset = 0.0
        self._virtual = None if start is None else utc_from(start)

    def now(self) -> datetime:
        with self._lock:
            if self._virtual is not None:
                return self._virtual
            return datetime.fromtimestamp(time.time() + self._offset, tz=timezone.utc)

    def advance(self, seconds: float):
        with self._lock:
            if self._virtual is not None:
                from datetime import timedelta

                self._virtual += timedelta(seconds=seconds)
            else:
                self._offset += seconds

    def freeze(self, moment=None):
        with self._lock:
            self._virtual = utc_now() if moment is None else utc_from(moment)
