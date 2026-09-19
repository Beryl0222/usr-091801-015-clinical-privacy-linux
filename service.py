"""诊疗隐私用途管控的 HTTP 运行入口。

除健康检查外，所有端点均为 POST JSON；领域编排见 privacy.app.PrivacyService。
原始影像内容不入库：/exports 只接收 base64 内容用于即时计算哈希。
"""

import argparse
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from privacy.app import (
    EMERGENCY_TTL_SECONDS,
    LedgerFrozenError,
    PrivacyService,
)
from privacy.encoding import Clock, utc_from
from privacy.policy import PolicyError
from privacy.audit import TamperError
from privacy.watermark import WatermarkError

SERVICE_ID = "clinical-privacy"
SERVICE_NAME = "诊疗隐私用途管控"

_SERVICE_LOCK = threading.Lock()
_SERVICE = None


def get_service() -> PrivacyService:
    global _SERVICE
    with _SERVICE_LOCK:
        if _SERVICE is None:
            _SERVICE = PrivacyService(Clock())
        return _SERVICE


def reset_service(service: PrivacyService = None) -> PrivacyService:
    """供测试替换共享实例。"""
    global _SERVICE
    with _SERVICE_LOCK:
        _SERVICE = service or PrivacyService(Clock())
        return _SERVICE


def health_payload():
    """返回基础服务状态。"""
    return {"status": "ok", "service": SERVICE_ID, "name": SERVICE_NAME}


# 路由表：路径段 -> (服务方法, 必填参数)
ROUTES = {
    ("POST", "/admin/users"): ("register_user", ["actor_id", "role"]),
    ("POST", "/admin/relations"): ("register_relation", ["actor_id", "patient_id", "relation"]),
    ("POST", "/consents"): ("register_consent", ["actor_id", "patient_id", "purposes", "version"]),
    ("POST", "/access/view"): ("view_record", ["actor_id", "patient_id", "purpose", "fields"]),
    ("POST", "/access/view-consent"): (
        "view_with_consent",
        ["actor_id", "patient_id", "purpose", "fields", "consent_id"],
    ),
    ("POST", "/emergencies"): ("start_emergency", ["actor_id", "patient_id", "reason"]),
    ("POST", "/exports"): ("request_export",
                           ["actor_id", "patient_id", "purpose", "fields", "delivered_to"]),
    ("POST", "/exports/verify"): ("verify_watermark", ["actor_id", "file_hash", "token"]),
    ("POST", "/exports/trace"): ("trace_source", ["actor_id", "file_hash"]),
    ("POST", "/incidents"): ("report_incident", ["reporter_id", "kind", "description"]),
    ("POST", "/audit/freeze"): ("freeze_audit", ["actor_id", "reason", "token"]),
    ("POST", "/audit/unfreeze"): ("unfreeze_audit", ["actor_id", "reason"]),
    ("POST", "/purges"): ("initiate_purge", ["actor_id", "file_hash", "reason"]),
    ("POST", "/keys/rotate"): ("rotate_keys", ["actor_id"]),
}

SUBROUTES = {
    "consents": {
        "revoke": ("revoke_consent", ["actor_id", "reason"]),
    },
    "emergencies": {
        "view": ("emergency_view", ["actor_id", "patient_id", "fields"]),
        "review": ("review_emergency", ["reviewer_id", "approved"]),
    },
    "incidents": {
        "close": ("close_incident", ["actor_id"]),
    },
    "purges": {
        "confirm": ("confirm_purge", ["actor_id"]),
    },
}


class Handler(BaseHTTPRequestHandler):
    """处理健康检查与隐私用途管控 API。"""

    def do_GET(self):
        if self.path == "/health":
            self._write_json(200, health_payload())
            return
        if self.path == "/state":
            self._write_json(200, get_service().state())
            return
        if self.path == "/audit/entries":
            self._write_json(
                200,
                {"entries": [e.to_dict() for e in get_service().ledger.all()]},
            )
            return
        if self.path == "/notifications":
            self._write_json(200, {"notifications": get_service().notifications})
            return
        self.send_error(404)

    def do_POST(self):
        path = self.path.rstrip("/") or "/"
        try:
            body = self._read_json()
        except (ValueError, json.JSONDecodeError) as exc:
            self._write_json(400, {"error": "bad-json", "message": str(exc)})
            return

        route = ROUTES.get(("POST", path))
        method_name = None
        kwargs = body
        resource_id = None

        if route is None:
            parts = path.strip("/").split("/")
            if len(parts) == 3 and parts[0] in SUBROUTES and parts[2] in SUBROUTES[parts[0]]:
                resource_id = parts[1]
                method_name, required = SUBROUTES[parts[0]][parts[2]]
            else:
                self._write_json(404, {"error": "not-found", "path": path})
                return
        else:
            method_name, required = route

        missing = [key for key in required if key not in body]
        if missing:
            self._write_json(400, {"error": "missing-fields", "fields": missing})
            return

        service = get_service()
        try:
            if path == "/exports":
                payload = self._handle_export_payload(body)
                result = service.request_export(**payload)
            elif resource_id is not None:
                id_kwarg = {
                    "consents": "consent_id",
                    "emergencies": "emergency_id",
                    "incidents": "incident_id",
                    "purges": "purge_id",
                }[parts[0]]
                call_kwargs = {k: v for k, v in body.items() if k != "content_b64"}
                call_kwargs[id_kwarg] = resource_id
                result = getattr(service, method_name)(**call_kwargs)
            else:
                call_kwargs = {k: v for k, v in body.items() if k != "content_b64"}
                result = getattr(service, method_name)(**call_kwargs)
        except PolicyError as denied:
            status = 423 if isinstance(denied, LedgerFrozenError) else 403
            self._write_json(status, {"error": denied.code, "message": str(denied),
                                      "details": denied.details})
            return
        except LedgerFrozenError as exc:
            self._write_json(423, {"error": "ledger-frozen", "message": str(exc)})
            return
        except (WatermarkError, TamperError) as exc:
            self._write_json(422, {"error": type(exc).__name__, "message": str(exc)})
            return
        except TypeError as exc:
            self._write_json(400, {"error": "bad-arguments", "message": str(exc)})
            return
        self._write_json(200, result)

    def _handle_export_payload(self, body):
        if "content_b64" not in body:
            raise ValueError("导出登记必须提供 content_b64（仅用于哈希计算，不保存）")
        raw = base64.b64decode(body["content_b64"])
        payload = {k: v for k, v in body.items() if k != "content_b64"}
        payload["content"] = raw
        return payload

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode())

    def _write_json(self, status: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def main():
    parser = argparse.ArgumentParser(description=SERVICE_NAME)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        assert health_payload()["service"] == SERVICE_ID
        svc = get_service()
        svc.ledger.verify()
        print("基础检查通过")
        return
    ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
