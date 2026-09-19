"""诊疗隐私用途管控的运行入口与 HTTP API。

保留 /health 与 --check；/v1/* 提供访问评估、知情同意、break-glass、
导出与水印验证、事件响应等 JSON 端点；--simulate 运行安全模拟。
"""

import argparse
import json
import sys
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from privacy.facade import PrivacyService
from privacy.models import (
    AccessRequest,
    BreakGlassError,
    ConsentWithdrawn,
    DeletionStateError,
    DuplicateExport,
    ExportSessionError,
    PolicyDenied,
    PrivacyError,
)

SERVICE_ID = "clinical-privacy"
SERVICE_NAME = "诊疗隐私用途管控"


def health_payload():
    """返回基础服务状态。"""
    return {"status": "ok", "service": SERVICE_ID, "name": SERVICE_NAME}


def _json_default(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, tuple):
        return list(value)
    if is_dataclass(value):
        return asdict(value)
    raise TypeError(f"不可序列化: {type(value)!r}")


def _parse_time(text):
    if text is None:
        return None
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _access_request(body):
    return AccessRequest(
        staff_id=body["staff_id"],
        role=body["role"],
        patient_id=body["patient_id"],
        relationship=body.get("relationship", "none"),
        purpose=body["purpose"],
        fields=frozenset(body["fields"]),
        consent_version=body.get("consent_version"),
        break_glass_id=body.get("break_glass_id"),
    )


class Handler(BaseHTTPRequestHandler):
    """健康检查与 /v1/* JSON API。"""

    service = None  # PrivacyService；由 make_handler 或 main 注入

    # --- 基础 ---
    def do_GET(self):
        if self.path != "/health":
            self.send_error(404)
            return
        self._respond(200, health_payload())

    def do_POST(self):
        if self.service is None:
            self._respond(503, {"error": "service-not-initialized"})
            return
        routes = {
            "/v1/access/check": self._access_check,
            "/v1/consents/register": self._consent_register,
            "/v1/consents/withdraw": self._consent_withdraw,
            "/v1/breakglass/request": self._breakglass_request,
            "/v1/breakglass/review": self._breakglass_review,
            "/v1/exports/begin": self._export_begin,
            "/v1/exports/complete": self._export_complete,
            "/v1/exports/verify": self._export_verify,
            "/v1/incidents/report": self._incident_report,
            "/v1/incidents/trace": self._incident_trace,
            "/v1/deletions/initiate": self._deletion_initiate,
            "/v1/deletions/confirm": self._deletion_confirm,
        }
        route = routes.get(self.path.split("?")[0])
        if route is None:
            self.send_error(404)
            return
        try:
            body = self._read_json()
            status, payload = route(body)
        except PolicyDenied as exc:
            status, payload = 403, {"error": exc.reason}
        except ConsentWithdrawn:
            status, payload = 409, {"error": "consent-withdrawn"}
        except (DuplicateExport, ExportSessionError, DeletionStateError) as exc:
            status, payload = 409, {"error": str(exc)}
        except BreakGlassError as exc:
            status, payload = 400, {"error": str(exc)}
        except PrivacyError as exc:
            status, payload = 400, {"error": str(exc)}
        except (KeyError, TypeError, ValueError) as exc:
            status, payload = 400, {"error": f"bad-request: {exc}"}
        self._respond(status, payload)

    # --- 端点 ---
    def _access_check(self, body):
        decision = self.service.check_access(_access_request(body))
        return 200, {
            "allowed": decision.allowed,
            "reason": decision.reason,
            "decision_id": decision.decision_id,
            "granted_fields": sorted(decision.granted_fields),
        }

    def _consent_register(self, body):
        consent = self.service.grant_consent(
            patient_id=body["patient_id"],
            version=body["version"],
            purposes=body["purposes"],
            fields=body["fields"],
            valid_from=_parse_time(body["valid_from"]),
            valid_until=_parse_time(body["valid_until"]),
            actor=body.get("actor", "patient"),
        )
        return 201, consent

    def _consent_withdraw(self, body):
        consent = self.service.withdraw_consent(body["consent_id"], actor=body.get("actor", "patient"))
        return 200, consent

    def _breakglass_request(self, body):
        grant = self.service.request_break_glass(
            staff_id=body["staff_id"],
            patient_id=body["patient_id"],
            reason=body["reason"],
            ttl_seconds=int(body.get("ttl_seconds", 600)),
        )
        return 201, grant

    def _breakglass_review(self, body):
        grant = self.service.review_break_glass(
            grant_id=body["grant_id"],
            reviewer=body["reviewer"],
            outcome=body["outcome"],
            notes=body.get("notes", ""),
        )
        return 200, grant

    def _export_begin(self, body):
        session = self.service.begin_export(
            _access_request(body), recipient=body["recipient"], source_id=body["source_id"]
        )
        return 201, {
            "session_id": session.session_id,
            "expires_at": session.expires_at,
            "decision_id": session.decision_id,
        }

    def _export_complete(self, body):
        record = self.service.complete_export(body["session_id"], body["file_hash"])
        return 201, record

    def _export_verify(self, body):
        return 200, self.service.verify_download(body["file_hash"], body["watermark"])

    def _incident_report(self, body):
        incident = self.service.report_incident(
            kind=body["kind"],
            patient_id=body["patient_id"],
            reporter=body["reporter"],
            description=body.get("description", ""),
            export_ids=body.get("export_ids", []),
        )
        return 201, incident

    def _incident_trace(self, body):
        return 200, {"records": self.service.trace_same_source(body["export_id"])}

    def _deletion_initiate(self, body):
        request = self.service.initiate_deletion(
            export_id=body["export_id"], reason=body["reason"], initiator=body["initiator"]
        )
        return 201, request

    def _deletion_confirm(self, body):
        request = self.service.confirm_deletion(body["request_id"], confirmer=body["confirmer"])
        return 200, request

    # --- 工具 ---
    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def _respond(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False, default=_json_default).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def make_handler(service):
    """绑定指定 PrivacyService 的处理器类（测试与多实例用）。"""

    class BoundHandler(Handler):
        pass

    BoundHandler.service = service
    return BoundHandler


def main():
    parser = argparse.ArgumentParser(description=SERVICE_NAME)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--simulate", action="store_true", help="运行安全部门模拟场景")
    args = parser.parse_args()
    if args.check:
        assert health_payload()["service"] == SERVICE_ID
        print("基础检查通过")
        return
    if args.simulate:
        from privacy.simulation import format_report, run_simulation

        report = run_simulation()
        print(format_report(report))
        sys.exit(0 if report["all_passed"] else 1)
    service = PrivacyService()
    ThreadingHTTPServer(("0.0.0.0", args.port), make_handler(service)).serve_forever()


if __name__ == "__main__":
    main()
