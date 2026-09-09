"""로컬 웹 검증 서버 (표준 라이브러리만 사용).

실행:
  python -m agent.webui.server           # http://127.0.0.1:8080
  python -m agent.webui.server --port 9000 --host 0.0.0.0

엔드포인트:
  GET  /                 -> 검증 UI (HTML)
  GET  /api/meta         -> 지원 collector/vendor/severity 목록
  POST /api/firewall     -> {"raw": "<로그>", "vendor": "auto|fortinet|...", "min_severity": "MEDIUM"}
  POST /api/event        -> {"event": {<EventBridge JSON>}, "min_severity": "MEDIUM"}

알림/대응은 호출하지 않는다(파싱→정규화→필터 결과만 반환). AWS 자격증명 불필요.
"""

from __future__ import annotations

import argparse
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..config import load_config
from ..core import preview_parse
from ..firewall.registry import available_vendors
from ..models import Severity
from ..registry import EVENT_TYPE_TO_COLLECTOR
from .page import INDEX_HTML

logger = logging.getLogger(__name__)


def _cfg_with_severity(min_severity: str | None):
    cfg = load_config()
    if min_severity:
        cfg.min_severity = Severity.from_name(min_severity)
    # 웹 검증에서는 실제 collector 폴링/알림을 쓰지 않음
    return cfg


class Handler(BaseHTTPRequestHandler):
    server_version = "SecAgentWebUI/1.0"

    def log_message(self, fmt, *args):  # 조용히
        logger.debug("%s - %s", self.address_string(), fmt % args)

    # --- helpers ----------------------------------------------------------
    def _send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str, status=200):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        try:
            return json.loads(raw)
        except ValueError:
            return {}

    # --- routes -----------------------------------------------------------
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send_html(INDEX_HTML)
        elif self.path == "/api/meta":
            self._send_json({
                "vendors": ["auto"] + available_vendors(),
                "event_types": sorted(EVENT_TYPE_TO_COLLECTOR.keys()),
                "severities": [s.name for s in Severity],
            })
        else:
            self._send_json({"error": "not found"}, status=404)

    def do_POST(self):
        try:
            payload = self._read_json()
            if self.path == "/api/firewall":
                self._handle_firewall(payload)
            elif self.path == "/api/event":
                self._handle_event(payload)
            else:
                self._send_json({"error": "not found"}, status=404)
        except Exception as e:  # noqa: BLE001 - UI에 오류 메시지 전달
            logger.exception("요청 처리 실패")
            self._send_json({"ok": False, "error": str(e)}, status=500)

    def _handle_firewall(self, payload: dict):
        raw = payload.get("raw", "")
        vendor = payload.get("vendor") or "auto"
        cfg = _cfg_with_severity(payload.get("min_severity"))
        fw_payload: dict = {"firewall_raw": raw}
        if vendor and vendor != "auto":
            fw_payload["vendor"] = vendor
        result = preview_parse(firewall_payload=fw_payload, cfg=cfg)
        self._send_json(result)

    def _handle_event(self, payload: dict):
        event = payload.get("event")
        if isinstance(event, str):
            try:
                event = json.loads(event)
            except ValueError:
                self._send_json({"ok": False, "error": "event가 올바른 JSON이 아닙니다."}, status=400)
                return
        if not isinstance(event, dict):
            self._send_json({"ok": False, "error": "event 객체가 필요합니다."}, status=400)
            return
        cfg = _cfg_with_severity(payload.get("min_severity"))
        result = preview_parse(event=event, cfg=cfg)
        self._send_json(result)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AWS Security Agent - 로컬 웹 검증 서버")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"웹 검증 UI: http://{args.host}:{args.port}  (Ctrl+C로 종료)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n종료합니다.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
