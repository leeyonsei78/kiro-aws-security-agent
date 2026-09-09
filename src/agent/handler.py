"""AWS Lambda 진입점.

하나의 함수로 세 트리거를 처리:
  - EventBridge 스케줄 (예: rate(5 minutes))                 -> 폴링 모드
  - EventBridge 이벤트 패턴 (지원 finding/이벤트)             -> 실시간 모드
  - API Gateway HTTP (써드파티 방화벽 webhook/syslog POST)   -> 방화벽 수신 모드

EventBridge 실시간 여부는 registry의 EVENT_TYPE_TO_COLLECTOR 매핑에 detail-type이
있는지로 판단한다(새 이벤트 타입을 registry에 추가하면 handler도 자동 반영).
"""

from __future__ import annotations

import json
import logging

from .config import load_config
from .core import run_event, run_firewall, run_poll
from .registry import EVENT_TYPE_TO_COLLECTOR
from .webhook_auth import authorize

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def _is_realtime_finding_event(event: dict) -> bool:
    # 스케줄 이벤트는 detail-type "Scheduled Event" / source aws.events -> 폴링으로 처리.
    return event.get("detail-type", "") in EVENT_TYPE_TO_COLLECTOR


def _is_http_event(event: dict) -> bool:
    # API Gateway (REST v1: httpMethod / HTTP v2: requestContext.http)
    if "httpMethod" in event:
        return True
    rc = event.get("requestContext", {})
    return isinstance(rc, dict) and "http" in rc


def _parse_firewall_payload(event: dict) -> dict:
    """API Gateway 요청 body를 firewall collector가 이해하는 payload로 변환.

    지원 body:
      - JSON: {"firewall_lines": [...], "vendor": ...} 또는 {"firewall_raw": "..."}
      - text/plain: 개행 구분 raw 로그 (vendor는 쿼리스트링 ?vendor=... 로 지정 가능)
    """
    body = event.get("body")
    if event.get("isBase64Encoded") and isinstance(body, str):
        import base64
        try:
            body = base64.b64decode(body).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass

    vendor = None
    qs = event.get("queryStringParameters") or {}
    if isinstance(qs, dict):
        vendor = qs.get("vendor")

    if isinstance(body, str):
        stripped = body.strip()
        if stripped.startswith("{"):
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, dict):
                    if vendor and "vendor" not in parsed:
                        parsed["vendor"] = vendor
                    return parsed
            except ValueError:
                pass
        # text/plain 취급
        payload = {"firewall_raw": body}
        if vendor:
            payload["vendor"] = vendor
        return payload

    if isinstance(body, dict):
        return body
    return {"firewall_raw": ""}


def _http_response(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def lambda_handler(event: dict, context=None) -> dict:  # noqa: ANN001
    cfg = load_config()
    logger.info("event received: %s", json.dumps(event)[:1000])

    if _is_http_event(event):
        # 파싱 전에 인증 먼저 검사 (인증 실패 시 body를 건드리지 않음)
        auth = authorize(event, cfg)
        if not auth.ok:
            logger.warning("firewall webhook 인증 실패: %s (status=%s)", auth.reason, auth.status)
            return _http_response(auth.status, {"error": auth.reason})
        payload = _parse_firewall_payload(event)
        result = run_firewall(payload, cfg)
        logger.info("firewall result: matched=%s", result.get("matched"))
        return _http_response(200, {"matched": result.get("matched", 0)})

    if _is_realtime_finding_event(event):
        result = run_event(event, cfg)
    else:
        # 스케줄/수동 호출 -> 폴링
        result = run_poll(cfg)

    logger.info("result: matched=%s", result.get("matched"))
    return result
