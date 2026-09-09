"""써드파티 방화벽 로그 수신 collector.

AWS를 폴링하지 않는다. 외부 장비가 webhook(HTTP)/syslog로 보낸 로그를
parse_event로 받아 벤더 파서로 정규화한다.

지원 입력(parse_event event 형태):
  1) {"firewall_lines": ["<raw line>", ...], "vendor": "fortinet"(선택)}
  2) {"firewall_raw": "<multi-line text>", "vendor": ...}
handler가 API Gateway HTTP 요청 body를 위 형태로 변환해 전달한다.

폴링(collect)은 no-op(수신형이라 조회할 소스가 없음).
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Iterable

from ..firewall.registry import detect_parser, get_parser
from ..models import SecurityFinding
from .base import BaseCollector

logger = logging.getLogger(__name__)


class FirewallSyslogCollector(BaseCollector):
    name = "firewall_syslog"

    def collect(self, since: datetime) -> Iterable[SecurityFinding]:
        # 수신형 collector라 폴링 소스 없음.
        return []

    def parse_event(self, event: dict[str, Any]) -> Iterable[SecurityFinding]:
        vendor = event.get("vendor")
        lines = self._extract_lines(event)
        forced = get_parser(vendor) if vendor else None
        if vendor and not forced:
            logger.warning("firewall_syslog: 알 수 없는 vendor '%s', 자동 감지로 대체", vendor)

        for line in lines:
            line = line.strip()
            if not line:
                continue
            parser = forced or detect_parser(line)
            if not parser:
                logger.info("firewall_syslog: 파서 미매칭 라인 스킵")
                continue
            try:
                finding = parser.parse(line)
            except Exception:  # noqa: BLE001 - 한 라인 파싱 실패가 전체를 막지 않도록
                logger.exception("firewall_syslog: 파싱 실패 (vendor=%s)", parser.vendor)
                continue
            if finding:
                yield finding

    def _extract_lines(self, event: dict[str, Any]) -> list[str]:
        if isinstance(event.get("firewall_lines"), list):
            return [str(x) for x in event["firewall_lines"]]
        raw = event.get("firewall_raw")
        if isinstance(raw, str):
            return raw.splitlines()
        return []
