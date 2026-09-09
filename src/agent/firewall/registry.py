"""방화벽 파서 registry + 자동 벤더 감지.

명시적 벤더 지정이 없으면 matches()로 파서를 자동 선택한다.
CEF는 여러 벤더 공통이므로 벤더별 파서보다 뒤에 시도한다.
"""

from __future__ import annotations

from .base import BaseFirewallParser
from .checkpoint import CheckPointParser
from .cef import CefParser
from .fortinet import FortinetParser
from .paloalto import PaloAltoParser

# 자동 감지 시도 순서: 벤더별 특화 파서 먼저, CEF는 마지막 fallback
_PARSER_ORDER: list[BaseFirewallParser] = [
    FortinetParser(),
    PaloAltoParser(),
    CheckPointParser(),
    CefParser(),
]

_PARSERS_BY_VENDOR: dict[str, BaseFirewallParser] = {p.vendor: p for p in _PARSER_ORDER}


def get_parser(vendor: str) -> BaseFirewallParser | None:
    return _PARSERS_BY_VENDOR.get(vendor)


def detect_parser(line: str) -> BaseFirewallParser | None:
    """라인 내용으로 벤더 파서를 자동 감지."""
    for parser in _PARSER_ORDER:
        try:
            if parser.matches(line):
                return parser
        except Exception:  # noqa: BLE001 - 한 파서의 matches 오류가 전체를 막지 않도록
            continue
    return None


def available_vendors() -> list[str]:
    return list(_PARSERS_BY_VENDOR.keys())
