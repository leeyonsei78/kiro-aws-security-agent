"""Palo Alto PAN-OS syslog 파서 (CSV 형식).

PAN-OS 로그는 CSV. 4번째 필드(Type)가 THREAT/TRAFFIC/SYSTEM 등.
THREAT 로그 표준 필드 순서(0-index 주요 항목):
  3=Type, 4=Threat/Content Type, 7=Source Address, 8=Destination Address,
  31(대략)=Severity, 30=Action ... 버전마다 열이 다를 수 있어 방어적으로 접근.

버전 차이에 견고하도록: Type/출발지/목적지는 앞쪽 고정 위치를 쓰고,
severity/action은 값 패턴으로 탐색한다.
"""

from __future__ import annotations

import csv
import io

from ..models import Severity
from .base import BaseFirewallParser
from .util import lookup_severity, strip_syslog_priority

_ACTION_TOKENS = {
    "alert", "allow", "deny", "drop", "reset-both", "reset-client",
    "reset-server", "block-url", "block-ip", "sinkhole", "block",
}


class PaloAltoParser(BaseFirewallParser):
    vendor = "paloalto"

    def matches(self, line: str) -> bool:
        body = strip_syslog_priority(line)
        cols = _split_csv(body)
        # 4번째 컬럼(Type)이 THREAT/TRAFFIC 등이면 PAN-OS로 간주
        return len(cols) >= 8 and any(
            c.upper() in ("THREAT", "TRAFFIC", "SYSTEM", "URL", "WILDFIRE", "DATA")
            for c in cols[3:5]
        )

    def parse(self, line: str):
        body = strip_syslog_priority(line)
        cols = _split_csv(body)
        if len(cols) < 8:
            return None

        # Type 컬럼 위치 탐색(보통 3, 헤더/버전에 따라 유동)
        type_idx = next(
            (i for i in range(3, min(6, len(cols)))
             if cols[i].upper() in ("THREAT", "TRAFFIC", "SYSTEM", "URL", "WILDFIRE", "DATA")),
            3,
        )
        log_type = cols[type_idx].upper()
        threat_content = cols[type_idx + 1] if type_idx + 1 < len(cols) else ""

        # 출발지/목적지: Type 이후 3~4번째 근방(THREAT 표준: src=7, dst=8)
        src = _first_ip(cols[type_idx + 3: type_idx + 6]) or _first_ip(cols)
        dst = _first_ip(cols[type_idx + 4: type_idx + 8])

        severity = _find_severity(cols)
        action = _find_action(cols)

        # TRAFFIC 로그는 severity가 없어 기본 LOW, THREAT는 값 기반
        if log_type != "THREAT" and severity == Severity.INFORMATIONAL:
            severity = Severity.LOW

        return self._finding(
            event_id=f"paloalto:{log_type}:{cols[1] if len(cols) > 1 else ''}:{src}",
            title=f"Palo Alto {log_type} - {threat_content or log_type}",
            severity=severity,
            finding_type=f"Firewall:PaloAlto/{log_type}"
            + ("/Threat" if log_type == "THREAT" else ""),
            description=(
                f"PAN-OS {log_type} 로그: {threat_content or '-'}. "
                f"src={src or '-'}, dst={dst or '-'}."
            ),
            src_ip=src,
            dst_ip=dst,
            action=action,
            raw_fields={"columns": cols},
        )


def _split_csv(body: str) -> list[str]:
    try:
        return next(csv.reader(io.StringIO(body)))
    except StopIteration:
        return []


def _is_ip(v: str) -> bool:
    parts = v.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _first_ip(cols: list[str]) -> str:
    for c in cols:
        if _is_ip(c):
            return c
    return ""


def _find_severity(cols: list[str]) -> Severity:
    for c in cols:
        s = lookup_severity(c)
        if s is not None:
            return s
    return Severity.INFORMATIONAL


def _find_action(cols: list[str]) -> str:
    for c in cols:
        if c.strip().lower() in _ACTION_TOKENS:
            return c.strip()
    return ""
