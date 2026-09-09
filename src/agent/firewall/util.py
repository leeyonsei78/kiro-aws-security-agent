"""방화벽 로그 파싱 공통 유틸.

- parse_kv: key=value / key="quoted value" 형식(Fortinet, Check Point) 파서.
  따옴표 안의 공백/= 는 구분자로 취급하지 않는다(인젝션 방지).
"""

from __future__ import annotations

import re

from ..models import Severity

# 벤더 공통 severity 문자열 -> Severity. 각 파서가 벤더 특수값을 얹어 쓴다.
_SEVERITY_NAMES: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
    "information": Severity.INFORMATIONAL,
    "info": Severity.INFORMATIONAL,
}


def severity_from_name(value: str, default: Severity = Severity.MEDIUM) -> Severity:
    """'high'/'critical' 등 공통 심각도 문자열을 Severity로. 미매칭 시 default."""
    return _SEVERITY_NAMES.get((value or "").strip().lower(), default)


def lookup_severity(value: str) -> Severity | None:
    """공통 심각도 문자열이면 Severity, 아니면 None(토큰 탐색용)."""
    return _SEVERITY_NAMES.get((value or "").strip().lower())


def slug(text: str) -> str:
    """영숫자 외 문자를 '_'로 치환. 빈 값이면 'unknown'."""
    return "".join(c if c.isalnum() else "_" for c in (text or "").strip()) or "unknown"


# key=value 또는 key="value with spaces" 를 안전하게 토큰화.
# 따옴표로 감싼 값 내부의 공백/=는 무시한다.
_KV_RE = re.compile(r'(\w[\w.\-]*)=("(?:[^"\\]|\\.)*"|\S*)')


def parse_kv(line: str) -> dict[str, str]:
    """key=value 로그를 dict로. 따옴표는 제거한다."""
    result: dict[str, str] = {}
    for match in _KV_RE.finditer(line):
        key = match.group(1)
        val = match.group(2)
        if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
            val = val[1:-1].replace('\\"', '"')
        result[key] = val
    return result


def strip_syslog_priority(line: str) -> str:
    """맨 앞의 <PRI> 및 흔한 syslog 헤더를 최대한 제거해 본문만 남긴다.

    예) "<134>1 2026-09-09T... host tag: msg" 형태에서 뒤쪽 본문을 반환.
    보수적으로 처리: <PRI>만 제거하고 나머지는 그대로 둔다(벤더 파서가 필드로 처리).
    """
    return re.sub(r"^<\d{1,3}>\d?\s*", "", line).strip()
