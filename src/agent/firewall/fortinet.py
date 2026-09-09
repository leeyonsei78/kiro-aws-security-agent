"""Fortinet FortiGate syslog 파서.

FortiGate는 key="value" 페어 형식. 예:
  date=2026-09-09 time=... devname="FGT" level="alert" logid="..." type="utm"
  subtype="ips" action="dropped" srcip=203.0.113.5 dstip=10.0.0.7 attack="Backdoor"
"""

from __future__ import annotations

from ..models import Severity
from .base import BaseFirewallParser
from .util import parse_kv, strip_syslog_priority

# FortiGate level -> 통합 심각도
_LEVEL_MAP = {
    "emergency": Severity.CRITICAL,
    "alert": Severity.CRITICAL,
    "critical": Severity.HIGH,
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "notice": Severity.LOW,
    "information": Severity.INFORMATIONAL,
    "debug": Severity.INFORMATIONAL,
}


class FortinetParser(BaseFirewallParser):
    vendor = "fortinet"

    def matches(self, line: str) -> bool:
        low = line.lower()
        # devname/logid/type 은 FortiGate 로그의 강한 신호
        return ("devname=" in low or "logid=" in low) and ("srcip=" in low or "type=" in low)

    def parse(self, line: str):
        body = strip_syslog_priority(line)
        f = parse_kv(body)
        if not f:
            return None

        level = (f.get("level") or "").lower()
        severity = _LEVEL_MAP.get(level, Severity.MEDIUM)

        subtype = f.get("subtype", f.get("type", "traffic"))
        attack = f.get("attack") or f.get("msg") or f.get("eventtype") or subtype
        action = f.get("action", "")
        src = f.get("srcip", "")
        dst = f.get("dstip", "")
        logid = f.get("logid", "")

        # IPS/바이러스/공격 계열은 위협으로 강조
        is_threat = subtype in ("ips", "virus", "anomaly", "app-ctrl", "waf")

        return self._finding(
            event_id=f"fortinet:{logid}:{f.get('eventtime', f.get('time',''))}:{src}",
            title=f"FortiGate {subtype} - {attack}",
            severity=severity,
            finding_type=f"Firewall:Fortinet/{subtype}"
            + ("/Threat" if is_threat else ""),
            description=(
                f"FortiGate 이벤트: {attack}. level={level or '-'}, "
                f"src={src or '-'}, dst={dst or '-'}."
            ),
            src_ip=src,
            dst_ip=dst,
            action=action,
            raw_fields=f,
        )
