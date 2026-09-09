"""Check Point 방화벽 syslog 파서 (key=value / 세미콜론 구분).

Check Point(로그 익스포터)는 key=value 페어를 공백 또는 세미콜론으로 구분해 내보낸다. 예:
  action="Drop" src=203.0.113.5 dst=10.0.0.7 proto=tcp service=445
  product="SmartDefense" attack="Port Scan" severity="High" ...
(CEF/LEEF로 내보내면 CefParser가 처리)
"""

from __future__ import annotations

from ..models import Severity
from .base import BaseFirewallParser
from .util import parse_kv, severity_from_name, slug as _slug, strip_syslog_priority


class CheckPointParser(BaseFirewallParser):
    vendor = "checkpoint"

    def matches(self, line: str) -> bool:
        low = line.lower()
        # Check Point 특유 필드 신호(product/origin + action/attack)
        has_cp_field = ("product=" in low) or ("origin=" in low) or ("orig=" in low)
        has_event = ("action=" in low) or ("attack=" in low)
        # CEF는 CefParser가 처리하므로 여기선 제외
        return has_cp_field and has_event and "cef:" not in low

    def parse(self, line: str):
        body = strip_syslog_priority(line.replace(";", " "))
        f = parse_kv(body)
        if not f:
            return None

        sev_raw = (f.get("severity") or "").lower()
        severity = severity_from_name(sev_raw, Severity.MEDIUM)

        attack = f.get("attack") or f.get("attack_info") or f.get("product") or "Check Point event"
        action = f.get("action", "")
        src = f.get("src", "")
        dst = f.get("dst", "")
        product = f.get("product", "Firewall")

        is_threat = bool(f.get("attack") or f.get("attack_info"))

        return self._finding(
            event_id=f"checkpoint:{product}:{f.get('time','')}:{src}",
            title=f"Check Point {product} - {attack}",
            severity=severity,
            finding_type=f"Firewall:CheckPoint/{_slug(product)}"
            + ("/Threat" if is_threat else ""),
            description=(
                f"Check Point 이벤트: {attack}. severity={sev_raw or '-'}, "
                f"src={src or '-'}, dst={dst or '-'}."
            ),
            src_ip=src,
            dst_ip=dst,
            action=action,
            raw_fields=f,
        )
