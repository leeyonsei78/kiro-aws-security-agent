"""CEF(Common Event Format) 파서 — 벤더 공통 fallback.

3사(Palo Alto/Fortinet/Check Point) 모두 CEF 출력 옵션을 지원한다.
형식:
  CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension
  Extension은 key=value 페어. 예: src=1.2.3.4 dst=5.6.7.8 act=blocked
"""

from __future__ import annotations

from ..models import Severity
from .base import BaseFirewallParser
from .util import parse_kv, slug as _slug, strip_syslog_priority


class CefParser(BaseFirewallParser):
    vendor = "cef"

    def matches(self, line: str) -> bool:
        return "CEF:" in line

    def parse(self, line: str):
        body = strip_syslog_priority(line)
        idx = body.find("CEF:")
        if idx < 0:
            return None
        cef = body[idx:]
        # 헤더 7개 필드는 escape되지 않은 '|'로 구분
        parts = _split_cef_header(cef)
        if len(parts) < 7:
            return None
        _, vendor, product, version, sig_id, name, sev = parts[:7]
        extension = parts[7] if len(parts) > 7 else ""
        ext = parse_kv(extension)

        return self._finding(
            event_id=f"cef:{vendor}:{sig_id}:{ext.get('src','')}",
            title=f"{vendor} {product} - {name}",
            severity=_cef_severity(sev),
            finding_type=f"Firewall:CEF/{_slug(vendor)}/{_slug(product)}",
            description=(
                f"CEF 이벤트: {name}. vendor={vendor}, product={product} {version}, "
                f"sig={sig_id}, src={ext.get('src','-')}, dst={ext.get('dst','-')}."
            ),
            src_ip=ext.get("src", ""),
            dst_ip=ext.get("dst", ""),
            action=ext.get("act", ""),
            raw_fields={"vendor": vendor, "product": product, "name": name, **ext},
        )


def _split_cef_header(cef: str) -> list[str]:
    # CEF 헤더의 '|'는 escape(\|)될 수 있음. 8조각(헤더7+extension)으로 분리.
    out: list[str] = []
    buf = []
    i = 0
    while i < len(cef) and len(out) < 7:
        ch = cef[i]
        if ch == "\\" and i + 1 < len(cef):
            buf.append(cef[i + 1])
            i += 2
            continue
        if ch == "|":
            out.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    # 나머지(extension) 통째로
    out.append(cef[i:])
    # 첫 조각 "CEF:Version"에서 버전만 필요없으니 그대로 두되 인덱스 맞춤
    return out


def _cef_severity(value: str) -> Severity:
    v = value.strip().lower()
    # CEF severity는 0~10 정수 또는 Low/Medium/High/Very-High
    named = {
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "very-high": Severity.CRITICAL,
        "critical": Severity.CRITICAL,
    }
    if v in named:
        return named[v]
    try:
        n = int(float(v))
    except (TypeError, ValueError):
        return Severity.MEDIUM
    if n >= 9:
        return Severity.CRITICAL
    if n >= 7:
        return Severity.HIGH
    if n >= 4:
        return Severity.MEDIUM
    if n >= 1:
        return Severity.LOW
    return Severity.INFORMATIONAL
