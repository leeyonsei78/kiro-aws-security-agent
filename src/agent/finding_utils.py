"""SecurityFinding raw 데이터에서 공통 정보를 뽑는 헬퍼.

여러 remediator가 GuardDuty finding에서 동일한 정보를 추출하므로 한 곳으로 통합한다.
"""

from __future__ import annotations

from .models import SecurityFinding


def guardduty_remote_ip(finding: SecurityFinding) -> str | None:
    """GuardDuty finding raw에서 원격(공격자) IPv4를 추출.

    Service.Action 하위의 NetworkConnectionAction / AwsApiCallAction / PortProbeAction
    각각의 RemoteIpDetails.IpAddressV4, 그리고 PortProbeDetails 배열까지 탐색한다.
    """
    service = (finding.raw or {}).get("Service", {}) or {}
    action = service.get("Action", {}) or {}
    for key in ("NetworkConnectionAction", "AwsApiCallAction", "PortProbeAction"):
        details = action.get(key, {}) or {}
        remote = details.get("RemoteIpDetails", {}) or {}
        if remote.get("IpAddressV4"):
            return remote["IpAddressV4"]
        for probe in details.get("PortProbeDetails", []) or []:
            r = probe.get("RemoteIpDetails", {}) or {}
            if r.get("IpAddressV4"):
                return r["IpAddressV4"]
    return None
