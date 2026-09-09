"""Security Group 위험 설정 감지 collector.

Security Hub에 항상 올라오지 않는 "구성 위험"을 직접 스캔한다.
탐지: 인터넷(0.0.0.0/0, ::/0)에 민감 포트가 개방된 인바운드 규칙.

폴링 전용(구성 스캔). 실시간은 Config/EventBridge(ec2 AuthorizeSecurityGroupIngress)로 확장 가능.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Iterable

from ..models import Resource, SecurityFinding, Severity, utcnow
from .base import BaseCollector

logger = logging.getLogger(__name__)

# 인터넷 개방 시 위험도가 높은 포트 -> 심각도
SENSITIVE_PORTS: dict[int, Severity] = {
    22: Severity.HIGH,      # SSH
    3389: Severity.HIGH,    # RDP
    3306: Severity.HIGH,    # MySQL
    5432: Severity.HIGH,    # PostgreSQL
    6379: Severity.HIGH,    # Redis
    27017: Severity.HIGH,   # MongoDB
    9200: Severity.HIGH,    # Elasticsearch
    1433: Severity.HIGH,    # MSSQL
    23: Severity.CRITICAL,  # Telnet
    21: Severity.MEDIUM,    # FTP
}

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


class SecurityGroupCollector(BaseCollector):
    name = "security_group"

    def _client(self):
        return self._make_client("ec2")

    def collect(self, since: datetime) -> Iterable[SecurityFinding]:
        # 구성 스캔이라 since 무시(전체 SG 평가). 노이즈는 dedup/알림 측에서 관리.
        client = self._client()
        paginator = client.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                yield from self._evaluate_sg(sg)

    def _evaluate_sg(self, sg: dict[str, Any]) -> Iterable[SecurityFinding]:
        sg_id = sg.get("GroupId", "")
        sg_name = sg.get("GroupName", "")
        account_id = sg.get("OwnerId", "")
        vpc_id = sg.get("VpcId", "")

        for perm in sg.get("IpPermissions", []) or []:
            open_ranges = self._open_ranges(perm)
            if not open_ranges:
                continue
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            proto = perm.get("IpProtocol", "-1")

            risky = self._risky_ports(proto, from_port, to_port)
            if not risky:
                continue

            severity = max((SENSITIVE_PORTS[p] for p in risky), default=Severity.MEDIUM)
            # 전체 포트(-1 또는 0-65535) 개방은 특히 위험
            if proto == "-1" or (from_port == 0 and to_port == 65535):
                severity = Severity.CRITICAL

            port_desc = self._port_desc(proto, from_port, to_port)
            cidrs = ", ".join(open_ranges)
            yield SecurityFinding(
                id=f"sg-open:{sg_id}:{proto}:{from_port}:{to_port}",
                source=self.name,
                title=f"Security Group {sg_id} 인터넷 개방 ({port_desc})",
                description=(
                    f"Security Group '{sg_name}' ({sg_id}) 가 {cidrs} 에 대해 "
                    f"{port_desc} 인바운드를 허용합니다. 민감 포트가 공개 노출됩니다."
                ),
                severity=severity,
                finding_type=f"NetworkExposure:SecurityGroup/OpenIngress:{self._first_risky_label(risky, proto)}",
                account_id=account_id,
                region=self.region or "",
                resources=[
                    Resource(
                        type="AwsEc2SecurityGroup",
                        id=sg_id,
                        region=self.region or "",
                        details={
                            "GroupName": sg_name,
                            "VpcId": vpc_id,
                            "IpProtocol": proto,
                            "FromPort": from_port,
                            "ToPort": to_port,
                            "OpenCidrs": open_ranges,
                        },
                    )
                ],
                created_at=utcnow(),
                updated_at=utcnow(),
                remediation=(
                    f"해당 인바운드 규칙을 회수(revoke)하거나, 소스 CIDR을 신뢰 대역으로 제한하세요. "
                    f"필요 시 SSM Session Manager/VPN 등 대안을 사용하세요."
                ),
                raw={"SecurityGroup": sg, "Permission": perm, "OpenCidrs": open_ranges},
            )

    def _open_ranges(self, perm: dict[str, Any]) -> list[str]:
        ranges: list[str] = []
        for r in perm.get("IpRanges", []) or []:
            if r.get("CidrIp") in OPEN_CIDRS:
                ranges.append(r["CidrIp"])
        for r in perm.get("Ipv6Ranges", []) or []:
            if r.get("CidrIpv6") in OPEN_CIDRS:
                ranges.append(r["CidrIpv6"])
        return ranges

    def _risky_ports(self, proto: str, from_port, to_port) -> list[int]:
        # 전체 개방(모든 프로토콜/전체 포트)이면 모든 민감 포트 포함으로 간주
        if proto == "-1" or from_port is None or to_port is None:
            return list(SENSITIVE_PORTS.keys())
        if from_port == 0 and to_port == 65535:
            return list(SENSITIVE_PORTS.keys())
        return [p for p in SENSITIVE_PORTS if from_port <= p <= to_port]

    def _first_risky_label(self, risky: list[int], proto: str) -> str:
        if proto == "-1":
            return "AllTraffic"
        return str(sorted(risky)[0]) if risky else "Unknown"

    def _port_desc(self, proto: str, from_port, to_port) -> str:
        if proto == "-1":
            return "모든 트래픽"
        if from_port == to_port:
            return f"{proto}/{from_port}"
        return f"{proto}/{from_port}-{to_port}"
