"""EC2/네트워크 관련 컴플라이언스 체크."""

from __future__ import annotations

from typing import Any

from ..models import Severity
from .base import BaseComplianceCheck, CheckViolation


class EbsEncryptionByDefaultCheck(BaseComplianceCheck):
    code = "CA-03"
    title = "EBS 기본 암호화 비활성화"
    severity = Severity.MEDIUM
    service = "ec2"
    category = "데이터 보호"
    remediation = "EnableEbsEncryptionByDefault로 리전 단위 EBS 기본 암호화를 활성화하세요."
    standards = ("KISA CII(클라우드)", "CIS AWS 2.2.1")

    def run(self, client: Any) -> list[CheckViolation]:
        try:
            resp = client.get_ebs_encryption_by_default()
        except Exception:  # noqa: BLE001
            return []
        if not resp.get("EbsEncryptionByDefault", False):
            return [CheckViolation(
                resource_id="account",
                detail="이 리전에서 EBS 기본 암호화가 비활성 상태",
                evidence={"EbsEncryptionByDefault": False},
            )]
        return []


class DefaultSgOpenCheck(BaseComplianceCheck):
    code = "CA-30"
    title = "기본 보안그룹에 허용 규칙 존재"
    severity = Severity.MEDIUM
    service = "ec2"
    category = "네트워크"
    remediation = "기본(default) 보안그룹의 모든 인바운드/아웃바운드 규칙을 제거하고 사용하지 마세요(전용 SG 사용)."
    standards = ("KISA CII(네트워크)", "CIS AWS 5.3")

    def run(self, client: Any) -> list[CheckViolation]:
        violations: list[CheckViolation] = []
        paginator = client.get_paginator("describe_security_groups")
        for page in paginator.paginate(
            Filters=[{"Name": "group-name", "Values": ["default"]}]
        ):
            for sg in page.get("SecurityGroups", []):
                ingress = sg.get("IpPermissions", []) or []
                egress = sg.get("IpPermissionsEgress", []) or []
                if ingress or egress:
                    violations.append(CheckViolation(
                        resource_id=sg.get("GroupId", ""),
                        resource_type="AwsEc2SecurityGroup",
                        detail=(f"기본 보안그룹 {sg.get('GroupId','')}(VPC {sg.get('VpcId','')})에 "
                                f"규칙이 존재(inbound {len(ingress)}, outbound {len(egress)})"),
                        evidence={"ingress": len(ingress), "egress": len(egress)},
                    ))
        return violations
