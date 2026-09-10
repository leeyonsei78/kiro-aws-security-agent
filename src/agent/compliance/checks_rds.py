"""RDS 관련 컴플라이언스 체크."""

from __future__ import annotations

from typing import Any

from ..models import Severity
from .base import BaseComplianceCheck, CheckViolation


class RdsPublicAccessCheck(BaseComplianceCheck):
    code = "CA-40"
    title = "RDS 인스턴스 퍼블릭 액세스 허용"
    severity = Severity.HIGH
    service = "rds"
    category = "네트워크"
    remediation = "ModifyDBInstance로 PubliclyAccessible=false 설정 후, 프라이빗 서브넷/SG로 접근을 제한하세요."
    standards = ("KISA CII(클라우드)", "CIS AWS 2.3.3")

    def run(self, client: Any) -> list[CheckViolation]:
        violations: list[CheckViolation] = []
        paginator = client.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                if db.get("PubliclyAccessible"):
                    ident = db.get("DBInstanceIdentifier", "")
                    violations.append(CheckViolation(
                        resource_id=ident, resource_type="AwsRdsDbInstance",
                        detail=f"RDS 인스턴스 '{ident}'가 퍼블릭 액세스 허용됨",
                        evidence={"PubliclyAccessible": True},
                    ))
        return violations


class RdsEncryptionCheck(BaseComplianceCheck):
    code = "CA-41"
    title = "RDS 인스턴스 저장 데이터 암호화 미설정"
    severity = Severity.MEDIUM
    service = "rds"
    category = "데이터 보호"
    remediation = "저장 시 암호화(StorageEncrypted)를 활성화하세요. 기존 인스턴스는 암호화 스냅샷으로 복원해 전환합니다."
    standards = ("KISA CII(클라우드)", "CIS AWS 2.3.1")

    def run(self, client: Any) -> list[CheckViolation]:
        violations: list[CheckViolation] = []
        paginator = client.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                if not db.get("StorageEncrypted"):
                    ident = db.get("DBInstanceIdentifier", "")
                    violations.append(CheckViolation(
                        resource_id=ident, resource_type="AwsRdsDbInstance",
                        detail=f"RDS 인스턴스 '{ident}'에 저장 암호화가 설정되지 않음",
                        evidence={"StorageEncrypted": False},
                    ))
        return violations
