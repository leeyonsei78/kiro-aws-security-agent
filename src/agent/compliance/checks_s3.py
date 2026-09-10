"""S3 관련 컴플라이언스 체크."""

from __future__ import annotations

from typing import Any

from ..models import Severity
from .base import BaseComplianceCheck, CheckViolation


class S3PublicAccessBlockCheck(BaseComplianceCheck):
    code = "CA-01"
    title = "S3 버킷 계정 수준 퍼블릭 액세스 차단 미설정"
    severity = Severity.HIGH
    service = "s3"
    remediation = "s3control:PutPublicAccessBlock로 계정 전체 퍼블릭 액세스를 차단하거나, 버킷별 PublicAccessBlock을 설정하세요."
    standards = ("KISA CII(클라우드)", "CIS AWS 2.1")

    def run(self, client: Any) -> list[CheckViolation]:
        violations: list[CheckViolation] = []
        buckets = client.list_buckets().get("Buckets", [])
        for b in buckets:
            name = b.get("Name", "")
            try:
                conf = client.get_public_access_block(Bucket=name)
                pab = conf.get("PublicAccessBlockConfiguration", {})
            except Exception:  # noqa: BLE001 - 미설정 시 예외 → 위반
                pab = {}
            required = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
            if not all(pab.get(k) for k in required):
                violations.append(CheckViolation(
                    resource_id=name, resource_type="AwsS3Bucket",
                    detail=f"버킷 '{name}'의 퍼블릭 액세스 차단이 완전하지 않음",
                    evidence={"PublicAccessBlockConfiguration": pab},
                ))
        return violations


class S3EncryptionCheck(BaseComplianceCheck):
    code = "CA-02"
    title = "S3 버킷 기본 암호화 미설정"
    severity = Severity.MEDIUM
    service = "s3"
    remediation = "PutBucketEncryption으로 SSE-S3(AES256) 또는 SSE-KMS 기본 암호화를 설정하세요."
    standards = ("KISA CII(클라우드)", "CIS AWS 2.1.1")

    def run(self, client: Any) -> list[CheckViolation]:
        violations: list[CheckViolation] = []
        for b in client.list_buckets().get("Buckets", []):
            name = b.get("Name", "")
            encrypted = False
            try:
                enc = client.get_bucket_encryption(Bucket=name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                encrypted = bool(rules)
            except Exception:  # noqa: BLE001 - 미설정 시 예외 → 위반
                encrypted = False
            if not encrypted:
                violations.append(CheckViolation(
                    resource_id=name, resource_type="AwsS3Bucket",
                    detail=f"버킷 '{name}'에 기본 암호화가 설정되지 않음",
                ))
        return violations
