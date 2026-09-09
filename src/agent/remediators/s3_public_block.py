"""공개 노출된 S3 버킷에 Public Access Block을 적용해 차단.

대상: Security Hub가 내는 S3 public 관련 finding.
  - finding_type 접두사 매칭 (ASFF Types 예: "Effects/Data Exposure",
    "Software and Configuration Checks/AWS Security Best Practices")
  - 실제 판별은 finding_type + 리소스 타입(AwsS3Bucket) 조합으로 한다.

액션: s3:PutPublicAccessBlock 로 4개 플래그를 모두 True 설정(완전 차단).

안전:
  - dry-run 기본.
  - Public Access Block은 되돌릴 수 있는(재설정 가능) 액션이라 롤백 지향에 부합.
  - 버킷 정책/ACL 자체를 지우지 않으므로 데이터 손실 위험 없음.
"""

from __future__ import annotations

from ..models import SecurityFinding
from .base import BaseRemediator, RemediationAction

# ASFF Types 중 데이터 노출 계열 접두사
_EXPOSURE_TYPE_PREFIXES = (
    "Effects/Data Exposure",
    "Sensitive Data Identifications",
)

_FULL_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


class S3PublicBlockRemediator(BaseRemediator):
    name = "s3_public_block"
    # finding_type 화이트리스트 매칭용. 넓게 잡되 can_handle에서 리소스 타입으로 재확인.
    supported_types = _EXPOSURE_TYPE_PREFIXES

    def _client(self):
        return self._make_client("s3")

    def can_handle(self, finding: SecurityFinding) -> bool:
        # 타입 접두사 + S3 버킷 리소스가 있어야 대응
        if not super().can_handle(finding):
            return False
        return self._bucket_name(finding) is not None

    def _bucket_name(self, finding: SecurityFinding) -> str | None:
        """finding 리소스에서 S3 버킷명을 추출.

        Security Hub ASFF: Resource.Type == "AwsS3Bucket",
        Resource.Id == "arn:aws:s3:::bucket-name".
        """
        for r in finding.resources:
            if r.type == "AwsS3Bucket" and r.id:
                return _bucket_from_arn(r.id)
        # GuardDuty S3 계열 fallback: raw.Resource.S3BucketDetails[].Name
        raw = finding.raw or {}
        res = raw.get("Resource", {}) or {}
        for b in res.get("S3BucketDetails", []) or []:
            if b.get("Name"):
                return b["Name"]
        return None

    def _plan(self, finding: SecurityFinding) -> list[RemediationAction]:
        bucket = self._bucket_name(finding)
        if not bucket:
            return []
        return [
            RemediationAction(
                description=f"S3 버킷 '{bucket}'에 Public Access Block 전체 적용",
                api="s3:PutPublicAccessBlock",
                params={"Bucket": bucket, "PublicAccessBlockConfiguration": dict(_FULL_BLOCK)},
            )
        ]

    def _apply(self, finding: SecurityFinding, actions: list[RemediationAction]) -> None:
        client = self._client()
        for action in actions:
            client.put_public_access_block(
                Bucket=action.params["Bucket"],
                PublicAccessBlockConfiguration=action.params["PublicAccessBlockConfiguration"],
            )


def _bucket_from_arn(arn: str) -> str:
    # arn:aws:s3:::bucket-name  또는  arn:aws:s3:::bucket-name/key
    if arn.startswith("arn:"):
        tail = arn.split(":::", 1)[-1]
        return tail.split("/", 1)[0]
    return arn
