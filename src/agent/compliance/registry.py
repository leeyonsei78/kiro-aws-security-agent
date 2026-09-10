"""컴플라이언스 체크 등록소.

새 체크를 추가하려면 여기 목록에 등록하면 collector가 자동으로 실행한다.
"""

from __future__ import annotations

from .base import BaseComplianceCheck
from .checks_cloudtrail import CloudTrailEnabledCheck
from .checks_iam import IamPasswordPolicyCheck, IamRootAccessKeyCheck, IamUserMfaCheck
from .checks_s3 import S3EncryptionCheck, S3PublicAccessBlockCheck

# 실행할 전체 체크 목록 (코드 순)
ALL_CHECKS: list[BaseComplianceCheck] = [
    S3PublicAccessBlockCheck(),
    S3EncryptionCheck(),
    IamPasswordPolicyCheck(),
    IamRootAccessKeyCheck(),
    IamUserMfaCheck(),
    CloudTrailEnabledCheck(),
]


def all_checks() -> list[BaseComplianceCheck]:
    return list(ALL_CHECKS)


def checks_by_code() -> dict[str, BaseComplianceCheck]:
    return {c.code: c for c in ALL_CHECKS}
