"""제로트러스트(Zero Trust) 관점 IAM 컴플라이언스 체크.

최소권한(least privilege)·자격증명 수명 관리 등 제로트러스트 성숙도 관점을 점검한다.
점검 항목 코드 체계(ZT-nn)와 제로트러스트 관점은 KISA 기반
KESE-KIT(https://github.com/cdppcorp/KESE-KIT, MIT)의 제로트러스트 가이드 접근을 참고했으며,
점검 로직은 boto3로 새로 구현했다.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..models import Severity, utcnow
from .base import BaseComplianceCheck, CheckViolation


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _is_wildcard_admin(statement: dict) -> bool:
    """정책 statement가 Allow + Action:* + Resource:* 인지(관리자 와일드카드) 판정."""
    if statement.get("Effect") != "Allow":
        return False
    actions = _as_list(statement.get("Action"))
    resources = _as_list(statement.get("Resource"))
    # Condition이 붙어 있으면 완전 무제한은 아니므로 제외(보수적)
    if statement.get("Condition"):
        return False
    return ("*" in actions) and ("*" in resources)


class IamWildcardAdminPolicyCheck(BaseComplianceCheck):
    code = "ZT-01"
    title = "관리형 정책에 와일드카드 관리자 권한(Action:* Resource:*)"
    severity = Severity.HIGH
    service = "iam"
    category = "제로트러스트"
    remediation = "최소권한 원칙에 따라 Action/Resource를 필요한 범위로 좁히세요. AdministratorAccess 부여는 최소화합니다."
    standards = ("KISA 제로트러스트 2.0", "NIST SP 800-207", "CIS AWS 1.16")

    def run(self, client: Any) -> list[CheckViolation]:
        violations: list[CheckViolation] = []
        paginator = client.get_paginator("list_policies")
        # 고객 관리형 정책 중 실제 연결된(attached) 것만 점검(노이즈 감소)
        for page in paginator.paginate(Scope="Local", OnlyAttached=True):
            for pol in page.get("Policies", []):
                arn = pol.get("Arn", "")
                name = pol.get("PolicyName", "")
                ver = pol.get("DefaultVersionId")
                if not arn or not ver:
                    continue
                doc = client.get_policy_version(PolicyArn=arn, VersionId=ver)
                statements = _as_list((doc.get("PolicyVersion", {})
                                       .get("Document", {}) or {}).get("Statement"))
                if any(_is_wildcard_admin(s) for s in statements if isinstance(s, dict)):
                    violations.append(CheckViolation(
                        resource_id=name or arn, resource_type="AwsIamPolicy",
                        detail=f"관리형 정책 '{name}'에 와일드카드 관리자 권한(Action:* Resource:*)이 존재",
                        evidence={"policyArn": arn},
                    ))
        return violations


class IamStaleAccessKeyCheck(BaseComplianceCheck):
    code = "ZT-02"
    title = "오래된 IAM 액세스 키(장기 미교체)"
    severity = Severity.MEDIUM
    service = "iam"
    category = "제로트러스트"
    remediation = "액세스 키를 주기적으로 교체(rotate)하세요. 장기 자격증명 대신 임시 자격증명(역할) 사용을 권장합니다."
    standards = ("KISA 제로트러스트 2.0", "CIS AWS 1.14")

    MAX_AGE_DAYS = 90

    def run(self, client: Any) -> list[CheckViolation]:
        violations: list[CheckViolation] = []
        now = utcnow()
        paginator = client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                name = user.get("UserName", "")
                for key in client.list_access_keys(UserName=name).get("AccessKeyMetadata", []):
                    if key.get("Status") != "Active":
                        continue
                    created = key.get("CreateDate")
                    age = self._age_days(created, now)
                    if age is not None and age > self.MAX_AGE_DAYS:
                        violations.append(CheckViolation(
                            resource_id=name, resource_type="AwsIamUser",
                            detail=f"사용자 '{name}'의 액세스 키가 {age}일 경과(> {self.MAX_AGE_DAYS}일, 교체 필요)",
                            evidence={"ageDays": age, "accessKeyId": key.get("AccessKeyId", "")[:4] + "..."},
                        ))
        return violations

    def _age_days(self, created, now) -> int | None:
        if created is None:
            return None
        if isinstance(created, str):
            try:
                created = datetime.fromisoformat(created.replace("Z", "+00:00"))
            except ValueError:
                return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return (now - created).days
